use std::collections::HashSet;

use pasta_curves::group::ff::PrimeField;
use zns_chain::{scan_blocks, GrpcClient, GrpcError, IncomingNote, ScanError, ScannerConfig};
use zns_core::{parse_memo, Action, ParsedMemo};
use zns_signer::{derive_psi_rcm, Signer, RequestId};
use zns_state::{MintedAction, ScanTip, StateError};
use zcash_protocol::ShieldedProtocol;

use crate::config::{MIN_CLAIM_FEE_ZAT, MIN_MUTATION_FEE_ZAT};
use crate::Registry;
use crate::spend::{QueuedSpend, SpendLane, SpendVerb};

#[derive(Debug, thiserror::Error)]
pub enum ScanSyncError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Chain(#[from] ScanError),
}

/// Block-linear intake: classify notes, enqueue spends, advance scan tip.
pub async fn catch_up(
    registry: &Registry,
    scanner: &ScannerConfig,
    birthday: u32,
    chain_tip: u32,
    spend: &SpendLane,
) -> Result<u32, ScanSyncError> {
    let start = {
        let st = registry.lock().await;
        match st.get_scan_tip()? {
            Some(tip) => tip.height.saturating_add(1),
            None => birthday,
        }
    };

    if start > chain_tip {
        return Ok(0);
    }

    let blocks_done = std::cell::Cell::new(0u32);

    scan_blocks(scanner, start, chain_tip, |height, hash, notes| {
        let registry = registry.clone();
        let blocks_done = &blocks_done;
        async move {
            process_block(registry, height, hash, notes, spend).await?;
            blocks_done.set(blocks_done.get().saturating_add(1));
            Ok::<(), ScanSyncError>(())
        }
    })
    .await?;

    Ok(blocks_done.get())
}

async fn process_block(
    registry: Registry,
    height: u32,
    hash: [u8; 32],
    notes: Vec<IncomingNote>,
    spend: &SpendLane,
) -> Result<(), ScanSyncError> {
    let mut claimed_this_block = HashSet::new();
    let note_count = notes.len();

    for note in notes {
        if !note.confirmed {
            continue;
        }

        let pool_byte = pool_byte(&note.pool);
        if {
            let st = registry.lock().await;
            st.is_processed(&note.txid, pool_byte, note.output_index)?
        } {
            continue;
        }

        let parsed = match parse_memo(&note.memo) {
            Err(_) => {
                mark_settled(&registry, &note, height, hash).await?;
                tracing::debug!("intake skipped: memo parse error");
                continue;
            }
            Ok(p) => p,
        };

        match handle_note(&registry, spend, &note, height, hash, parsed, &mut claimed_this_block)
            .await?
        {
            NoteOutcome::Settled => {
                mark_settled(&registry, &note, height, hash).await?;
            }
            NoteOutcome::Defer => {}
            NoteOutcome::Enqueued => {}
        }
    }

    {
        let st = registry.lock().await;
        st.set_scan_tip(&ScanTip { height, hash })?;
    }
    tracing::debug!(height, notes = note_count, "scan tip advanced");
    Ok(())
}

enum NoteOutcome {
    Settled,
    Defer,
    Enqueued,
}

async fn handle_note(
    registry: &Registry,
    spend: &SpendLane,
    note: &IncomingNote,
    height: u32,
    hash: [u8; 32],
    parsed: ParsedMemo,
    claimed: &mut HashSet<String>,
) -> Result<NoteOutcome, ScanSyncError> {
    match parsed {
        ParsedMemo::Action {
            prev_rcm: Some(prev_rcm),
            action,
            name,
            ua,
        } => {
            apply_name_note(registry, spend, note, height, hash, action, name, ua, prev_rcm)
                .await?;
            Ok(NoteOutcome::Settled)
        }
        ParsedMemo::Challenge { name, .. } => {
            if let Some(flight) = {
                let st = registry.lock().await;
                st.get_in_flight()?
            } {
                if flight.relay && flight.name == name {
                    let st = registry.lock().await;
                    st.clear_in_flight()?;
                    spend.clear_active();
                    tracing::debug!(name = %name, "relay challenge seen on chain");
                }
            }
            Ok(NoteOutcome::Settled)
        }
        ParsedMemo::Confirm { name, nonce } => {
            if {
                let st = registry.lock().await;
                st.get_challenge(&name)?.is_none()
            } {
                tracing::debug!(%name, "confirm without pending challenge");
                return Ok(NoteOutcome::Settled);
            }
            let queued = QueuedSpend {
                txid: note.txid,
                pool: pool_byte(&note.pool),
                output_index: note.output_index,
                block_height: height,
                block_hash: hash,
                verb: SpendVerb::Confirm,
                name,
                ua: String::new(),
                nonce,
                value_zat: note.value_zat,
            };
            tracing::info!(height, name = %queued.name, "enqueued spend");
            spend.push(queued);
            Ok(NoteOutcome::Enqueued)
        }
        ParsedMemo::Action {
            action,
            name,
            ua,
            prev_rcm: None,
        } => {
            if note.value_zat < fee_floor(action) {
                tracing::debug!(%name, ?action, "intake skipped: insufficient fee");
                return Ok(NoteOutcome::Settled);
            }

            if matches!(action, Action::Claim) && !claimed.insert(name.clone()) {
                tracing::debug!(%name, "intake skipped: duplicate claim in block");
                return Ok(NoteOutcome::Settled);
            }

            if matches!(action, Action::Claim) {
                if {
                    let st = registry.lock().await;
                    st.get_record(&name)?.is_some()
                } {
                    tracing::debug!(%name, "intake skipped: name already registered");
                    return Ok(NoteOutcome::Settled);
                }
                if spend.has_pending_claim(&name) || in_flight_mint(registry, &name).await? {
                    tracing::debug!(%name, "intake skipped: claim already pending");
                    return Ok(NoteOutcome::Settled);
                }
            }

            if matches!(action, Action::Update | Action::Release) {
                if {
                    let st = registry.lock().await;
                    st.get_record(&name)?.is_none()
                } {
                    tracing::debug!(%name, ?action, "intake skipped: unknown name");
                    return Ok(NoteOutcome::Settled);
                }
                if {
                    let st = registry.lock().await;
                    st.get_challenge(&name)?.is_some()
                } {
                    tracing::debug!(%name, "intake deferred: challenge pending");
                    return Ok(NoteOutcome::Defer);
                }
            }

            let verb = match action {
                Action::Claim => SpendVerb::Claim,
                Action::Update => SpendVerb::Update,
                Action::Release => SpendVerb::Release,
            };
            let queued = QueuedSpend {
                txid: note.txid,
                pool: pool_byte(&note.pool),
                output_index: note.output_index,
                block_height: height,
                block_hash: hash,
                verb,
                name: name.clone(),
                ua,
                nonce: String::new(),
                value_zat: note.value_zat,
            };
            tracing::info!(
                height,
                verb = crate::spend::verb_label(queued.verb),
                name = %queued.name,
                "enqueued spend"
            );
            spend.push(queued);
            Ok(NoteOutcome::Enqueued)
        }
    }
}

async fn in_flight_mint(registry: &Registry, name: &str) -> Result<bool, ScanSyncError> {
    let flight = {
        let st = registry.lock().await;
        st.get_in_flight()?
    };
    Ok(flight
        .map(|f| !f.relay && f.name == name)
        .unwrap_or(false))
}

fn fee_floor(action: Action) -> u64 {
    match action {
        Action::Claim => MIN_CLAIM_FEE_ZAT,
        Action::Update | Action::Release => MIN_MUTATION_FEE_ZAT,
    }
}

async fn mark_settled(
    registry: &Registry,
    note: &IncomingNote,
    height: u32,
    hash: [u8; 32],
) -> Result<(), ScanSyncError> {
    let st = registry.lock().await;
    st.mark_processed(
        &note.txid,
        pool_byte(&note.pool),
        note.output_index,
        height,
        &hash,
    )?;
    Ok(())
}

fn pool_byte(pool: &ShieldedProtocol) -> u8 {
    match pool {
        ShieldedProtocol::Orchard => 0,
        ShieldedProtocol::Sapling => 1,
    }
}

/// Persist a registry-authored Name Note seen on chain and finish the spend lane.
async fn apply_name_note(
    registry: &Registry,
    spend: &SpendLane,
    note: &IncomingNote,
    height: u32,
    hash: [u8; 32],
    action: Action,
    name: String,
    ua: String,
    prev_rcm: [u8; 32],
) -> Result<(), StateError> {
    let (psi, rcm) = derive_psi_rcm(action, &name, &ua, &prev_rcm);
    let minted = MintedAction {
        name: name.clone(),
        action,
        ua,
        txid: note.txid,
        cmx: [0u8; 32],
        rcm: rcm.to_repr(),
        psi: psi.to_repr(),
        prev_rcm,
        height,
    };

    {
        let st = registry.lock().await;
        st.apply_mint(&minted)?;
        st.mark_processed(
            &note.txid,
            pool_byte(&note.pool),
            note.output_index,
            height,
            &hash,
        )?;
    }

    let flight = {
        let st = registry.lock().await;
        st.get_in_flight()?
    };
    if let Some(flight) = flight {
        if !flight.relay && flight.name == name {
            let request_pool = spend
                .active_job()
                .map(|j| j.pool)
                .unwrap_or_else(|| pool_byte(&note.pool));
            let st = registry.lock().await;
            st.mark_processed(
                &flight.request_txid,
                request_pool,
                flight.request_index,
                height,
                &hash,
            )?;
            st.clear_in_flight()?;
            spend.clear_active();
            tracing::info!(name = %name, height, "mint confirmed on chain");
        }
    }

    Ok(())
}

/// Detect a chain reorg against the scan tip and rewind if needed.
pub async fn handle_reorg(
    registry: &Registry,
    grpc: &GrpcClient,
    signer: &Signer,
    chain_tip: u32,
) -> Result<Option<u32>, ReorgError> {
    let scan_tip = {
        let st = registry.lock().await;
        st.get_scan_tip()?
    };

    let Some(scan_tip) = scan_tip else {
        return Ok(None);
    };

    let reorg_height = if scan_tip.height > chain_tip {
        chain_tip.saturating_add(1)
    } else {
        let current_hash = grpc.block_hash(scan_tip.height).await?;
        if current_hash == scan_tip.hash {
            return Ok(None);
        }

        let mut h = scan_tip.height;
        loop {
            let stored = {
                let st = registry.lock().await;
                st.processed_hash_at_height(h)?
            };
            let Some(stored) = stored else {
                break 0;
            };
            let current = grpc.block_hash(h).await?;
            if stored == current {
                break h.saturating_add(1);
            }
            if h == 0 {
                break 0;
            }
            h -= 1;
        }
    };

    let affected = {
        let st = registry.lock().await;
        st.apply_reorg(reorg_height, |(txid, idx)| {
            signer.release_request(RequestId {
                txid,
                action_index: idx,
            });
        })?
    };

    tracing::warn!(
        reorg_height,
        affected_names = affected,
        "chain reorg: registry rewound"
    );
    Ok(Some(reorg_height))
}

#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Grpc(#[from] GrpcError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use zns_state::State;

    fn pad_memo(text: &str) -> Vec<u8> {
        let mut memo = vec![0u8; 512];
        let bytes = text.as_bytes();
        memo[..bytes.len()].copy_from_slice(bytes);
        memo
    }

    fn intake_note(txid_byte: u8, memo: &str, value_zat: u64) -> IncomingNote {
        IncomingNote {
            txid: [txid_byte; 32],
            height: 2_000_100,
            block_hash: [0u8; 32],
            output_index: 0,
            pool: ShieldedProtocol::Orchard,
            value_zat,
            memo: pad_memo(memo),
            is_received: true,
            confirmed: true,
        }
    }

    #[tokio::test]
    async fn claim_with_sufficient_fee_enqueues_spend() {
        let registry = Registry::new(State::open_in_memory().unwrap());
        let spend = SpendLane::new();
        let note = intake_note(1, "ZNS:claim:alice:u1test", MIN_CLAIM_FEE_ZAT);

        process_block(
            registry.clone(),
            2_000_100,
            [9u8; 32],
            vec![note],
            &spend,
        )
        .await
        .unwrap();

        assert_eq!(spend.pending_count(), 1);
        let tip = registry.lock().await.get_scan_tip().unwrap().unwrap();
        assert_eq!(tip.height, 2_000_100);
    }

    #[tokio::test]
    async fn claim_with_insufficient_fee_is_settled() {
        let registry = Registry::new(State::open_in_memory().unwrap());
        let spend = SpendLane::new();
        let note = intake_note(2, "ZNS:claim:bob:u1test", 1);

        process_block(registry.clone(), 2_000_101, [8u8; 32], vec![note], &spend)
            .await
            .unwrap();

        assert_eq!(spend.pending_count(), 0);
        let st = registry.lock().await;
        assert!(st.is_processed(&[2u8; 32], 0, 0).unwrap());
    }

    #[tokio::test]
    async fn duplicate_claim_in_block_is_settled_once() {
        let registry = Registry::new(State::open_in_memory().unwrap());
        let spend = SpendLane::new();
        let note_a = intake_note(3, "ZNS:claim:carol:u1test", MIN_CLAIM_FEE_ZAT);
        let note_b = intake_note(4, "ZNS:claim:carol:u1test", MIN_CLAIM_FEE_ZAT);

        process_block(
            registry.clone(),
            2_000_102,
            [7u8; 32],
            vec![note_a, note_b],
            &spend,
        )
        .await
        .unwrap();

        assert_eq!(spend.pending_count(), 1);
        let st = registry.lock().await;
        assert!(st.is_processed(&[4u8; 32], 0, 0).unwrap());
    }

    #[tokio::test]
    async fn update_for_unknown_name_is_settled() {
        let registry = Registry::new(State::open_in_memory().unwrap());
        let spend = SpendLane::new();
        let note = intake_note(5, "ZNS:update:missing:u1new", MIN_MUTATION_FEE_ZAT);

        process_block(registry.clone(), 2_000_103, [6u8; 32], vec![note], &spend)
            .await
            .unwrap();

        assert_eq!(spend.pending_count(), 0);
        let st = registry.lock().await;
        assert!(st.is_processed(&[5u8; 32], 0, 0).unwrap());
    }

    #[tokio::test]
    async fn unconfirmed_notes_are_ignored() {
        let registry = Registry::new(State::open_in_memory().unwrap());
        let spend = SpendLane::new();
        let mut note = intake_note(6, "ZNS:claim:dave:u1test", MIN_CLAIM_FEE_ZAT);
        note.confirmed = false;

        process_block(registry.clone(), 2_000_104, [5u8; 32], vec![note], &spend)
            .await
            .unwrap();

        assert_eq!(spend.pending_count(), 0);
        let st = registry.lock().await;
        assert!(!st.is_processed(&[6u8; 32], 0, 0).unwrap());
    }
}