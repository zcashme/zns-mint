use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::scanning::ScanningKeys;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zns_mint::zcash::NETWORK;

use zns_mint::auth::ChallengeKey;
use zns_mint::boot::Boot;
use zns_mint::key::{RegistryKeys, TreasuryKeys};
use zns_mint::metrics;
use zns_mint::mint::{
    Action, Name, UnifiedAddress, OperationalState,
    SubmissionKind, TREASURY_ACCOUNT, TX_EXPIRY_BUFFER,
};
use zns_mint::registry::authorize;
use zns_mint::registry::liquidity::RegistryFeeLiquidity;
use zns_mint::registry::Registry;
use zns_mint::sync::scan_block;
use zns_mint::treasury::claim::process_claim;
use zns_mint::treasury::memo::RequestMemo;
use zns_mint::treasury::relay::process_otp_relay;
use zns_mint::wallet::{NoteLocator, Wallet, trees::RETAINED_CHECKPOINTS};
use zns_mint::zcash::{CanonicalBlockSource, CanonicalTip, SubmitOutcome, TransportError};

use zebra_indexer_proto::Empty;

const BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("block scan failed: {0}")]
    Scan(#[from] zns_mint::sync::ScanError),
    #[error("wallet block application failed: {0}")]
    Wallet(#[from] zns_mint::wallet::WalletApplyError),
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");
    tokio::spawn(metrics::serve());

    let boot = Boot::run().await;
    metrics::set_boot_success(true);

    let boot_height = boot.height();
    let mut cursor = *boot.cursor().metadata();
    let (mut chain, mut wallet, mut registry, _treasury, treasury_keys, registry_keys) =
        boot.into_parts();
    let block_source = CanonicalBlockSource::new();
    let mut ops = OperationalState::recovering(cursor.block_height());
    let mut chain_history = BTreeMap::from([(cursor.block_height(), cursor)]);

    // Build scanning inputs once — the wallet's account set never changes after boot.
    let ufvks: HashMap<zip32::AccountId, zcash_keys::keys::UnifiedFullViewingKey> = wallet
        .ufvk_map()
        .iter()
        .map(|(account_id, ufvk)| (*account_id, ufvk.clone()))
        .collect();
    let scanning_keys = ScanningKeys::from_account_ufvks(ufvks.clone());

    let mut applied_txids: Vec<TxId> = Vec::new();
    let mut reorg_ancestor: Option<BlockHeight> = None;

    metrics::publish_wallet_gauges(&wallet, cursor.block_height());

    tracing::info!(
        height = u32::from(boot_height),
        "zns-mint: boot complete; entering block fold loop"
    );

    let mut tip_stream = chain
        .client()
        .chain_tip_change(Empty {})
        .await
        .expect("FATAL: could not open Zebra chain-tip stream")
        .into_inner();

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("zns-mint: received ctrl-c, shutting down");
                break;
            }
            tip_event = tip_stream.message() => {
                match tip_event {
                    Ok(Some(tip)) => {
                        let (height, hash) = zns_mint::zcash::tip_height_hash(&tip);
                        tracing::debug!(height = u32::from(height), %hash, "chain tip event");
                    }
                    Ok(None) => {
                        tracing::warn!("Zebra tip stream closed; waiting before reconnect");
                        tokio::time::sleep(BLOCK_POLL_INTERVAL).await;
                        tip_stream = chain
                            .client()
                            .chain_tip_change(Empty {})
                            .await
                            .expect("FATAL: could not reopen Zebra chain-tip stream")
                            .into_inner();
                    }
                    Err(error) => {
                        metrics::inc_rpc_error("chain_tip_change");
                        tracing::warn!(error = %error, "tip stream error; reconnecting");
                        tokio::time::sleep(BLOCK_POLL_INTERVAL).await;
                        tip_stream = chain
                            .client()
                            .chain_tip_change(Empty {})
                            .await
                            .expect("FATAL: could not reopen Zebra chain-tip stream")
                            .into_inner();
                    }
                }
            }
            _ = tokio::time::sleep(BLOCK_POLL_INTERVAL) => {}
        }

        // ── sync phase: reorg resolution + forward catch-up ──
        let sync_result: Result<CanonicalTip, RuntimeError> = async {
            loop {
                // ── reorg resolution ──
                let mut tip;
                loop {
                    tip = block_source.exact_tip().await?;

                    if cursor.block_height() <= tip.height() {
                        let canonical_hash = if cursor.block_height() == tip.height() {
                            tip.hash()
                        } else {
                            block_source
                                .get_block(cursor.block_height())
                                .await?
                                .header()
                                .hash()
                        };
                        if cursor.block_hash() == canonical_hash {
                            break;
                        }
                    }

                    let prev_height = cursor.block_height() - 1;
                    let prev_metadata = *chain_history
                        .get(&prev_height)
                        .expect("reorg exceeds Zebra consensus reorg depth");

                    wallet.rewind_to_height(prev_height)?;
                    registry.truncate_to_height(prev_height);
                    chain_history.retain(|h, _| *h <= prev_height);
                    cursor = prev_metadata;

                    reorg_ancestor = Some(
                        reorg_ancestor.map_or(prev_height, |h: BlockHeight| h.min(prev_height)),
                    );
                    metrics::inc_reorg();
                    tracing::info!(
                        height = u32::from(prev_height),
                        "rewound to common ancestor"
                    );
                }

                // ── forward catch-up ──
                let mut continuity_broke = false;
                while cursor.block_height() < tip.height() {
                    let next_height = cursor.block_height() + 1;
                    let block = block_source.get_block(next_height).await?;

                    if block.header().prev_block != cursor.block_hash() {
                        tracing::warn!(
                            height = u32::from(next_height),
                            expected = %cursor.block_hash(),
                            actual = %block.header().prev_block,
                            "reorg detected: block prev_hash does not match cursor"
                        );
                        metrics::inc_reorg();
                        continuity_broke = true;
                        break;
                    }

                    let output = scan_block(
                        &NETWORK,
                        Some(&cursor),
                        block,
                        &ufvks,
                        &scanning_keys,
                    )?;

                    let next_registry = registry.apply_block(&wallet, &output);
                    wallet.apply_block(&output, cursor.block_height())?;
                    registry = next_registry;

                    let metadata = *output.metadata();
                    chain_history.insert(metadata.block_height(), metadata);
                    while chain_history.len() > RETAINED_CHECKPOINTS {
                        chain_history.pop_first();
                    }
                    cursor = metadata;

                    applied_txids.extend(output.transactions().iter().map(|tx| tx.txid()));
                }

                if !continuity_broke {
                    return Ok(tip);
                }
            }
        }
        .await;

        match sync_result {
            Ok(tip) => {
                metrics::set_tip_height(u32::from(tip.height()));
                // ── live phase ──
                if cursor.block_height() == tip.height() && cursor.block_hash() == tip.hash() {
                    metrics::publish_wallet_gauges(&wallet, cursor.block_height());

                    if let Some(ancestor) = reorg_ancestor.take() {
                        tracing::info!("reorg detected; invalidating changed name-tip work");
                        ops.invalidate_after_reorg(&registry, &wallet, ancestor);
                    }

                    ops.reconcile(&applied_txids, cursor.block_height());
                    applied_txids.clear();

                    // ── request processing ──
                    process_cycle(
                        &mut wallet,
                        &registry,
                        &mut ops,
                        &treasury_keys,
                        &registry_keys,
                        &block_source,
                        cursor,
                    ).await;
                }
            }
            Err(RuntimeError::Transport(error)) if error.is_retryable() => {
                tracing::warn!(error = %error, "sync transport failed; retrying");
            }
            Err(RuntimeError::Transport(error)) => {
                tracing::error!(error = %error, "sync non-retryable transport error");
            }
            Err(error) => {
                tracing::error!(error = %error, "sync failed; skipping this cycle");
            }
        }
    }
}

/// Processes all pending Treasury work for one canonical block cycle.
///
/// Iterates Treasury Orchard notes, dispatches each parsed request to the
/// appropriate assembly path (claim, OTP relay, authorized transition),
/// submits the resulting transaction, and records it in [`OperationalState`].
/// Then runs replenishment and sweep policy checks.
///
/// This is the sole entry point that mutates `ops` with new submissions.
/// The caller has already run [`OperationalState::reconcile`] to prune
/// confirmed/expired submissions before calling this function.
async fn process_cycle(
    wallet: &mut Wallet,
    registry: &Registry,
    ops: &mut OperationalState,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    block_source: &CanonicalBlockSource,
    cursor: BlockMetadata,
) {
    let cursor_height = cursor.block_height();
    let target_height =
        BlockHeight::from_u32(u32::from(cursor_height) + 1);
    let expiry_height = BlockHeight::from_u32(
        u32::from(target_height)
            .checked_add(TX_EXPIRY_BUFFER)
            .unwrap_or(u32::from(target_height)),
    );

    if !ops.recovery_complete(cursor_height) {
        return;
    }

    let pruned = ops.pending_otps.prune(cursor_height);
    if pruned > 0 {
        tracing::debug!(pruned, "pruned expired OTP challenges");
    }

    let mut excluded = ops.reserved_locators();
    let reserved = excluded.clone();

    // ── request processing ──
    let treasury_notes: Vec<_> = wallet
        .orchard_notes_for(TREASURY_ACCOUNT)
        .map(|note| {
            (
                note.memo.clone(),
                note.note.rho(),
                note.note.value().inner(),
                note.confirmed_height,
            )
        })
        .collect();

    let mut seen_claims: BTreeSet<Name> = BTreeSet::new();
    let mut seen_no_otp: BTreeSet<ChallengeKey> = BTreeSet::new();
    let mut seen_with_otp: BTreeSet<ChallengeKey> = BTreeSet::new();

    for (memo, rho, value, confirmed_height) in treasury_notes {
        let Ok(request) =
            RequestMemo::parse(memo.as_array()) else { continue };
        let Some(name) = Name::parse(request.name()) else { continue };
        let locator = NoteLocator::orchard(TREASURY_ACCOUNT, rho);
        if reserved.contains(&locator) { continue; }

        let outcome = match &request {
            RequestMemo::Claim { ua, .. } => {
                process_claim(
                    name, ua, locator, value, confirmed_height,
                    cursor_height, target_height, &excluded,
                    wallet, registry, treasury_keys, registry_keys,
                    ops, &mut seen_claims,
                )
            }
            RequestMemo::Update { ua, otp, .. } => {
                let ua = UnifiedAddress::from_string(ua.clone());
                let record = match registry.record(&name) {
                    Some(r) if r.action != Action::Release => r,
                    _ => continue,
                };
                let controller_ua = record.ua.clone();
                match otp {
                    None => process_otp_relay(
                        &name, Action::Update, &ua, &controller_ua,
                        record.commitment, locator, value,
                        cursor_height, target_height, &excluded,
                        wallet, treasury_keys, ops, &mut seen_no_otp,
                    ),
                    Some(otp_bytes) => {
                        authorize::process_transition(
                            name, Action::Update, ua, otp_bytes,
                            record.commitment,
                            cursor_height, target_height, &excluded,
                            wallet, registry, registry_keys,
                            ops, &mut seen_with_otp,
                        )
                    }
                }
            }
            RequestMemo::Release { ua, otp, .. } => {
                let ua = UnifiedAddress::from_string(ua.clone());
                let record = match registry.record(&name) {
                    Some(r) if r.action != Action::Release => r,
                    _ => continue,
                };
                let controller_ua = record.ua.clone();
                if ua != controller_ua {
                    metrics::inc_request_invalid("release_owner_mismatch");
                    continue;
                }
                match otp {
                    None => process_otp_relay(
                        &name, Action::Release, &ua, &controller_ua,
                        record.commitment, locator, value,
                        cursor_height, target_height, &excluded,
                        wallet, treasury_keys, ops, &mut seen_no_otp,
                    ),
                    Some(otp_bytes) => {
                        authorize::process_transition(
                            name, Action::Release, ua, otp_bytes,
                            record.commitment,
                            cursor_height, target_height, &excluded,
                            wallet, registry, registry_keys,
                            ops, &mut seen_with_otp,
                        )
                    }
                }
            }
        };

        if let Some(mut outcome) = outcome {
            match outcome.result {
                Ok((kind, txid, hex, reserved_notes)) => {
                    let submit_result = block_source
                        .submit_transaction(
                            &hex,
                            &txid.to_string(),
                            cursor.block_height(),
                            cursor.block_hash(),
                        )
                        .await;
                    let already_in_chain = matches!(
                        submit_result,
                        Ok(SubmitOutcome::AlreadyInChain)
                    );
                    match submit_result {
                        Ok(SubmitOutcome::Accepted)
                        | Ok(SubmitOutcome::AlreadyInChain) => {
                            if already_in_chain {
                                tracing::info!(
                                    txid = %txid,
                                    kind = kind.as_str(),
                                    "already in chain; tracking as pending"
                                );
                            }
                            if let Some((key, otp)) =
                                outcome.relay_challenge.take()
                            {
                                ops.pending_otps
                                    .release_challenge(&key);
                                ops.pending_otps
                                    .record_issued(key, &otp, cursor_height);
                            }
                            ops.record_submission(
                                kind,
                                txid,
                                reserved_notes,
                                outcome.name_binding.take(),
                                expiry_height,
                                &mut excluded,
                            );
                            metrics::inc_tx_submitted(kind.as_str());
                        }
                        Ok(SubmitOutcome::TipChanged) => {
                            tracing::info!(
                                kind = kind.as_str(),
                                "canonical tip changed during assembly; discarding stale transaction"
                            );
                            metrics::inc_spend_error("pre_submit_tip_changed");
                        }
                        Ok(SubmitOutcome::TxIdMismatch { returned_txid }) => {
                            tracing::error!(
                                %txid,
                                %returned_txid,
                                "node returned a transaction ID different from the signed bytes"
                            );
                            metrics::inc_spend_error("submission_txid_mismatch");
                        }
                        Ok(SubmitOutcome::Rejected(e)) => {
                            tracing::warn!(
                                error = %e,
                                kind = kind.as_str(),
                                "submission rejected"
                            );
                            metrics::inc_spend_error("submit_rejected");
                            for loc in &reserved_notes {
                                excluded.remove(loc);
                            }
                        }
                        Err(e) if e.is_retryable() => {
                            tracing::warn!(
                                error = %e,
                                kind = kind.as_str(),
                                "submission transport failed; no submission state retained"
                            );
                            metrics::inc_spend_error("submit_transport");
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                kind = kind.as_str(),
                                "non-retryable transport error"
                            );
                            metrics::inc_spend_error("submit_transport");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "assembly failed");
                    metrics::inc_spend_error("assembly");
                }
            }

            // Cleanup remaining locks and challenges.
            // On the Accepted path, record_submission consumed the pre-submit
            // lock and relay_challenge was .take()'n — these are no-ops.
            // On any failure path, they release the unconsumed reservations.
            if let Some((key, _)) = &outcome.relay_challenge {
                ops.pending_otps.release_challenge(key);
            }
            if let Some(lock) = &outcome.name_lock {
                ops.release_name(lock);
            }
        }
    }

    // ── replenishment ──
    let reserved_ironwood = ops
        .reserved_locators()
        .iter()
        .filter(|loc| matches!(loc, NoteLocator::Ironwood { .. }))
        .count();
    let mut liquidity = RegistryFeeLiquidity::from_wallet(wallet);
    liquidity.fee_note_count =
        liquidity.fee_note_count.saturating_sub(reserved_ironwood);
    let has_pending_replenish = ops
        .submissions
        .values()
        .any(|s| s.kind == SubmissionKind::Replenish && s.confirmed_at.is_none());
    let replenishment_queued =
        if let Some(plan) = liquidity.treasury_funding_plan() {
            if !has_pending_replenish {
                let excluded_rhos =
                    zns_mint::wallet::treasury_excluded_rhos(&excluded);
                let result =
                    zns_mint::treasury::replenish::assemble_replenishment(
                        wallet,
                        treasury_keys,
                        &plan,
                        cursor_height,
                        target_height,
                        &excluded_rhos,
                    )
                    .map(|r| {
                        (SubmissionKind::Replenish, r.txid, r.hex, r.reserved_notes)
                    });
                match result {
                    Ok((kind, txid, hex, reserved_notes)) => {
                        let submit_result = block_source
                            .submit_transaction(
                                &hex,
                                &txid.to_string(),
                                cursor.block_height(),
                                cursor.block_hash(),
                            )
                            .await;
                        match submit_result {
                            Ok(SubmitOutcome::Accepted)
                            | Ok(SubmitOutcome::AlreadyInChain) => {
                                ops.record_submission(
                                    kind,
                                    txid,
                                    reserved_notes,
                                    None,
                                    expiry_height,
                                    &mut excluded,
                                );
                                metrics::inc_tx_submitted(kind.as_str());
                            }
                            Ok(SubmitOutcome::Rejected(_)) => {
                                for loc in &reserved_notes {
                                    excluded.remove(loc);
                                }
                                metrics::inc_spend_error("submit_rejected");
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "replenishment assembly failed");
                        metrics::inc_spend_error("assembly");
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        };

    // ── sweep ──
    let balance = wallet.balance(TREASURY_ACCOUNT).into_u64();
    let has_pending_sweep = ops
        .submissions
        .values()
        .any(|s| s.kind == SubmissionKind::AutoSweep && s.confirmed_at.is_none());
    if !replenishment_queued && !has_pending_replenish
        && zns_mint::treasury::sweep::sweep_policy(balance)
        && !has_pending_sweep
    {
        let excluded_rhos =
            zns_mint::wallet::treasury_excluded_rhos(&excluded);
        let result =
            zns_mint::treasury::sweep::assemble_sweep(
                wallet,
                treasury_keys,
                cursor_height,
                target_height,
                &excluded_rhos,
            )
            .map(|r| {
                (SubmissionKind::AutoSweep, r.txid, r.hex, r.reserved_notes)
            });
        match result {
            Ok((kind, txid, hex, reserved_notes)) => {
                let submit_result = block_source
                    .submit_transaction(
                        &hex,
                        &txid.to_string(),
                        cursor.block_height(),
                        cursor.block_hash(),
                    )
                    .await;
                match submit_result {
                    Ok(SubmitOutcome::Accepted)
                    | Ok(SubmitOutcome::AlreadyInChain) => {
                        ops.record_submission(
                            kind,
                            txid,
                            reserved_notes,
                            None,
                            expiry_height,
                            &mut excluded,
                        );
                        metrics::inc_tx_submitted(kind.as_str());
                    }
                    Ok(SubmitOutcome::Rejected(_)) => {
                        for loc in &reserved_notes {
                            excluded.remove(loc);
                        }
                        metrics::inc_spend_error("submit_rejected");
                    }
                    _ => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "sweep assembly failed");
                metrics::inc_spend_error("assembly");
            }
        }
    }
}

