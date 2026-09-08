//! The Zcash Name Service attested Mint.
//!
//! This binary is deliberately an orchestrator. It follows the canonical
//! Zcash chain, keeps the wallet and derived registry in lockstep, delegates
//! policy to the mint modules, and submits the transactions those modules
//! record. It does not compose Name Notes or independently mutate registry
//! state.

use std::convert::Infallible;
use std::time::Duration as StdDuration;

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{WalletRead as _, WalletWrite as _};
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_client_backend::scanning::{Nullifiers, ScanningKeys};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;
use zip32::AccountId;

use zns_mint::boot::Boot;
use zns_mint::mint::otp::{decode_otp_relay_memo, issue_relay, OtpQueue};
use zns_mint::mint::registry::settle::Settle;
use zns_mint::mint::treasury::{parse_request, sweep_ironwood_to_vault, sweep_sapling_to_vault};
use zns_mint::mint::{decrypt_name_notes, Action, ChainTip, TREASURY_ACCOUNT};
use zns_mint::zcash::{self, CanonicalBlockSource, JsonRpc, SubmitOutcome};

/// Submits a transaction only if the canonical tip is still the tip used to
/// build it. Producers record a transaction before this boundary, reserving
/// its selected notes while Zebra accepts it or it expires.
async fn submit(
    source: &CanonicalBlockSource,
    tx: &Transaction,
    expected_height: BlockHeight,
    expected_hash: zcash_primitives::block::BlockHash,
    kind: &'static str,
) -> bool {
    let txid = tx.txid();
    match source
        .submit_transaction(tx, expected_height, expected_hash)
        .await
    {
        Ok(SubmitOutcome::Accepted) => {
            tracing::info!(%txid, kind, "submitted");
            true
        }
        Ok(SubmitOutcome::AlreadyInChain) => {
            tracing::info!(%txid, kind, "already in chain");
            true
        }
        Ok(SubmitOutcome::TipChanged) => {
            tracing::info!(%txid, kind, "tip changed before submission");
            false
        }
        Ok(other) => {
            tracing::warn!(?other, %txid, kind, "submission rejected");
            false
        }
        Err(error) => {
            tracing::warn!(%error, %txid, kind, "submission transport failure");
            false
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    #[cfg(feature = "regtest")]
    let boot = Boot::run_regtest().await;
    #[cfg(not(feature = "regtest"))]
    let boot = Boot::run().await;

    let boot_height = boot.height();
    let mut chain_tip: ChainTip = *boot.checkpoint_metadata();
    let (
        network,
        mut chain,
        mut wallet,
        mut registry,
        treasury_keys,
        registry_keys,
        sapling_spend,
        sapling_output,
        mut mtp,
    ) = boot.into_parts();
    let rpc = JsonRpc::new();
    let source = CanonicalBlockSource::new();
    let mut otp_queue = OtpQueue::new();

    let scanning_keys = ScanningKeys::from_account_ufvks(wallet.ufvk_map().clone());
    let registry_orchard = registry_keys
        .fvk()
        .orchard()
        .expect("Registry UFVK carries an Orchard component")
        .clone();
    let registry_ivk = registry_orchard
        .to_ivk(orchard::keys::Scope::External)
        .prepare();
    let registry_recipient = registry_orchard.address_at(0u32, orchard::keys::Scope::External);

    tracing::info!(boot = u32::from(boot_height), "run loop starting");

    'reconnect: loop {
        let stream = match chain.chain_tip_change_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "tip stream open failed; reconnecting");
                tokio::time::sleep(StdDuration::from_secs(5)).await;
                continue 'reconnect;
            }
        };
        tokio::pin!(stream);

        use futures_util::StreamExt as _;
        loop {
            let Some(Ok(message)) = stream.next().await else {
                tracing::warn!("tip stream ended; reconnecting");
                continue 'reconnect;
            };
            let (best_height, best_hash) = zcash::tip_height_hash(&message);

            // The stream's initial item is commonly our current tip. It still
            // needs a settle pass: boot may already have caught up.
            if best_height != chain_tip.block_height() || best_hash != chain_tip.block_hash() {
                let is_reorg = if best_height <= chain_tip.block_height() {
                    true
                } else {
                    match rpc.get_block(&network, chain_tip.block_height() + 1).await {
                        Ok(block) => block.header().prev_block != chain_tip.block_hash(),
                        Err(error) => {
                            tracing::warn!(%error, "reorg check block fetch failed; retrying");
                            tokio::time::sleep(StdDuration::from_secs(5)).await;
                            continue;
                        }
                    }
                };

                if is_reorg {
                    tracing::warn!(
                        applied = u32::from(chain_tip.block_height()),
                        best = u32::from(best_height),
                        "reorg detected; rewinding to common ancestor"
                    );
                    let mut ancestor = chain_tip.block_height();
                    while ancestor > BlockHeight::from(0u32) {
                        let chain_hash = match rpc.get_block_hash(ancestor).await {
                            Ok(hash) => hash,
                            Err(error) => {
                                tracing::warn!(%error, "ancestor walk fetch failed; retrying");
                                tokio::time::sleep(StdDuration::from_secs(5)).await;
                                continue;
                            }
                        };
                        if wallet.block_hash_at(ancestor) == Some(chain_hash) {
                            break;
                        }
                        ancestor = BlockHeight::from_u32(u32::from(ancestor) - 1);
                    }

                    chain_tip = match wallet.truncate_to(ancestor) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            tracing::error!(?error, "wallet truncation failed");
                            continue;
                        }
                    };
                    registry.truncate_to_height(ancestor);
                    mtp.truncate_to(ancestor);
                    tracing::warn!(ancestor = u32::from(ancestor), "rewound to common ancestor");
                }

                while chain_tip.block_height() < best_height {
                    let from_height = chain_tip.block_height();
                    let next_height = from_height + 1;

                    let from_state = loop {
                        match rpc.chain_state_at(from_height).await {
                            Ok(state) => break state,
                            Err(error) => {
                                tracing::warn!(%error, "treestate fetch failed; retrying");
                                tokio::time::sleep(StdDuration::from_secs(5)).await;
                            }
                        }
                    };
                    let block = match rpc.get_block(&network, next_height).await {
                        Ok(block) => block,
                        Err(error) => {
                            tracing::warn!(%error, "block fetch failed; retrying");
                            tokio::time::sleep(StdDuration::from_secs(5)).await;
                            continue;
                        }
                    };
                    let block_time = block.header().time;

                    let candidates =
                        decrypt_name_notes(&network, &block, &registry_ivk, registry_recipient);
                    let (header, batches) = decrypt_block(&network, block, &scanning_keys);
                    let scanned = match scan_block(
                        &network,
                        next_height,
                        &header,
                        batches,
                        &scanning_keys,
                        &Nullifiers::empty(),
                        Some(&chain_tip),
                        |_| {
                            Ok::<
                                Option<(AccountId, Option<transparent::keys::TransparentKeyScope>)>,
                                Infallible,
                            >(None)
                        },
                    ) {
                        Ok(scanned) => scanned,
                        Err(error) => {
                            tracing::warn!(?error, "scan_block failed; retrying block");
                            tokio::time::sleep(StdDuration::from_secs(5)).await;
                            continue;
                        }
                    };

                    let name_notes: Vec<_> = candidates
                        .iter()
                        .map(|candidate| {
                            zns_mint::mint::registry::ReceivedNameNote::new(
                                candidate.txid,
                                candidate.action_index,
                                candidate.note.clone(),
                                candidate.payload.clone(),
                            )
                        })
                        .collect();
                    let next_registry =
                        registry.apply_block(&network, &wallet, &scanned, &name_notes);

                    for candidate in &candidates {
                        if wallet
                            .store_name_note(
                                &scanned,
                                candidate.ordinal,
                                candidate.txid,
                                candidate.action_index,
                                candidate.note.clone(),
                                candidate.ephemeral_key.clone(),
                                candidate.memo,
                            )
                            .is_none()
                        {
                            tracing::error!(txid = %candidate.txid, "failed to store decrypted Name Note");
                        }
                    }

                    let next_metadata = scanned.to_block_metadata();
                    if let Err(error) = wallet.put_blocks(&from_state, vec![scanned]) {
                        tracing::error!(?error, "put_blocks failed; retrying block");
                        continue;
                    }

                    registry = next_registry;
                    chain_tip = next_metadata;
                    mtp.update(next_height, block_time);
                }
            }

            let tip = chain_tip.block_height();
            let tip_hash = chain_tip.block_hash();
            let target_height = tip + 1;

            // Re-read before every request. A successful producer records its
            // inputs, so the next iteration cannot use a stale intake view.
            let mut handled = Vec::new();
            loop {
                let next_request = wallet
                    .unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip))
                    .into_iter()
                    .filter(|note| note.mined_height().is_some())
                    .find_map(|note| {
                        let note_id = *note.internal_note_id();
                        if handled.contains(&note_id) {
                            return None;
                        }
                        let memo = match wallet.get_memo(note_id).ok().flatten() {
                            Some(Memo::Future(bytes)) => *bytes.as_array(),
                            _ => return None,
                        };
                        Some((note_id, note, memo))
                    });
                let Some((note_id, note, memo)) = next_request else {
                    break;
                };
                handled.push(note_id);

                if let Some((action, name, ua)) = parse_request(&network, &memo) {
                    match action {
                        Action::Claim => {
                            let result = {
                                let mut settle = Settle::new(
                                    &network,
                                    &mut wallet,
                                    &registry,
                                    &mut otp_queue,
                                    &treasury_keys,
                                    &registry_keys,
                                    &sapling_spend,
                                    &sapling_output,
                                    tip,
                                    target_height,
                                );
                                settle.claim(name, ua, &note)
                            };
                            match result {
                                Ok(tx) => {
                                    let _ =
                                        submit(&source, &tx, tip, tip_hash, "claim/refund").await;
                                }
                                Err(error) => tracing::warn!(?error, "claim settlement failed"),
                            }
                        }
                        Action::Update | Action::Release => {
                            let Some(mtp_now) = mtp.current() else {
                                tracing::debug!("MTP window incomplete; deferring OTP relay");
                                continue;
                            };
                            let Some(record) = registry.record(&name) else {
                                continue;
                            };
                            let Some(controller_ua) = record.ua.as_ref() else {
                                continue;
                            };
                            let Some(outcome) = issue_relay(
                                &network,
                                &name,
                                action,
                                &ua,
                                controller_ua,
                                record.commitment,
                                target_height,
                                mtp_now,
                                &mut wallet,
                                &treasury_keys,
                                &sapling_spend,
                                &sapling_output,
                            ) else {
                                continue;
                            };

                            match outcome.result {
                                Ok(txid) => match wallet.get_transaction(txid) {
                                    Ok(Some(tx)) => {
                                        if submit(&source, &tx, tip, tip_hash, "OTP relay").await {
                                            if let Some(request) = outcome.relay_otp {
                                                otp_queue.push(request);
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        tracing::error!(%txid, "stored OTP relay transaction missing")
                                    }
                                    Err(error) => {
                                        tracing::error!(?error, %txid, "could not retrieve OTP relay transaction")
                                    }
                                },
                                Err(error) => {
                                    tracing::warn!(?error, "OTP relay construction failed")
                                }
                            }
                        }
                    }
                    continue;
                }

                let Some((name, action, ua_string, otp)) = decode_otp_relay_memo(&memo) else {
                    continue;
                };
                let Some(ua) = (match zcash_keys::address::Address::decode(&network, &ua_string) {
                    Some(zcash_keys::address::Address::Unified(ua)) => Some(ua),
                    _ => None,
                }) else {
                    continue;
                };
                let Some(mtp_now) = mtp.current() else {
                    tracing::debug!("MTP window incomplete; deferring OTP echo");
                    continue;
                };

                let result = {
                    let mut settle = Settle::new(
                        &network,
                        &mut wallet,
                        &registry,
                        &mut otp_queue,
                        &treasury_keys,
                        &registry_keys,
                        &sapling_spend,
                        &sapling_output,
                        tip,
                        target_height,
                    );
                    match action {
                        Action::Update => settle.update(name, ua, &note, &otp, mtp_now),
                        Action::Release => settle.release(name, ua, &note, &otp, mtp_now),
                        Action::Claim => unreachable!("OTP memo decoder rejects claims"),
                    }
                };
                match result {
                    Ok(Some(tx)) => {
                        let kind = match action {
                            Action::Update => "update",
                            Action::Release => "release",
                            Action::Claim => unreachable!("OTP memo decoder rejects claims"),
                        };
                        let _ = submit(&source, &tx, tip, tip_hash, kind).await;
                    }
                    Ok(None) => {
                        tracing::debug!(action = action.as_str(), "OTP echo was not authorized")
                    }
                    Err(error) => {
                        tracing::warn!(?error, action = action.as_str(), "OTP settlement failed")
                    }
                }
            }

            // Housekeeping follows settlement. Sweeps use the upstream
            // proposal pipeline and have already stored their transactions.
            for result in [
                sweep_ironwood_to_vault(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                    &sapling_spend,
                    &sapling_output,
                ),
                sweep_sapling_to_vault(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                    &sapling_spend,
                    &sapling_output,
                ),
            ] {
                match result {
                    Ok(Some(txid)) => match wallet.get_transaction(txid) {
                        Ok(Some(tx)) => {
                            let _ = submit(&source, &tx, tip, tip_hash, "vault sweep").await;
                        }
                        Ok(None) => tracing::error!(%txid, "stored sweep transaction missing"),
                        Err(error) => {
                            tracing::error!(?error, %txid, "could not retrieve sweep transaction")
                        }
                    },
                    Ok(None) => {}
                    Err(error) => tracing::warn!(?error, "vault sweep construction failed"),
                }
            }
        }
    }
}
