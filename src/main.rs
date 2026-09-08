//! The Zcash Name Service attested Mint.
//!
//! The orchestrator: follows the canonical chain, keeps the wallet and
//! registry in lockstep, prices in zats, and speaks the Mint's sentences.
//!
//! One stream, one loop, sequential passes. The gRPC tip stream is the only
//! event source; blocks are fetched forward-only; the ledger applies each
//! block to the wallet, the registry, and the clock; and the world is then
//! evaluated as of that block — requests, OTP echoes, liveness, sweeps.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::time::Duration as StdDuration;

use futures_util::StreamExt as _;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{WalletRead as _, WalletWrite as _};
use zcash_primitives::block::BlockHash;
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_client_backend::scanning::{Nullifiers, ScanningKeys};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;
use zcash_protocol::value::Zatoshis;

use zns_mint::boot::Boot;
use zns_mint::key::{RegistryKeys, TreasuryKeys};
use zns_mint::mint::otp::{issue_relay, OtpQueue};
use zns_mint::mint::registry::ReceivedNameNote;
use zns_mint::mint::treasury::{
    fee_note_candidates, sweep_ironwood_to_vault, sweep_sapling_to_vault,
};
use zns_mint::mint::{
    Action, Challenge, ChainTip, MINT_BIRTHDAY, Name, Request, Term, TREASURY_ACCOUNT,
};
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{self, CanonicalBlockSource, JsonRpc, SubmitOutcome};

/// Transport retry pause: connection, timeout, and 5xx failures re-try
/// after this long. Trust-path failures are never retried.
const RETRY_PAUSE: StdDuration = StdDuration::from_secs(5);

/// The liveness challenge is issued this close to the release deadline and
/// re-issued while it goes unanswered. The OTP itself lives for `D_OTP`, so
/// the re-issue rate is bounded by the block cadence inside this window.
const CHALLENGE_WINDOW: i64 = crate::mint::otp::D_OTP;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    #[cfg(feature = "regtest")]
    let boot = Boot::run_regtest().await;
    #[cfg(not(feature = "regtest"))]
    let boot = Boot::run().await;

    let (
        network,
        mut chain,
        mut wallet,
        origin,
        mut registry,
        treasury_keys,
        registry_keys,
        mut mtp,
        mut oracle,
        mut pending_challenges,
    ) = boot.into_parts();

    let rpc = JsonRpc::new();
    let source = CanonicalBlockSource::new();

    let mut chain_tip: ChainTip = zns_mint::boot::block_metadata(&origin);

    // The scanner's keyset is derived from the wallet's own UFVK map — not
    // from the keys, and not handed over by boot. The scanner scans exactly
    // the accounts the wallet stores, by construction. (Seam criterion: the
    // loop acquires this for itself.)
    let scanning_keys = ScanningKeys::from_account_ufvks(wallet.ufvk_map().clone());

    let spend = zns_mint::boot::load_sapling_spend_params();
    let output = zns_mint::boot::load_sapling_output_params();

    tracing::info!(
        boot = u32::from(origin.block_height()),
        "run loop starting"
    );

    'reconnect: loop {
        let mut stream = match chain.chain_tip_change_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "tip stream open failed; reconnecting");
                tokio::time::sleep(RETRY_PAUSE).await;
                continue 'reconnect;
            }
        };

        loop {
            let Some(Ok(message)) = stream.next().await else {
                tracing::warn!("tip stream ended; reconnecting");
                continue 'reconnect;
            };
            let (best, best_hash) = zcash::tip_height_hash(&message);

            // Reorg: the next canonical block does not continue our tip.
            // Walk ancestors until the wallet recognizes one, then rewind
            // every replica lane to it — blocks are refetched forward.
            let reorged = best <= chain_tip.block_height()
                || match rpc.get_block(&network, chain_tip.block_height() + 1).await {
                    Ok(block) => block.header().prev_block != chain_tip.block_hash(),
                    Err(error) => {
                        tracing::warn!(%error, "reorg check failed; retrying");
                        tokio::time::sleep(RETRY_PAUSE).await;
                        continue;
                    }
                };
            if reorged {
                let mut ancestor = chain_tip.block_height();
                let ancestor_hash = loop {
                    match rpc.get_block_hash(ancestor).await {
                        Ok(hash) => {
                            if wallet.block_hash_at(ancestor) == Some(hash) {
                                break hash;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "ancestor walk fetch failed; retrying");
                            tokio::time::sleep(RETRY_PAUSE).await;
                            continue;
                        }
                    }
                    // The origin is the wallet floor: a fork below it is
                    // unrecoverable by construction.
                    if ancestor == MINT_BIRTHDAY - 1 {
                        panic!("FATAL: fork below the mint birthday");
                    }
                    ancestor = BlockHeight::from_u32(u32::from(ancestor) - 1);
                };
                wallet
                    .truncate_to(ancestor)
                    .expect("FATAL: wallet truncation failed");
                registry.truncate_to_height(ancestor);
                mtp.truncate_to(ancestor);
                chain_tip = wallet
                    .block_metadata_at(ancestor)
                    .expect("rewound to a known height");
                tracing::warn!(
                    ancestor = u32::from(ancestor),
                    "rewound to common ancestor"
                );
            }

            // Forward-only catch-up: one block at a time.
            while chain_tip.block_height() < best {
                let from_height = chain_tip.block_height();
                let next_height = from_height + 1;

                let from_state = loop {
                    match rpc.chain_state_at(from_height).await {
                        Ok(state) => break state,
                        Err(error) => {
                            tracing::warn!(%error, "treestate fetch failed; retrying");
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                    }
                };
                let block = loop {
                    match rpc.get_block(&network, next_height).await {
                        Ok(block) => break block,
                        Err(error) => {
                            tracing::warn!(%error, "block fetch failed; retrying");
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                    }
                };
                let block_time = block.header().time;

                let candidates = zns_mint::mint::decrypt_name_notes(
                    &network,
                    &block,
                    &registry_keys,
                );
                let name_notes: Vec<_> = candidates
                    .iter()
                    .map(|candidate| {
                        ReceivedNameNote::new(
                            candidate.txid,
                            candidate.action_index,
                            candidate.note.clone(),
                            candidate.payload.clone(),
                        )
                    })
                    .collect();
                let (header, batches) = decrypt_block(&network, block, &scanning_keys);
                let scanned = loop {
                    match scan_block(
                        &network,
                        next_height,
                        &header,
                        batches.clone(),
                        &scanning_keys,
                        &Nullifiers::empty(),
                        Some(&chain_tip),
                        |_| {
                            Ok::<
                                Option<(
                                    zip32::AccountId,
                                    Option<transparent::keys::TransparentKeyScope>,
                                >,
                                Infallible,
                            >(None)
                        },
                    ) {
                        Ok(scanned) => break scanned,
                        Err(error) => {
                            tracing::warn!(%error, "scan_block failed; retrying");
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                    }
                };

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
                        tracing::error!(
                            txid = %candidate.txid,
                            "failed to store decrypted Name Note"
                        );
                    }
                }

                let next_metadata = scanned.to_block_metadata();
                match wallet.put_blocks(&from_state, vec![scanned]) {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::error!(%error, "put_blocks failed; retrying block");
                        continue;
                    }
                }

                // The clock advances with the applied block; every timestamp
                // from here on is this block's MTP.
                mtp.update(next_height, block_time);
                let mtp_now = mtp.current().expect("window complete during scan");

                let next_registry = registry.apply_block(
                    &network,
                    &wallet,
                    &scanned,
                    &name_notes,
                    mtp_now,
                );
                registry = next_registry;
                chain_tip = next_metadata;

                // The rate is policy input, not chain state: it advances per
                // block and never rewinds with a reorg.
                oracle.accumulate(pricing_round().await, mtp_now);
            }

            // The world, evaluated as of the current tip.
            let tip = chain_tip.block_height();
            let target_height = tip + 1;
            let mtp_now = mtp.current().expect("MTP complete while synced");

            // Intake: every unspent Treasury note is either a request or an
            // OTP echo. Claims settle; update/release requests are answered
            // with a liveness challenge; echoes authorize their transitions.
            let mut handled: Vec<_> = Vec::new();
            loop {
                let Some((note_id, note, memo)) = next_treasury_memo(
                    &wallet, tip, &handled,
                ) else {
                    break;
                };
                handled.push(note_id);

                if let Some(request) = Request::decode(&network, &memo) {
                    handle_request(
                        request,
                        &note,
                        &network,
                        &mut wallet,
                        &registry,
                        &mut oracle,
                        &mut pending_challenges,
                        &treasury_keys,
                        &registry_keys,
                        &spend,
                        &output,
                        tip,
                        target_height,
                        mtp_now,
                        &source,
                        &mut retained,
                    )
                    .await;
                    continue;
                }

                let Some(challenge) = Challenge::decode(&network, &memo) else {
                    continue; // not ours
                };
                let request = match challenge.action {
                    Action::Update => Request::Update {
                        name: challenge.name.clone(),
                        ua: challenge.ua.clone(),
                        extend_years: None,
                    },
                    Action::Release => Request::Release {
                        name: challenge.name.clone(),
                        ua: challenge.ua.clone(),
                    },
                    Action::Claim => continue,
                };

                let Some(transition) = registry.authorize(
                    &mut pending_challenges,
                    request,
                    Some(&challenge.code.digits()),
                    mtp_now,
                ) else {
                    tracing::debug!(action = challenge.action.as_str(), "echo not authorized");
                    continue;
                };

                let tx = match transition {
                    NameNote for update/release → assemble on a treasury-funded builder,
                    _ => unreachable!(),
                };
                let _ = submit(&source, &tx, tip, target_height, challenge.action.as_str()).await;
            }

            // Liveness: every live name owes an accepted update per interval.
            // Inside the window, challenge the bound address; past the
            // deadline, release — the Mint's own sentence, no OTP.
            for (name, record) in registry.name_chain() {
                if record.action == Action::Release {
                    continue;
                }
                let due_in = record.release_deadline.as_seconds() - mtp_now.as_seconds();

                if due_in <= 0 {
                    let Some(transition) = registry.authorize(
                        &mut pending_challenges,
                        Request::Release {
                            name: name.clone(),
                            ua: record.ua.clone().expect("live names are bound"),
                        },
                        None,
                        mtp_now,
                    ) else {
                        continue;
                    };
                    let predecessor = wallet.unspent_ironwood_note_by_rho(
                        zns_mint::mint::REGISTRY_ACCOUNT,
                        record.rho,
                        TargetHeight::from(target_height),
                    );
                    let Some(predecessor) = predecessor else { continue };
                    let tx = match transition {
                        NameNote::Release { name, ua, prev } => {
                            let opening = predecessor_opening(
                                &network, &wallet, &predecessor,
                            );
                            build_lifecycle_release(
                                &network, &wallet, &treasury_keys, &registry_keys,
                                &spend, &output, name, ua, prev, opening,
                                tip, target_height,
                            )
                        }
                        _ => unreachable!("liveness releases are releases"),
                    };
                    ...submit...
                    continue;
                }

                if due_in <= CHALLENGE_WINDOW {
                    let Some(controller) = &record.ua else { continue };
                    let Some(outcome) = issue_relay(
                        &network, name, Action::Update, &record.ua, controller,
                        target_height, mtp_now, &mut wallet, &treasury_keys,
                        &spend, &output,
                    ) else {
                        continue;
                    };
                    ...submit relay...
                    if let Some(request) = outcome.relay_otp {
                        pending_challenges.push(request);
                    }
                }
            }

            // Housekeeping: the vault takes the excess, the float stays.
            for sweep in [
                sweep_ironwood_to_vault(&network, &mut wallet, &treasury_keys,
                    &spend, &output),
                sweep_sapling_to_vault(&network, &mut wallet, &treasury_keys,
                    &spend, &output),
            ] {
                match sweep {
                    Ok(Some(tx)) => {
                        let _ = submit(&source, &tx, tip, target_height, "vault sweep").await;
                    }
                    Ok(None) => {}
                    Err(error) => tracing::warn!(?error, "vault sweep failed"),
                }
            }
        }
    }
}

/// Fetches one pricing round from the venues and collapses it to the
/// oracle's input. Transport failures return `None` — the standing rate
/// carries.
