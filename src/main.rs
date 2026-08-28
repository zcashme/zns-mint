//! The Zcash Name Service attested Mint.
//!
//! `zns-mint` is the single registrar for the Zcash Name Service, a
//! human-readable naming layer over the Zcash transaction log. It owns
//! the sealed Treasury seed, derives the registry state from the
//! canonical Zcash chain, evaluates the naming policy inside a TEE, and
//! writes accepted transitions — claims, updates, and lifecycle releases —
//! into Ironwood Name Notes whose memos and commitments are verifiable
//! by any Resolver.
//!
//! The Mint listens to a co-located Zebra indexer for chain-tip changes.
//! Each new best-chain tip advances the wallet and registry forward
//! block-by-block, scanning Name Notes with the published registry key,
//! applying them to the on-chain registry; reorgs are rolled back to the
//! common ancestor before the chain catches up again.
//!
//! After catch-up, matured request Name Notes are settled exactly once:
//! claim requests create new registrations, update and release requests
//! complete their OTP authorization, lifecycle releases enforce
//! expiration and liveness, and the resulting reply transactions are
//! built, signed, and broadcast through the Zebra node. Housekeeping
//! then sweeps Treasury funds to the vault.
//!
//! State is held by `Wallet`, `Registry`, and `OtpQueue`; this entry
//! point only sequences their calls.

use std::convert::Infallible;
use std::time::Duration as StdDuration;

use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::WalletWrite as _;
use zcash_client_backend::scanning::Nullifiers;
use zcash_client_backend::scanning::ScanningKeys;
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_protocol::consensus::Parameters;
use zcash_protocol::memo::Memo;
use zip32::AccountId;

use zns_mint::boot::Boot;
use zns_mint::mint::otp::{decode_otp_relay_memo, OtpQueue};
use zns_mint::mint::treasury::parse_request;
use time::Timestamp;
use zns_mint::mint::{decrypt_name_notes, ChainTip};
use zns_mint::wallet::assembly::{assemble_v6_transaction, serialize_tx};
use zns_mint::mint::{TREASURY_ACCOUNT, AssemblyError};
use zns_mint::zcash::{self, CanonicalBlockSource, JsonRpc, SubmitOutcome};

/// Minimum spendable Treasury balance to trigger a vault sweep (2 ZEC).
const SWEEP_THRESHOLD: zcash_protocol::value::Zatoshis = zcash_protocol::value::Zatoshis::const_from_u64(200_000_000);

/// Amount retained as Treasury change after a sweep (0.01 ZEC).
const SWEEP_RESERVE: zcash_protocol::value::Zatoshis = zcash_protocol::value::Zatoshis::const_from_u64(1_000_000);

/// The project vault's P2PKH address (placeholder pending final approved address).
const VAULT_ADDRESS: zcash_primitives::transparent::address::TransparentAddress =
    zcash_primitives::transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]);

/// Sweeps excess Treasury Ironwood balance to the project vault.
fn sweep_ironwood_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut zns_mint::wallet::Wallet,
    treasury_keys: &zns_mint::key::TreasuryKeys,
) -> Result<Option<zcash_primitives::transaction::TxId>, AssemblyError> {
    use zcash_client_backend::data_api::wallet::{
        create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
    };
    use zcash_client_backend::data_api::wallet::input_selection::{
        GreedyInputSelector, LockFilter, LockedInputPolicy, SpendPolicy,
    };
    use zcash_client_backend::fees::{standard::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule};
    use zcash_client_backend::wallet::OvkPolicy;
    use zcash_protocol::ShieldedPool;
    use zcash_protocol::value::Zatoshis;

    let spendable = wallet
        .account_balances()
        .get(&TREASURY_ACCOUNT)
        .map(|b| b.ironwood_balance().spendable_value())
        .unwrap_or(Zatoshis::ZERO);
    if spendable <= SWEEP_THRESHOLD {
        return Ok(None);
    }

    let sweep_amount = (spendable - SWEEP_RESERVE).ok_or(AssemblyError::InsufficientFunds)?;
    let recipient = zcash_keys::address::Address::Transparent(VAULT_ADDRESS).to_zcash_address(network);
    let payment = zip321::Payment::new(recipient, Some(sweep_amount), None, None, None, Vec::new())
        .map_err(|e| AssemblyError::UpstreamTransfer(format!("{e:?}")))?;
    let request = zip321::TransactionRequest::new(vec![payment])
        .map_err(|e| AssemblyError::UpstreamTransfer(format!("{e:?}")))?;

    let input_selector = GreedyInputSelector::new();
    let change_strategy = SingleOutputChangeStrategy::<zns_mint::wallet::Wallet>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );
    let proposal = propose_transfer(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::new_symmetrical(std::num::NonZeroU32::MIN, false),
        &SpendPolicy::shielded_pools([ShieldedPool::Ironwood]),
        None,
        None,
    ).map_err(|e| AssemblyError::UpstreamTransfer(format!("{e:?}")))?;

    let (spend_prover, output_prover) = signer::sapling_provers();
    let spending_keys = SpendingKeys::new(treasury_keys.usk_clone());
    let txids = create_proposed_transactions(
        wallet,
        network,
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    ).map_err(|e| AssemblyError::UpstreamTransfer(format!("{e:?}")))?;

    Ok(Some(*txids.first()))
}

/// Sweeps all spendable Treasury Sapling notes to the project vault.
fn sweep_sapling_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut zns_mint::wallet::Wallet,
    treasury_keys: &zns_mint::key::TreasuryKeys,
) -> Result<Option<zcash_primitives::transaction::TxId>, AssemblyError> {
    use zcash_client_backend::data_api::wallet::input_selection::{
        GreedyInputSelectorError, LockedInputPolicy,
    };
    use zcash_client_backend::data_api::wallet::{
        create_proposed_transactions, propose_send_max_transfer, ConfirmationsPolicy, CreateErrT,
        ProposeSendMaxErrT, SpendingKeys,
    };
    use zcash_client_backend::data_api::{MaxSpendMode, WalletRead as _};
    use zcash_client_backend::fees::StandardFeeRule;
    use zcash_client_backend::wallet::OvkPolicy;
    use zcash_protocol::ShieldedPool;
    use zcash_protocol::value::Zatoshis;

    let summary = wallet
        .get_wallet_summary(ConfirmationsPolicy::new_symmetrical(std::num::NonZeroU32::MIN, false))
        .ok()
        .flatten();
    let sapling_balance = summary
        .as_ref()
        .and_then(|s| s.account_balances().get(&TREASURY_ACCOUNT))
        .map(|b| b.sapling_balance().spendable_value())
        .unwrap_or(Zatoshis::ZERO);
    if sapling_balance == Zatoshis::ZERO {
        return Ok(None);
    }

    let vault_recipient =
        zcash_keys::address::Address::Transparent(VAULT_ADDRESS).to_zcash_address(network);
    let proposal = propose_send_max_transfer(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &[ShieldedPool::Sapling],
        &StandardFeeRule::Zip317,
        vault_recipient,
        None,
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::new_symmetrical(std::num::NonZeroU32::MIN, false),
        &LockedInputPolicy::default(),
        None,
    )
    .map_err(|e: ProposeSendMaxErrT<zns_mint::wallet::Wallet, std::convert::Infallible, StandardFeeRule>| {
        AssemblyError::UpstreamTransfer(format!("{e:?}"))
    })?;

    let (spend_prover, output_prover) = signer::sapling_provers();
    let spending_keys = SpendingKeys::new(treasury_keys.usk_clone());
    let txids = create_proposed_transactions(
        wallet,
        network,
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .map_err(|e: CreateErrT<
        zns_mint::wallet::Wallet,
        GreedyInputSelectorError,
        StandardFeeRule,
        <StandardFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error,
        zcash_client_backend::wallet::NoteId,
    >| AssemblyError::UpstreamTransfer(format!("{e:?}")))?;

    Ok(Some(*txids.first()))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    // ── Setup ────────────────────────────────────────────────────────────
    #[cfg(feature = "regtest")]
    let boot = Boot::run_regtest().await;
    #[cfg(not(feature = "regtest"))]
    let boot = Boot::run().await;

    let boot_height = boot.height();
    // ChainTip = boot checkpoint (first-class position)
    // Must be cloned before into_parts consumes the boot evidence.
    let mut chain_tip: ChainTip = *boot.checkpoint_metadata();
    let (network, mut chain, wallet, registry, treasury_keys, registry_keys, sapling_spend, sapling_output) =
        boot.into_parts();
    let rpc = JsonRpc::new();
    let source = CanonicalBlockSource::new();

    let mut wallet = wallet;
    let mut registry = registry;
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
    let registry_recipient =
        registry_orchard.address_at(0u32, orchard::keys::Scope::External);

    tracing::info!(boot = u32::from(boot_height), "run loop starting");

    'outer: loop {
        let stream = match chain.chain_tip_change_stream().await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(%e, "tip stream open failed; reconnecting");
                tokio::time::sleep(StdDuration::from_secs(5)).await;
                continue 'outer;
            }
        };
        tokio::pin!(stream);

        use futures_util::StreamExt as _;
        loop {
            let Some(Ok(message)) = stream.next().await else {
                tracing::warn!("tip stream ended; reconnecting");
                continue 'outer;
            };
            let (height, hash) = zcash::tip_height_hash(&message);

            // No change? Zebra's tip matches our tip.
            if height == chain_tip.block_height()
                && hash == chain_tip.block_hash()
            {
                continue;
            }

            // Reorg? If Zebra's tip is at or below our tip, or if the next
            // block's parent doesn't match our tip hash, the chain diverged.
            let is_reorg = if height <= chain_tip.block_height() {
                true
            } else {
                let block = match rpc.get_block(&network, chain_tip.block_height() + 1).await {
                    Ok(block) => block,
                    Err(e) => {
                        tracing::warn!(%e, "reorg check block fetch failed; retrying");
                        tokio::time::sleep(StdDuration::from_secs(5)).await;
                        continue;
                    }
                };
                block.header().prev_block != chain_tip.block_hash()
            };

            if is_reorg {
                tracing::warn!(
                    applied = u32::from(chain_tip.block_height()),
                    best = u32::from(height),
                    "reorg detected; rewinding to common ancestor"
                );
                let mut ancestor = chain_tip.block_height();
                while ancestor > zcash_protocol::consensus::BlockHeight::from(0u32) {
                    let chain_hash = match rpc.get_block_hash(ancestor).await {
                        Ok(hash) => hash,
                        Err(e) => {
                            tracing::warn!(%e, "ancestor walk fetch failed; retrying");
                            tokio::time::sleep(StdDuration::from_secs(5)).await;
                            continue;
                        }
                    };
                    if wallet.block_hash_at(ancestor) == Some(chain_hash) {
                        break;
                    }
                    ancestor = zcash_protocol::consensus::BlockHeight::from_u32(
                        u32::from(ancestor) - 1,
                    );
                }
                tracing::warn!(ancestor = u32::from(ancestor), "rewinding to ancestor");
                chain_tip = match wallet.truncate_to(ancestor) {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        tracing::error!(?e, "wallet truncation failed");
                        continue;
                    }
                };
                registry.truncate_to_height(ancestor);
            }

            // Catch up: apply blocks one at a time from our tip through
            // `height`, retrying transient I/O indefinitely.
            while chain_tip.block_height() < height {
                let from_height = chain_tip.block_height();
                let next_height = from_height + 1;

                let from_state = loop {
                    match rpc.chain_state_at(from_height).await {
                        Ok(state) => break state,
                        Err(e) => {
                            tracing::warn!(%e, "treestate fetch failed; retrying");
                            tokio::time::sleep(StdDuration::from_secs(5)).await;
                        }
                    }
                };

                let block = match rpc.get_block(&network, next_height).await {
                    Ok(block) => block,
                    Err(e) => {
                        tracing::warn!(%e, "block fetch failed; retrying");
                        tokio::time::sleep(StdDuration::from_secs(5)).await;
                        continue;
                    }
                };

                // ZNS pass first (needs `&block`); the standard pass consumes it.
                let candidates = decrypt_name_notes(
                    &network,
                    &block,
                    &registry_ivk,
                    registry_recipient,
                );

                let prior_metadata = Some(&chain_tip);
                let (header, batches) =
                    decrypt_block(&network, block, &scanning_keys);
                let nullifiers = Nullifiers::empty();
                // The published Treasury UA omits a transparent receiver, so no
                // transparent output is ever attributed to a wallet account:
                // the closure permanently yields `None`.
                let scanned = match scan_block(
                    &network,
                    next_height,
                    &header,
                    batches,
                    &scanning_keys,
                    &nullifiers,
                    prior_metadata,
                    |_| {
                        Ok::<
                            Option<(
                                AccountId,
                                Option<transparent::keys::TransparentKeyScope>,
                            )>,
                            Infallible,
                        >(None)
                    },
                ) {
                    Ok(scanned) => scanned,
                    Err(e) => {
                        tracing::warn!(?e, "scan_block failed; retrying block");
                        tokio::time::sleep(StdDuration::from_secs(5)).await;
                        continue;
                    }
                };

                // Registry evidence is judged against the pre-put wallet (its
                // fee-note set evolves per transaction inside `apply_block`).
                let name_notes: Vec<_> = candidates
                    .iter()
                    .map(|c| {
                        zns_mint::mint::registry::ReceivedNameNote::new(
                            c.txid,
                            c.action_index,
                            c.note.clone(),
                            c.payload.clone(),
                        )
                    })
                    .collect();

                // Compute new registry BEFORE committing the wallet — if the
                // wallet commit fails, we discard this and retry cleanly.
                let new_registry =
                    registry.apply_block(&network, &wallet, &scanned, &name_notes);

                // The wallet's own record of its Name Notes — before
                // `put_blocks` consumes the `ScannedBlock`.
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
                            "failed to store decrypted Name Note — registry keys missing?"
                        );
                    }
                }

                // Extract BlockMetadata BEFORE put_blocks consumes scanned
                let new_metadata = scanned.to_block_metadata();

                match wallet.put_blocks(&from_state, vec![scanned]) {
                    Ok(()) => {}
                    Err(e) => {
                        // Wallet commit failed — discard new_registry, retry
                        tracing::error!(?e, "put_blocks failed");
                        continue;
                    }
                }

                // Swap in new registry (atomic with wallet commit)
                registry = new_registry;

                // Advance chain_tip (pull — only after wallet committed)
                chain_tip = new_metadata;


            }

            // ── Settle ──────────────────────────────────────────────────────

            let tip = chain_tip.block_height();
            let tip_hash = chain_tip.block_hash();
            let target = tip + 1;
            // Intake: every confirmed Treasury note. Spent notes are naturally
            // excluded because the wallet marks them spent on broadcast.
            let intake: Vec<_> = wallet
                .unspent_ironwood_notes(TREASURY_ACCOUNT)
                .into_iter()
                .filter(|note| note.mined_height().is_some())
                .collect();

            for note in intake {
                let mtp = Timestamp::now();
                let value = note
                    .note_value()
                    .expect("Ironwood note values are within valid ZEC bounds by consensus");
                let confirmed_height = note.mined_height().expect("filtered on Some");
                let Some(Memo::Future(memo)) = wallet
                    .get_memo(*note.internal_note_id())
                    .ok()
                    .flatten()
                else {
                    continue;
                };
                let memo = *memo.as_array();

                let outcome = parse_request(&network, &memo)
                    .map(|(action, name, ua)| match action {
                        zns_mint::mint::Action::Claim => {
                            zns_mint::mint::registry::authorize::process_claim(
                                &network,
                                name.clone(),
                                ua,
                                value,
                                confirmed_height,
                                tip,
                                target,
                                &mut wallet,
                                &registry,
                                &registry_keys,
                            )
                        }
                        // Relay: controller receives OTP, requester's UA rides memo.
                        // An ordinary upstream-built Treasury payment; the
                        // request note itself is not consumed.
                        zns_mint::mint::Action::Update | zns_mint::mint::Action::Release => {
                            let Some(record) = registry.record(&name) else {
                                return None;
                            };
                            zns_mint::mint::otp::issue_relay(
                                &network,
                                &name,
                                action,
                                &ua,
                                record
                                    .ua
                                    .as_ref()
                                    .expect("relay requires a live controller"),
                                target,
                                mtp,
                                &mut wallet,
                                &treasury_keys,
                            )
                        }
                    })
                    .or_else(|| Some({
                        // Controller forwarded a relay memo back.
                        decode_otp_relay_memo(&memo).and_then(
                            |(otp_name, otp_action, otp_ua_str, otp_digits)| {
                                let otp_ua = match zcash_keys::address::Address::decode(
                                    &network,
                                    &otp_ua_str,
                                )? {
                                    zcash_keys::address::Address::Unified(ua) => ua,
                                    _ => return None,
                                };
                                // The name must be registered; the
                                // authorization binds to the live tip at
                                // execution time.
                                registry.record(&otp_name)?;
                                zns_mint::mint::registry::authorize::process_transition(
                                    &network,
                                    otp_name,
                                    otp_action,
                                    otp_ua,
                                    &otp_digits,
                                    mtp,
                                    tip,
                                    target,
                                    &mut otp_queue,
                                    &mut wallet,
                                    &registry,
                                    &registry_keys,
                                )
                            },
                        )
                    })).flatten();

                if outcome.is_none() {
                    // Not a ZNS request or relay memo.
                    continue;
                }

                if let Some(outcome) = outcome {
                    match outcome.result {
                        Ok((kind, txid, hex, _reserved)) => {
                            let mut accepted = false;
                            match source
                                .submit_transaction(&hex, &txid.to_string(), tip, tip_hash)
                                .await
                            {
                                Ok(SubmitOutcome::Accepted) => {
                                    accepted = true;
                                    tracing::info!(
                                        %txid, kind = kind.as_str(), "submitted"
                                    )
                                }
                                Ok(SubmitOutcome::AlreadyInChain) => {
                                    accepted = true;
                                    tracing::info!(
                                        %txid, kind = kind.as_str(), "already in chain"
                                    )
                                }
                                Ok(other) => {
                                    tracing::warn!(
                                        ?other, %txid,
                                        kind = kind.as_str(),
                                        "submit not accepted"
                                    );
                                }
                                Err(e) => tracing::warn!(
                                    %e, %txid,
                                    kind = kind.as_str(),
                                    "submit transport error"
                                ),
                            }
                            if let Some(req) = outcome.relay_otp {
                                if accepted {
                                    otp_queue.push(req);
                                }
                            }
                        }
                        Err(error) => {
                            tracing::warn!(?error, "assembly failed");
                        }
                    }
                }
            }

            // Housekeeping: vault sweep.
            let sweep_tip = tip;
            let produced: Vec<zcash_primitives::transaction::TxId> = [
                sweep_ironwood_to_vault(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                ),
                sweep_sapling_to_vault(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                ),
            ]
            .into_iter()
            .filter_map(|r| match r {
                Ok(Some(txid)) => Some(txid),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(?e, "housekeeping failed");
                    None
                }
            })
            .collect();
            for txid in produced {
                match wallet.get_transaction(txid) {
                    Ok(Some(tx)) => match serialize_tx(&tx) {
                        Ok(hex) => {
                            match source
                                .submit_transaction(
                                    &hex,
                                    &txid.to_string(),
                                    sweep_tip,
                                    tip_hash,
                                )
                                .await
                            {
                                Ok(SubmitOutcome::Accepted)
                                | Ok(SubmitOutcome::AlreadyInChain) => {
                                    tracing::info!(%txid, "submitted")
                                }
                                other => tracing::warn!(?other, %txid, "submit not accepted"),
                            }
                        }
                        Err(e) => {
                            tracing::error!(?e, %txid, "serialization failed")
                        }
                    },
                    other => {
                        tracing::error!(?other, %txid, "stored transaction missing")
                    }
                }
            }
        }
    }
}
