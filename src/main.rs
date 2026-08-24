//! zns-mint run loop.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::time::Duration;

use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::WalletWrite as _;
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_client_backend::scanning::Nullifiers;
use zcash_client_backend::scanning::ScanningKeys;
use zip32::AccountId;

use zns_mint::boot::Boot;
use zns_mint::key::{RegistryKeys, TreasuryKeys};
use zns_mint::mint::registry::Registry;
use zns_mint::mint::treasury::memo::RequestMemo;
use zns_mint::mint::signer;
use zns_mint::mint::{
    Name, OperationalState, RequestOutcome, SubmissionKind, TREASURY_ACCOUNT, TX_EXPIRY_BUFFER,
};
use zns_mint::wallet::{NoteLocator, Wallet};
use zns_mint::zcash::{self, CanonicalBlockSource, JsonRpc, SubmitOutcome};

/// Confirmations required before a Treasury intake note is settled.
const INTAKE_CONFIRMATIONS: u32 = 10;

/// Pause between retries of chain I/O (fetch, scan, submit).
const RETRY_PAUSE: Duration = Duration::from_secs(5);

/// One decrypted Name Note candidate from the ZNS pass, with the facts the
/// wallet store and the Registry evidence need.
struct NameNoteCandidate {
    txid: zcash_primitives::transaction::TxId,
    action_index: usize,
    /// The action's index in the block's full Ironwood commitment stream —
    /// fixes the note's tree position.
    ordinal: usize,
    note: orchard::note::Note,
    ephemeral_key: zcash_note_encryption::EphemeralKeyBytes,
    memo: [u8; 512],
    payload: zns_mint::mint::NameNote,
}

// ---------------------------------------------------------------------------
// Free functions — each takes exactly the capabilities it uses; main owns
// every value. The library types (Wallet, Registry, OperationalState) are
// the state machines; this file only sequences them.
// ---------------------------------------------------------------------------

/// Scans and applies blocks from the wallet's applied tip through `target`,
/// retrying transient chain I/O indefinitely.
#[allow(clippy::too_many_arguments)]
async fn catch_up<P: zcash_protocol::consensus::Parameters + Send + 'static>(
    network: &P,
    rpc: &JsonRpc,
    scanning_keys: &ScanningKeys<AccountId, (AccountId, zip32::Scope)>,
    registry_ivk: &orchard::keys::PreparedIncomingViewingKey,
    registry_recipient: orchard::Address,
    wallet: &mut Wallet,
    registry: &mut Registry,
    ops: &mut OperationalState,
    boot_height: zcash_protocol::consensus::BlockHeight,
    target: zcash_protocol::consensus::BlockHeight,
) {
    loop {
        let done = wallet
            .applied_tip_metadata()
            .is_some_and(|tip| tip.block_height() >= target);
        if done {
            return;
        }
        let from = rpc_start_state(rpc, wallet, boot_height).await;
        if let Err(e) = scan_and_apply(
            network,
            rpc,
            scanning_keys,
            registry_ivk,
            registry_recipient,
            wallet,
            registry,
            ops,
            from,
        )
        .await
        {
            tracing::warn!(%e, "scan failed; retrying");
            tokio::time::sleep(RETRY_PAUSE).await;
        }
    }
}

/// The `ChainState` at the wallet's applied tip — `put_blocks`' continuity
/// connection point.
async fn rpc_start_state(
    rpc: &JsonRpc,
    wallet: &Wallet,
    boot_height: zcash_protocol::consensus::BlockHeight,
) -> zcash_client_backend::data_api::chain::ChainState {
    let height = wallet
        .applied_tip_metadata()
        .map(|m| m.block_height())
        .unwrap_or(boot_height);
    loop {
        match rpc.chain_state_at(height).await {
            Ok(state) => return state,
            Err(e) => {
                tracing::warn!(%e, "treestate fetch failed; retrying");
                tokio::time::sleep(RETRY_PAUSE).await;
            }
        }
    }
}

/// Fetches, scans, and applies exactly one block (the next after the
/// wallet's applied tip).
#[allow(clippy::too_many_arguments)]
async fn scan_and_apply<P: zcash_protocol::consensus::Parameters + Send + 'static>(
    network: &P,
    rpc: &JsonRpc,
    scanning_keys: &ScanningKeys<AccountId, (AccountId, zip32::Scope)>,
    registry_ivk: &orchard::keys::PreparedIncomingViewingKey,
    registry_recipient: orchard::Address,
    wallet: &mut Wallet,
    registry: &mut Registry,
    ops: &mut OperationalState,
    from_state: zcash_client_backend::data_api::chain::ChainState,
) -> Result<(), zcash::TransportError> {
    let next_height = zcash_protocol::consensus::BlockHeight::from_u32(
        u32::from(from_state.block_height()) + 1,
    );
    let block = rpc.get_block(network, next_height).await?;

    // ZNS pass first (needs `&block`); the standard pass consumes it.
    let candidates =
        decrypt_name_notes(network, &block, registry_ivk, registry_recipient);

    let prior_metadata = wallet.applied_tip_metadata();
    let (header, batches) = decrypt_block(network, block, scanning_keys);
    let nullifiers = Nullifiers::empty();
    // The published Treasury UA omits a transparent receiver, so no
    // transparent output is ever attributed to a wallet account: the
    // account-resolution closure permanently yields `None`.
    let scanned = scan_block(
        network,
        next_height,
        &header,
        batches,
        scanning_keys,
        &nullifiers,
        prior_metadata.as_ref(),
        |_| {
            Ok::<
                Option<(AccountId, Option<transparent::keys::TransparentKeyScope>)>,
                Infallible,
            >(None)
        },
    )
    .map_err(|_| zcash::TransportError::BadNodeData("scan_block"))?;

    // Registry evidence is judged against the pre-put wallet (its fee-note
    // set evolves per transaction inside `apply_block` itself).
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
    *registry = registry.apply_block(network, wallet, &scanned, &name_notes);

    // The wallet's own record of its Name Notes — before `put_blocks`
    // consumes the `ScannedBlock`.
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

    let confirmed: Vec<_> = scanned.transactions().iter().map(|tx| tx.txid()).collect();
    let height = scanned.height();
    wallet
        .put_blocks(&from_state, vec![scanned])
        .map_err(|_| zcash::TransportError::BadNodeData("put_blocks"))?;
    ops.reconcile(&confirmed, height);
    Ok(())
}

/// Walks applied heights backwards until one matches the node's best chain,
/// then truncates wallet, registry, and operational state to that common
/// ancestor. Spans all state by nature — called directly by main.
async fn rewind<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    rpc: &JsonRpc,
    wallet: &mut Wallet,
    registry: &mut Registry,
    ops: &mut OperationalState,
    boot_height: zcash_protocol::consensus::BlockHeight,
) {
    let mut ancestor = wallet
        .applied_tip_metadata()
        .map(|m| m.block_height())
        .unwrap_or(boot_height);
    while ancestor > zcash_protocol::consensus::BlockHeight::from(0u32) {
        let chain_hash = match rpc.get_block_hash(ancestor).await {
            Ok(hash) => hash,
            Err(e) => {
                tracing::warn!(%e, "ancestor walk fetch failed; retrying");
                tokio::time::sleep(RETRY_PAUSE).await;
                continue;
            }
        };
        if wallet
            .block_metadata_at(ancestor)
            .is_some_and(|m| m.block_hash() == chain_hash)
        {
            break;
        }
        ancestor = zcash_protocol::consensus::BlockHeight::from_u32(u32::from(ancestor) - 1);
    }
    tracing::warn!(ancestor = u32::from(ancestor), "rewinding to ancestor");
    let _ = network;

    match wallet.truncate_to_height(ancestor) {
        Ok(_) => {}
        Err(e) => tracing::error!(?e, "wallet truncation failed"),
    }
    registry.truncate_to_height(ancestor);
    ops.invalidate_after_reorg(registry, wallet, ancestor);
}

/// The settle phase: Treasury intake, then housekeeping. Runs once per
/// observed tip once the restart recovery window has passed.
#[allow(clippy::too_many_arguments)]
async fn settle<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    source: &CanonicalBlockSource,
    wallet: &mut Wallet,
    registry: &mut Registry,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    ops: &mut OperationalState,
) {
    let Some(applied) = wallet.applied_tip_metadata() else {
        return;
    };
    let tip = applied.block_height();
    if !ops.recovery_complete(tip) {
        tracing::info!(until = ?tip, "recovery window active; settlement paused");
        return;
    }
    let target = zcash_protocol::consensus::BlockHeight::from_u32(u32::from(tip) + 1);
    let tip_hash = applied.block_hash();
    let mut excluded = ops.reserved_locators();

    intake_claims(
        network,
        source,
        wallet,
        registry,
        treasury_keys,
        registry_keys,
        ops,
        tip,
        target,
        &tip_hash,
        &mut excluded,
    )
    .await;
    housekeeping(
        network,
        source,
        wallet,
        treasury_keys,
        ops,
        target,
        &tip_hash,
        &mut excluded,
    )
    .await;
}

/// Processes every matured Treasury intake note exactly once.
#[allow(clippy::too_many_arguments)]
async fn intake_claims<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    source: &CanonicalBlockSource,
    wallet: &mut Wallet,
    registry: &mut Registry,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    ops: &mut OperationalState,
    tip: zcash_protocol::consensus::BlockHeight,
    target: zcash_protocol::consensus::BlockHeight,
    tip_hash: &zcash_primitives::block::BlockHash,
    excluded: &mut BTreeSet<NoteLocator>,
) {
    let intake: Vec<_> = wallet
        .ironwood_notes_for(TREASURY_ACCOUNT)
        .filter(|note| {
            note.mined_height.is_some_and(|mined| {
                u32::from(tip).saturating_sub(u32::from(mined)) + 1 >= INTAKE_CONFIRMATIONS
            })
        })
        .collect();
    if intake.is_empty() {
        return;
    }

    for note in intake {
        let locator = NoteLocator::ironwood(TREASURY_ACCOUNT, note.note.rho());
        if ops.intake_seen(locator) {
            continue;
        }
        let memo = match RequestMemo::parse(&note.memo) {
            Ok(memo) => memo,
            Err(_) => {
                // Not a ZNS request memo (or malformed): never revisit.
                ops.mark_intake_seen(locator);
                continue;
            }
        };
        let value = note.note.value().inner();
        let confirmed_height = note.mined_height.expect("filtered on Some");
        let Some(name) = Name::parse(memo.name()) else {
            ops.mark_intake_seen(locator);
            continue;
        };
        // The request's UA validated at the single boundary; invalid UAs end
        // this note's handling (never revisited).
        let Some(ua) = zns_mint::mint::NameNote::parse_ua(network, memo.ua()) else {
            ops.mark_intake_seen(locator);
            continue;
        };
        let ua_string = memo.ua().to_string();

        let outcome = match &memo {
            RequestMemo::Claim { .. } => zns_mint::mint::claim::process_claim(
                network,
                name.clone(),
                &ua_string,
                locator,
                value,
                confirmed_height,
                tip,
                target,
                excluded,
                wallet,
                registry,
                treasury_keys,
                registry_keys,
                ops,
            ),
            // OTP relay request: the controller (the record's bound UA)
            // receives the OTP, the requester's UA rides the memo.
            RequestMemo::Update { otp: None, .. } | RequestMemo::Release { otp: None, .. } => {
                let Some(record) = registry.record(&name) else {
                    continue;
                };
                zns_mint::mint::treasury::relay::process_otp_relay(
                    network,
                    &name,
                    memo.action(),
                    &ua,
                    record.ua.as_ref().expect("relay requires a live controller"),
                    record.commitment,
                    locator,
                    value,
                    tip,
                    target,
                    wallet,
                    treasury_keys,
                    ops,
                )
            }
            // Transition with OTP: update binds to the requested UA,
            // release to the current controller UA.
            RequestMemo::Update { otp: Some(otp), .. }
            | RequestMemo::Release { otp: Some(otp), .. } => {
                let Some(record) = registry.record(&name) else {
                    continue;
                };
                let bound_ua = match memo.action() {
                    zns_mint::mint::Action::Update => ua.clone(),
                    _ => record.ua.clone().expect("live record has a UA"),
                };
                zns_mint::mint::registry::authorize::process_transition(
                    network,
                    name.clone(),
                    memo.action(),
                    bound_ua,
                    otp,
                    record.commitment,
                    tip,
                    target,
                    excluded,
                    wallet,
                    registry,
                    registry_keys,
                    ops,
                )
            }
        };

        match outcome {
            Some(outcome) => {
                finish_outcome(source, ops, outcome, tip, target, tip_hash, excluded).await;
                ops.mark_intake_seen(locator);
            }
            None => {
                // Invalid request, or a lock/challenge is held: never mark
                // processed — the next cycle re-evaluates.
            }
        }
    }
}

/// Broadcasts one assembled outcome and records its submission.
async fn finish_outcome(
    source: &CanonicalBlockSource,
    ops: &mut OperationalState,
    outcome: RequestOutcome,
    tip: zcash_protocol::consensus::BlockHeight,
    target: zcash_protocol::consensus::BlockHeight,
    tip_hash: &zcash_primitives::block::BlockHash,
    excluded: &mut BTreeSet<NoteLocator>,
) {
    let (kind, txid, hex, reserved) = match outcome.result {
        Ok(assembled) => assembled,
        Err(error) => {
            tracing::warn!(?error, kind = ?outcome.name_binding.is_some(), "assembly failed");
            if let Some(lock) = outcome.name_lock {
                ops.release_name(&lock);
            }
            if let Some((key, _)) = outcome.relay_challenge {
                ops.pending_otps.release_challenge(&key);
            }
            return;
        }
    };

    let mut accepted = false;
    match source
        .submit_transaction(&hex, &txid.to_string(), tip, *tip_hash)
        .await
    {
        Ok(SubmitOutcome::Accepted) => {
            accepted = true;
            tracing::info!(%txid, kind = kind.as_str(), "submitted")
        }
        Ok(SubmitOutcome::AlreadyInChain) => {
            accepted = true;
            tracing::info!(%txid, kind = kind.as_str(), "already in chain")
        }
        Ok(other) => {
            // TipChanged / TxIdMismatch / Rejected: the submission record
            // stands regardless — reservations hold until confirmation or
            // expiry, and can never double-spend.
            tracing::warn!(?other, %txid, kind = kind.as_str(), "submit not accepted");
        }
        Err(e) => tracing::warn!(%e, %txid, kind = kind.as_str(), "submit transport error"),
    }

    // A relay's OTP becomes deliverable only once its transaction is
    // definitively accepted for broadcast. The challenge travels with the
    // submission so eviction can discard it later.
    let relay_challenge = outcome
        .relay_challenge
        .as_ref()
        .map(|(key, _)| key.clone());
    if let Some((key, otp)) = outcome.relay_challenge {
        if accepted {
            ops.pending_otps.record_issued(key, &otp, tip);
        } else {
            ops.pending_otps.release_challenge(&key);
        }
    }

    ops.record_submission(
        kind,
        txid,
        reserved,
        outcome.name_binding,
        relay_challenge,
        zcash_protocol::consensus::BlockHeight::from_u32(u32::from(target) + TX_EXPIRY_BUFFER),
        excluded,
    );
}

/// Vault sweep and Registry fee replenishment — both no-op below their
/// thresholds and record their own wallet spend state.
#[allow(clippy::too_many_arguments)]
async fn housekeeping<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    source: &CanonicalBlockSource,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    ops: &mut OperationalState,
    target: zcash_protocol::consensus::BlockHeight,
    tip_hash: &zcash_primitives::block::BlockHash,
    excluded: &mut BTreeSet<NoteLocator>,
) {
    let tip = zcash_protocol::consensus::BlockHeight::from_u32(u32::from(target) - 1);
    match zns_mint::mint::treasury::vault::sweep_to_vault(network, wallet, treasury_keys) {
        Ok(Some(txid)) => {
            broadcast_stored(source, wallet, ops, txid, SubmissionKind::AutoSweep, tip, tip_hash, excluded)
                .await
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(?e, "vault sweep failed"),
    }

    match zns_mint::mint::treasury::replenish::replenish_registry_fees(
        network,
        wallet,
        treasury_keys,
    ) {
        Ok(Some(txid)) => {
            broadcast_stored(source, wallet, ops, txid, SubmissionKind::Replenish, tip, tip_hash, excluded)
                .await
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(?e, "replenish failed"),
    }
}

/// Broadcasts a transaction that the housekeeping path already recorded in
/// the wallet (fetch by txid, serialize, submit, track to expiry).
#[allow(clippy::too_many_arguments)]
async fn broadcast_stored(
    source: &CanonicalBlockSource,
    wallet: &Wallet,
    ops: &mut OperationalState,
    txid: zcash_primitives::transaction::TxId,
    kind: SubmissionKind,
    tip: zcash_protocol::consensus::BlockHeight,
    tip_hash: &zcash_primitives::block::BlockHash,
    excluded: &mut BTreeSet<NoteLocator>,
) {
    let tx = match wallet.get_transaction(txid) {
        Ok(Some(tx)) => tx,
        other => {
            tracing::error!(?other, %txid, "stored transaction missing");
            return;
        }
    };
    let hex = match signer::serialize_tx(&tx) {
        Ok(hex) => hex,
        Err(e) => {
            tracing::error!(?e, %txid, "serialization failed");
            return;
        }
    };
    match source
        .submit_transaction(&hex, &txid.to_string(), tip, *tip_hash)
        .await
    {
        Ok(SubmitOutcome::Accepted) | Ok(SubmitOutcome::AlreadyInChain) => {
            tracing::info!(%txid, kind = kind.as_str(), "submitted")
        }
        other => tracing::warn!(?other, %txid, kind = kind.as_str(), "submit not accepted"),
    }
    ops.record_submission(
        kind,
        txid,
        Vec::new(),
        None,
        None,
        zcash_protocol::consensus::BlockHeight::from_u32(u32::from(tip) + 1 + TX_EXPIRY_BUFFER),
        excluded,
    );
}

/// Post-(re)connect mempool re-baseline: every unconfirmed submission absent
/// from the snapshot is eviction evidence only — it may have been mined in
/// the gap — so each goes through the same on-node verification as an
/// `Invalidated` event before anything is released.
async fn rebaseline_mempool<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    rpc: &JsonRpc,
    wallet: &Wallet,
    ops: &mut OperationalState,
    boot_height: zcash_protocol::consensus::BlockHeight,
) {
    let txids = match rpc.get_raw_mempool().await {
        Ok(txids) => txids,
        Err(e) => {
            tracing::warn!(%e, "mempool re-baseline failed");
            return;
        }
    };
    for txid in ops.unconfirmed_txids() {
        if !txids.contains(&txid) {
            on_evicted(network, rpc, wallet, ops, boot_height, txid).await;
        }
    }
}

/// One of our unconfirmed submissions was reported invalidated (or is absent
/// from a fresh mempool baseline). Establishes death against the node before
/// releasing: a transaction that re-entered the mempool, or was mined in the
/// gap between evidence and check, is alive.
///
/// Residual risk, accepted and logged: a queue-evicted transaction the node
/// still considers valid could in principle be mined later. The outcome is a
/// double-spend race in which exactly one transaction confirms — an
/// availability cost, never a safety violation.
async fn on_evicted<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    rpc: &JsonRpc,
    wallet: &Wallet,
    ops: &mut OperationalState,
    boot_height: zcash_protocol::consensus::BlockHeight,
    txid: zcash_primitives::transaction::TxId,
) {
    let Some(submission) = ops.submissions.get(&txid) else {
        return; // not ours, or already gone
    };
    if submission.confirmed_at.is_some() {
        return; // already reconciled through a block
    }
    let at = wallet
        .applied_tip_metadata()
        .map(|m| m.block_height())
        .unwrap_or(boot_height);
    let branch_id = zcash_protocol::consensus::BranchId::for_height(network, at);

    let present = loop {
        match rpc.get_raw_transaction(branch_id, txid).await {
            Ok(found) => break found.is_some(),
            Err(e) => {
                tracing::warn!(%e, %txid, "eviction verification failed; retrying");
                tokio::time::sleep(RETRY_PAUSE).await;
            }
        }
    };
    if present {
        tracing::debug!(%txid, "invalidation raced re-entry or mining; alive");
        return;
    }

    if let Some(submission) = ops.evict(&txid) {
        tracing::warn!(
            %txid,
            kind = submission.kind.as_str(),
            "submission evicted from mempool; reservations released"
        );
    }
}

/// Trial-decrypts the block's Ironwood actions under the ZNS domain.
///
/// A candidate is exposed only if its memo parses as a Name Note payload and
/// the payload-derived ZNS commitment reproduces the action's actual cmx —
/// the cryptographic authorship check. Value must be zero and the recipient
/// must be the exact Registry address; anything else is not a Name Note.
fn decrypt_name_notes<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    block: &zcash_primitives::block::Block,
    registry_ivk: &orchard::keys::PreparedIncomingViewingKey,
    registry_recipient: orchard::Address,
) -> Vec<NameNoteCandidate> {
    use pasta_curves::group::ff::PrimeField as _;
    use subtle::ConstantTimeEq as _;

    let mut candidates = Vec::new();
    let mut ordinal = 0usize;
    for tx in block.vtx() {
        let Some(bundle) = tx.ironwood_bundle() else {
            continue;
        };
        let zns_capable = bundle.bundle_version() == orchard::bundle::BundleVersion::ironwood_v3()
            && bundle.flags().outputs_enabled();
        for (action_index, action) in bundle.actions().iter().enumerate() {
            if zns_capable {
                if let Some((note, recipient, memo)) =
                    orchard::note_encryption::ZnsIronwoodDomain::for_action(action).try_decrypt(
                        action,
                        registry_ivk,
                        |note, memo, cmx| {
                            let payload =
                                match zns_mint::mint::note::decode_name_note(network, memo) {
                                    Some(p) => p,
                                    None => return subtle::Choice::from(0),
                                };
                            let (rcm, psi) = payload.opening(network);
                            let (g_d, pk_d) = note.recipient().zns_commitment_keys();
                            let rho = Option::from(pasta_curves::pallas::Base::from_repr(
                                note.rho().to_bytes(),
                            ))
                            .expect("valid rho");
                            let computed = match zns_mint::mint::note::note_commitment_cmx(
                                g_d, pk_d, 0, rho, psi, rcm,
                            ) {
                                Some(c) => c,
                                None => return subtle::Choice::from(0),
                            };
                            computed.to_repr().ct_eq(&cmx.to_bytes())
                        },
                    )
                {
                    if note.value() == orchard::value::NoteValue::ZERO
                        && recipient == registry_recipient
                    {
                        let payload = zns_mint::mint::note::decode_name_note(network, &memo)
                            .expect("memo was validated in callback");
                        candidates.push(NameNoteCandidate {
                            txid: tx.txid(),
                            action_index,
                            ordinal,
                            note,
                            // The epk bytes directly — the `ShieldedOutput`
                            // trait method is ambiguous across the three
                            // Ironwood-family domains.
                            ephemeral_key: zcash_note_encryption::EphemeralKeyBytes(
                                action.encrypted_note().epk_bytes,
                            ),
                            memo,
                            payload,
                        });
                    }
                }
            }
            ordinal += 1;
        }
    }
    candidates
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    #[cfg(feature = "dev-regtest")]
    let boot = Boot::run_regtest().await;
    #[cfg(not(feature = "dev-regtest"))]
    let boot = Boot::run().await;

    let boot_height = boot.height();
    let (network, mut chain, wallet, registry, treasury_keys, registry_keys) = boot.into_parts();
    let rpc = JsonRpc::new();
    let source = CanonicalBlockSource::new();

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

    let mut wallet = wallet;
    let mut registry = registry;
    let mut ops = OperationalState::recovering(boot_height);

    tracing::info!(boot = u32::from(boot_height), "run loop starting");

    // Initial catch-up to the node's best tip, retrying transient I/O.
    let (tip_height, _tip_hash) = loop {
        match source.exact_tip().await {
            Ok(tip) => break tip,
            Err(e) => {
                tracing::warn!(%e, "tip fetch failed; retrying");
                tokio::time::sleep(RETRY_PAUSE).await;
            }
        }
    };
    catch_up(
        &network,
        &rpc,
        &scanning_keys,
        &registry_ivk,
        registry_recipient,
        &mut wallet,
        &mut registry,
        &mut ops,
        boot_height,
        tip_height,
    )
    .await;
    settle(
        &network,
        &source,
        &mut wallet,
        &mut registry,
        &treasury_keys,
        &registry_keys,
        &mut ops,
    )
    .await;

    let mut mempool_stream: Option<_> = None;

    loop {
        let stream = match chain.chain_tip_change_stream().await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(%e, "tip stream open failed; reconnecting");
                tokio::time::sleep(RETRY_PAUSE).await;
                continue;
            }
        };
        tokio::pin!(stream);

        use futures_util::StreamExt as _;
        let mut mempool_alive = false;
        loop {
            // The mempool stream is opened lazily on first use and re-opened
            // after every end: each reconnect re-baselines against
            // `getrawmempool` so evictions that happen while the stream is
            // down are still surfaced.
            if !mempool_alive {
                match chain.mempool_events().await {
                    Ok(stream) => {
                        rebaseline_mempool(
                            &network,
                            &rpc,
                            &wallet,
                            &mut ops,
                            boot_height,
                        )
                        .await;
                        mempool_stream = Some(stream);
                        mempool_alive = true;
                    }
                    Err(e) => {
                        tracing::warn!(%e, "mempool stream open failed");
                        tokio::time::sleep(RETRY_PAUSE).await;
                        continue;
                    }
                }
            }
            tokio::select! {
                item = mempool_stream
                    .as_mut()
                    .expect("mempool_alive implies present")
                    .next() => {
                    let item = match item {
                        Some(item) => item,
                        None => {
                            // Stream ended (error or server-side close): drop
                            // it; the top of this loop reconnects and
                            // re-baselines.
                            mempool_alive = false;
                            mempool_stream = None;
                            continue;
                        }
                    };
                    match item {
                        Ok((zebra_indexer_proto::MempoolChangeKind::Invalidated, txid)) => {
                            on_evicted(
                                &network,
                                &rpc,
                                &wallet,
                                &mut ops,
                                boot_height,
                                txid,
                            )
                            .await;
                        }
                        Ok((_kind, txid)) => {
                            // `Mined` is a reorg-sensitive preview of what the
                            // block pipeline authoritatively confirms; `Added`
                            // for a transaction we did not build carries no
                            // decision for this mint.
                            tracing::trace!(%txid, "mempool event (informational)");
                        }
                        Err(e) => {
                            tracing::warn!(%e, "mempool stream error; reconnecting");
                            mempool_alive = false;
                            mempool_stream = None;
                            continue;
                        }
                    }
                }
                message = stream.next() => {
                    let Some(Ok(message)) = message else {
                        tracing::warn!("tip stream ended; reconnecting");
                        break;
                    };
                    let (height, hash) = zcash::tip_height_hash(&message);

                    match wallet.applied_tip_metadata() {
                        Some(applied) if height > applied.block_height() => {
                            catch_up(
                                &network,
                                &rpc,
                                &scanning_keys,
                                &registry_ivk,
                                registry_recipient,
                                &mut wallet,
                                &mut registry,
                                &mut ops,
                                boot_height,
                                height,
                            )
                            .await;
                            settle(
                                &network,
                                &source,
                                &mut wallet,
                                &mut registry,
                                &treasury_keys,
                                &registry_keys,
                                &mut ops,
                            )
                            .await;
                        }
                        Some(applied)
                            if height == applied.block_height()
                                && hash == applied.block_hash() =>
                        {
                            // Duplicate event at our tip — nothing to do.
                        }
                        Some(applied) => {
                            // Shorter tip, or same height under a different
                            // hash: the best chain diverged from our applied
                            // prefix.
                            tracing::warn!(
                                applied = u32::from(applied.block_height()),
                                best = u32::from(height),
                                "reorg detected; rewinding to common ancestor"
                            );
                            rewind(
                                &network,
                                &rpc,
                                &mut wallet,
                                &mut registry,
                                &mut ops,
                                boot_height,
                            )
                            .await;
                            catch_up(
                                &network,
                                &rpc,
                                &scanning_keys,
                                &registry_ivk,
                                registry_recipient,
                                &mut wallet,
                                &mut registry,
                                &mut ops,
                                boot_height,
                                height,
                            )
                            .await;
                            settle(
                                &network,
                                &source,
                                &mut wallet,
                                &mut registry,
                                &treasury_keys,
                                &registry_keys,
                                &mut ops,
                            )
                            .await;
                        }
                        None => {
                            // No block applied yet (fresh boot): catch up from
                            // the seeded origin checkpoint.
                            catch_up(
                                &network,
                                &rpc,
                                &scanning_keys,
                                &registry_ivk,
                                registry_recipient,
                                &mut wallet,
                                &mut registry,
                                &mut ops,
                                boot_height,
                                height,
                            )
                            .await;
                            settle(
                                &network,
                                &source,
                                &mut wallet,
                                &mut registry,
                                &treasury_keys,
                                &registry_keys,
                                &mut ops,
                            )
                            .await;
                        }
                    }
                }
            }
        }
    }
}
