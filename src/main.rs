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
use zns_mint::mint::otp::ChallengeKey;
use zns_mint::mint::registry::Registry;
use zns_mint::mint::treasury::memo::RequestMemo;
use zns_mint::mint::v6;
use zns_mint::mint::{
    Name, OperationalState, RequestOutcome, SubmissionKind, TREASURY_ACCOUNT, TX_EXPIRY_BUFFER,
};
use zns_mint::wallet::{NoteLocator, Wallet};
use zns_mint::zcash::{self, CanonicalBlockSource, ChainClient, JsonRpc, SubmitOutcome};

/// Confirmations required before a Treasury intake note is settled.
const INTAKE_CONFIRMATIONS: u32 = 10;

/// Pause between retries of chain I/O (fetch, scan, submit).
const RETRY_PAUSE: Duration = Duration::from_secs(5);

/// Evidence from the mempool watcher.
enum MempoolEvent {
    /// The node invalidated a transaction.
    Invalidated(zcash_primitives::transaction::TxId),
    /// The watcher (re)connected; `txids` is the post-connect mempool
    /// baseline. A pending submission absent from it is eviction evidence
    /// only — it may have been mined in the gap — so the handler verifies
    /// against the node before releasing anything.
    Rebaselined(Vec<zcash_primitives::transaction::TxId>),
}

/// The mempool watcher: a dedicated task translating Zebra's mempool
/// lifecycle stream into compact evidence for the run loop.
///
/// Only `Invalidated` is reported: `Mined` is a reorg-sensitive preview of
/// what the block pipeline will authoritatively confirm, and `Added` for a
/// transaction we did not build carries no decision for this mint. After
/// every (re)connect the watcher re-baselines and reports the snapshot, so
/// evictions that happen during a disconnect are still surfaced.
async fn mempool_watcher(
    mut chain: ChainClient,
    rpc: JsonRpc,
    events: tokio::sync::mpsc::Sender<MempoolEvent>,
) {
    use futures_util::StreamExt as _;
    use zebra_indexer_proto::MempoolChangeKind;

    loop {
        let stream = match chain.mempool_events().await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(%e, "mempool stream open failed; retrying");
                tokio::time::sleep(RETRY_PAUSE).await;
                continue;
            }
        };
        tokio::pin!(stream);

        while let Some(item) = stream.next().await {
            match item {
                Ok((MempoolChangeKind::Invalidated, txid)) => {
                    if events.send(MempoolEvent::Invalidated(txid)).await.is_err() {
                        return; // run loop gone; nothing to watch for
                    }
                }
                Ok((_kind, txid)) => {
                    tracing::trace!(%txid, "mempool event (informational)")
                }
                Err(e) => {
                    tracing::warn!(%e, "mempool stream error; reconnecting");
                    break;
                }
            }
        }

        // Reconnected (or first connect): re-baseline and report the
        // snapshot so the run loop can re-verify its pending set.
        tokio::time::sleep(RETRY_PAUSE).await;
        match rpc.get_raw_mempool().await {
            Ok(txids) => {
                let _ = events.send(MempoolEvent::Rebaselined(txids)).await;
            }
            Err(e) => tracing::warn!(%e, "mempool re-baseline failed"),
        }
    }
}

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
    payload: zns_mint::mint::note::NameNotePayload,
}

struct RunLoop<P: zcash_protocol::consensus::Parameters> {
    network: P,
    chain: ChainClient,
    rpc: JsonRpc,
    source: CanonicalBlockSource,
    wallet: Wallet,
    registry: Registry,
    treasury_keys: TreasuryKeys,
    registry_keys: RegistryKeys,
    /// (prepared registry IVK, exact registry recipient) for the ZNS pass.
    registry_ivk: orchard::keys::PreparedIncomingViewingKey,
    registry_recipient: orchard::Address,
    scanning_keys: ScanningKeys<AccountId, (AccountId, zip32::Scope)>,
    ops: OperationalState,
    /// The boot origin-checkpoint height — the recovery baseline and the
    /// pre-first-block starting point.
    boot_height: zcash_protocol::consensus::BlockHeight,
    /// Intake notes already definitively handled (by locator).
    processed: BTreeSet<NoteLocator>,
    seen_claims: BTreeSet<Name>,
    seen_no_otp: BTreeSet<ChallengeKey>,
    seen_with_otp: BTreeSet<ChallengeKey>,
}

impl<P: zcash_protocol::consensus::Parameters + Send + 'static> RunLoop<P> {
    async fn run(mut self) -> ! {
        // Initial catch-up to the node's best tip, retrying transient I/O.
        let (tip_height, _tip_hash) = loop {
            match self.source.exact_tip().await {
                Ok(tip) => break tip,
                Err(e) => {
                    tracing::warn!(%e, "tip fetch failed; retrying");
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
            }
        };
        self.catch_up(tip_height).await;
        self.settle().await;

        let mut mempool_rx = self.spawn_mempool_watcher();

        loop {
            let stream = match self.chain.chain_tip_change_stream().await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::warn!(%e, "tip stream open failed; reconnecting");
                    tokio::time::sleep(RETRY_PAUSE).await;
                    continue;
                }
            };
            tokio::pin!(stream);

            use futures_util::StreamExt as _;
            loop {
                tokio::select! {
                    event = mempool_rx.recv() => {
                        match event {
                            Some(event) => self.on_mempool_event(event).await,
                            None => {
                                // The watcher never exits by design; a closed
                                // channel means it panicked — respawn it.
                                tracing::error!("mempool watcher died; respawning");
                                mempool_rx = self.spawn_mempool_watcher();
                            }
                        }
                    }
                    message = stream.next() => {
                        let Some(Ok(message)) = message else {
                            tracing::warn!("tip stream ended; reconnecting");
                            break;
                        };
                        let (height, hash) = zcash::tip_height_hash(&message);

                        match self.wallet.applied_tip_metadata() {
                            Some(applied) if height > applied.block_height() => {
                                self.catch_up(height).await;
                                self.settle().await;
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
                                self.rewind().await;
                                self.catch_up(height).await;
                                self.settle().await;
                            }
                            None => {
                                // No block applied yet (fresh boot): catch up
                                // from the seeded origin checkpoint.
                                self.catch_up(height).await;
                                self.settle().await;
                            }
                        }
                    }
                }
            }
        }
    }

    fn spawn_mempool_watcher(&self) -> tokio::sync::mpsc::Receiver<MempoolEvent> {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(mempool_watcher(self.chain.clone(), JsonRpc::new(), tx));
        rx
    }

    /// Mempool evidence: eviction candidates are verified against the node
    /// (mempool + chain) before anything is released.
    async fn on_mempool_event(&mut self, event: MempoolEvent) {
        match event {
            MempoolEvent::Invalidated(txid) => self.on_evicted(txid).await,
            MempoolEvent::Rebaselined(present) => {
                for txid in self.ops.unconfirmed_txids() {
                    if !present.contains(&txid) {
                        self.on_evicted(txid).await;
                    }
                }
            }
        }
    }

    /// One of our unconfirmed submissions was reported invalidated (or is
    /// absent from a fresh mempool baseline). Establishes death against the
    /// node before releasing: a transaction that re-entered the mempool, or
    /// was mined in the gap between evidence and check, is alive.
    ///
    /// Residual risk, accepted and logged: a queue-evicted transaction the
    /// node still considers valid could in principle be mined later. The
    /// outcome is a double-spend race in which exactly one transaction
    /// confirms — an availability cost, never a safety violation.
    async fn on_evicted(&mut self, txid: zcash_primitives::transaction::TxId) {
        let Some(submission) = self.ops.submissions.get(&txid) else {
            return; // not ours, or already gone
        };
        if submission.confirmed_at.is_some() {
            return; // already reconciled through a block
        }
        let at = self
            .wallet
            .applied_tip_metadata()
            .map(|m| m.block_height())
            .unwrap_or(self.boot_height);
        let branch_id =
            zcash_protocol::consensus::BranchId::for_height(&self.network, at);

        let present = loop {
            match self.rpc.get_raw_transaction(branch_id, txid).await {
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

        if let Some(submission) = self.ops.evict(&txid) {
            tracing::warn!(
                %txid,
                kind = submission.kind.as_str(),
                "submission evicted from mempool; reservations released"
            );
        }
    }

    /// Scans and applies blocks from the wallet's applied tip through
    /// `target`, retrying transient chain I/O indefinitely.
    async fn catch_up(&mut self, target: zcash_protocol::consensus::BlockHeight) {
        loop {
            let Some(applied) = self.wallet.applied_tip_metadata() else {
                // Fresh boot: the wallet is seeded at the origin checkpoint but
                // has applied no block yet. Start from the checkpoint height.
                let from = self.rpc_start_state().await;
                match self.scan_and_apply(from).await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(%e, "scan failed; retrying");
                        tokio::time::sleep(RETRY_PAUSE).await;
                    }
                }
                if self
                    .wallet
                    .applied_tip_metadata()
                    .is_some_and(|tip| tip.block_height() >= target)
                {
                    return;
                }
                continue;
            };
            if applied.block_height() >= target {
                return;
            }
            let from = self.rpc_start_state().await;
            match self.scan_and_apply(from).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(%e, "scan failed; retrying");
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
            }
        }
    }

    /// The `ChainState` at the wallet's applied tip — `put_blocks`' continuity
    /// connection point.
    async fn rpc_start_state(&self) -> zcash_client_backend::data_api::chain::ChainState {
        let height = self
            .wallet
            .applied_tip_metadata()
            .map(|m| m.block_height())
            .unwrap_or_else(|| self.ops_boot_height());
        loop {
            match self.rpc.chain_state_at(height).await {
                Ok(state) => return state,
                Err(e) => {
                    tracing::warn!(%e, "treestate fetch failed; retrying");
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
            }
        }
    }

    /// Height of the boot origin checkpoint, recorded as the recovery
    /// baseline before any block is applied.
    fn ops_boot_height(&self) -> zcash_protocol::consensus::BlockHeight {
        // `OperationalState::recovering` was seeded with this height; before
        // the first applied block it is the only height the mint knows.
        self.boot_height
    }

    /// Fetches, scans, and applies exactly one block (the next after the
    /// wallet's applied tip).
    async fn scan_and_apply(
        &mut self,
        from_state: zcash_client_backend::data_api::chain::ChainState,
    ) -> Result<(), zcash::TransportError> {
        let next_height = zcash_protocol::consensus::BlockHeight::from_u32(
            u32::from(from_state.block_height()) + 1,
        );
        let block = self.rpc.get_block(&self.network, next_height).await?;

        // ZNS pass first (needs `&block`); the standard pass consumes it.
        let candidates = decrypt_name_notes(&block, &self.registry_ivk, self.registry_recipient);

        let prior_metadata = self.wallet.applied_tip_metadata();
        let (header, batches) = decrypt_block(&self.network, block, &self.scanning_keys);
        let nullifiers = Nullifiers::empty();
        // The published Treasury UA omits a transparent receiver, so no
        // transparent output is ever attributed to a wallet account: the
        // account-resolution closure permanently yields `None`.
        let scanned =
            scan_block(
                &self.network,
                next_height,
                &header,
                batches,
                &self.scanning_keys,
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
        self.registry = self
            .registry
            .apply_block(&self.wallet, &scanned, &name_notes);

        // The wallet's own record of its Name Notes — before `put_blocks`
        // consumes the `ScannedBlock`.
        for candidate in &candidates {
            if self
                .wallet
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
        self.wallet
            .put_blocks(&from_state, vec![scanned])
            .map_err(|_| zcash::TransportError::BadNodeData("put_blocks"))?;
        self.ops.reconcile(&confirmed, height);
        Ok(())
    }

    /// Walks applied heights backwards until one matches the node's best
    /// chain, then truncates wallet, registry, and operational state to that
    /// common ancestor.
    async fn rewind(&mut self) {
        let mut ancestor = self
            .wallet
            .applied_tip_metadata()
            .map(|m| m.block_height())
            .unwrap_or_else(|| self.ops_boot_height());
        while ancestor > zcash_protocol::consensus::BlockHeight::from(0u32) {
            let chain_hash = match self.rpc.get_block_hash(ancestor).await {
                Ok(hash) => hash,
                Err(e) => {
                    tracing::warn!(%e, "ancestor walk fetch failed; retrying");
                    tokio::time::sleep(RETRY_PAUSE).await;
                    continue;
                }
            };
            if self
                .wallet
                .block_metadata_at(ancestor)
                .is_some_and(|m| m.block_hash() == chain_hash)
            {
                break;
            }
            ancestor = zcash_protocol::consensus::BlockHeight::from_u32(u32::from(ancestor) - 1);
        }
        tracing::warn!(ancestor = u32::from(ancestor), "rewinding to ancestor");

        match self.wallet.truncate_to_height(ancestor) {
            Ok(_) => {}
            Err(e) => tracing::error!(?e, "wallet truncation failed"),
        }
        self.registry.truncate_to_height(ancestor);
        self.ops
            .invalidate_after_reorg(&self.registry, &self.wallet, ancestor);
    }

    /// The settle phase: Treasury intake, then housekeeping. Runs once per
    /// observed tip once the restart recovery window has passed.
    async fn settle(&mut self) {
        let Some(applied) = self.wallet.applied_tip_metadata() else {
            return;
        };
        let tip = applied.block_height();
        if !self.ops.recovery_complete(tip) {
            tracing::info!(until = ?tip, "recovery window active; settlement paused");
            return;
        }
        let target = zcash_protocol::consensus::BlockHeight::from_u32(u32::from(tip) + 1);
        let tip_hash = applied.block_hash();
        let mut excluded = self.ops.reserved_locators();

        self.intake_claims(tip, target, &tip_hash, &mut excluded)
            .await;
        self.housekeeping(target, &tip_hash, &mut excluded).await;
    }

    /// Processes every matured Treasury intake note exactly once.
    async fn intake_claims(
        &mut self,
        tip: zcash_protocol::consensus::BlockHeight,
        target: zcash_protocol::consensus::BlockHeight,
        tip_hash: &zcash_primitives::block::BlockHash,
        excluded: &mut BTreeSet<NoteLocator>,
    ) {
        let intake: Vec<_> = self
            .wallet
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
            if self.processed.contains(&locator) {
                continue;
            }
            let memo = match RequestMemo::parse(&note.memo) {
                Ok(memo) => memo,
                Err(_) => {
                    // Not a ZNS request memo (or malformed): never revisit.
                    self.processed.insert(locator);
                    continue;
                }
            };
            let value = note.note.value().inner();
            let confirmed_height = note.mined_height.expect("filtered on Some");
            // `RequestMemo::parse` validated the name grammar; the mint's own
            // `Name` type is canonical for everything downstream.
            let Some(name) = Name::parse(memo.name()) else {
                self.processed.insert(locator);
                continue;
            };
            let ua = memo.ua().to_string();

            let outcome = match &memo {
                RequestMemo::Claim { .. } => zns_mint::mint::claim::process_claim(
                    &self.network,
                    name.clone(),
                    &ua,
                    locator,
                    value,
                    confirmed_height,
                    tip,
                    target,
                    excluded,
                    &mut self.wallet,
                    &self.registry,
                    &self.treasury_keys,
                    &self.registry_keys,
                    &mut self.ops,
                    &mut self.seen_claims,
                ),
                // OTP relay request: the controller (the record's bound UA)
                // receives the OTP, the requester's UA rides the memo.
                RequestMemo::Update { otp: None, .. } | RequestMemo::Release { otp: None, .. } => {
                    let Some(record) = self.registry.record(&name) else {
                        continue;
                    };
                    zns_mint::mint::treasury::relay::process_otp_relay(
                        &self.network,
                        &name,
                        memo.action(),
                        &zns_mint::mint::UnifiedAddress::from_string(ua),
                        &record.ua.clone(),
                        record.commitment,
                        locator,
                        value,
                        tip,
                        target,
                        &mut self.wallet,
                        &self.treasury_keys,
                        &mut self.ops,
                        &mut self.seen_no_otp,
                    )
                }
                // Transition with OTP: update binds to the requested UA,
                // release to the current controller UA.
                RequestMemo::Update { otp: Some(otp), .. }
                | RequestMemo::Release { otp: Some(otp), .. } => {
                    let Some(record) = self.registry.record(&name) else {
                        continue;
                    };
                    let bound_ua = match memo.action() {
                        zns_mint::mint::Action::Update => {
                            zns_mint::mint::UnifiedAddress::from_string(ua)
                        }
                        _ => record.ua.clone(),
                    };
                    zns_mint::mint::registry::authorize::process_transition(
                        &self.network,
                        name.clone(),
                        memo.action(),
                        bound_ua,
                        otp,
                        record.commitment,
                        tip,
                        target,
                        excluded,
                        &mut self.wallet,
                        &self.registry,
                        &self.registry_keys,
                        &mut self.ops,
                        &mut self.seen_with_otp,
                    )
                }
            };

            match outcome {
                Some(outcome) => {
                    self.finish_outcome(outcome, tip, target, tip_hash, excluded)
                        .await;
                    self.processed.insert(locator);
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
        &mut self,
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
                    self.ops.release_name(&lock);
                }
                if let Some((key, _)) = outcome.relay_challenge {
                    self.ops.pending_otps.release_challenge(&key);
                }
                return;
            }
        };

        let mut accepted = false;
        match self
            .source
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
                self.ops.pending_otps.record_issued(key, &otp, tip);
            } else {
                self.ops.pending_otps.release_challenge(&key);
            }
        }

        self.ops.record_submission(
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
    async fn housekeeping(
        &mut self,
        target: zcash_protocol::consensus::BlockHeight,
        tip_hash: &zcash_primitives::block::BlockHash,
        excluded: &mut BTreeSet<NoteLocator>,
    ) {
        let tip = zcash_protocol::consensus::BlockHeight::from_u32(u32::from(target) - 1);
        match zns_mint::mint::treasury::vault::sweep_to_vault(
            &self.network,
            &mut self.wallet,
            &self.treasury_keys,
        ) {
            Ok(Some(txid)) => {
                self.broadcast_stored(txid, SubmissionKind::AutoSweep, tip, tip_hash, excluded)
                    .await
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(?e, "vault sweep failed"),
        }

        match zns_mint::mint::treasury::replenish::replenish_registry_fees(
            &self.network,
            &mut self.wallet,
            &self.treasury_keys,
        ) {
            Ok(Some(txid)) => {
                self.broadcast_stored(txid, SubmissionKind::Replenish, tip, tip_hash, excluded)
                    .await
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(?e, "replenish failed"),
        }
    }

    /// Broadcasts a transaction that the housekeeping path already recorded in
    /// the wallet (fetch by txid, serialize, submit, track to expiry).
    async fn broadcast_stored(
        &mut self,
        txid: zcash_primitives::transaction::TxId,
        kind: SubmissionKind,
        tip: zcash_protocol::consensus::BlockHeight,
        tip_hash: &zcash_primitives::block::BlockHash,
        excluded: &mut BTreeSet<NoteLocator>,
    ) {
        let tx = match self.wallet.get_transaction(txid) {
            Ok(Some(tx)) => tx,
            other => {
                tracing::error!(?other, %txid, "stored transaction missing");
                return;
            }
        };
        let hex = match v6::serialize_tx(&tx) {
            Ok(hex) => hex,
            Err(e) => {
                tracing::error!(?e, %txid, "serialization failed");
                return;
            }
        };
        match self
            .source
            .submit_transaction(&hex, &txid.to_string(), tip, *tip_hash)
            .await
        {
            Ok(SubmitOutcome::Accepted) | Ok(SubmitOutcome::AlreadyInChain) => {
                tracing::info!(%txid, kind = kind.as_str(), "submitted")
            }
            other => tracing::warn!(?other, %txid, kind = kind.as_str(), "submit not accepted"),
        }
        self.ops.record_submission(
            kind,
            txid,
            Vec::new(),
            None,
            None,
            zcash_protocol::consensus::BlockHeight::from_u32(u32::from(tip) + 1 + TX_EXPIRY_BUFFER),
            excluded,
        );
    }
}

/// Trial-decrypts the block's Ironwood actions under the ZNS domain.
///
/// A candidate is exposed only if its memo parses as a Name Note payload and
/// the payload-derived ZNS commitment reproduces the action's actual cmx —
/// the cryptographic authorship check. Value must be zero and the recipient
/// must be the exact Registry address; anything else is not a Name Note.
fn decrypt_name_notes(
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
                            let payload = match zns_mint::mint::note::decode_name_note_payload(memo)
                            {
                                Some(p) => p,
                                None => return subtle::Choice::from(0),
                            };
                            let (rcm, psi) = payload.opening();
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
                        let payload = zns_mint::mint::note::decode_name_note_payload(&memo)
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
    let (network, chain, wallet, registry, treasury_keys, registry_keys) = boot.into_parts();

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

    RunLoop {
        network,
        chain,
        rpc: JsonRpc::new(),
        source: CanonicalBlockSource::new(),
        wallet,
        registry,
        treasury_keys,
        registry_keys,
        registry_ivk,
        registry_recipient,
        scanning_keys,
        ops: OperationalState::recovering(boot_height),
        processed: BTreeSet::new(),
        seen_claims: BTreeSet::new(),
        seen_no_otp: BTreeSet::new(),
        seen_with_otp: BTreeSet::new(),
        boot_height,
    }
    .run()
    .await;
}
