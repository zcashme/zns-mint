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
//! The Mint listens to a co-located Zebra indexer for chain-tip and
//! mempool changes, and polls for missed tips because the indexer
//! chain-tip stream is change-only and emits no current tip on connect.
//! Each new best-chain tip advances the wallet and registry forward
//! block-by-block, scanning Name Notes with the published registry key,
//! applying them to the on-chain registry, and reconciling pending
//! submissions against confirmed transactions; reorgs are rolled back to the
//! common ancestor before the chain catches up again.
//!
//! After catch-up, matured request Name Notes are settled exactly once:
//! claim requests create new registrations, update and release requests
//! complete their OTP authorization, lifecycle releases enforce
//! expiration and liveness, and the resulting reply transactions are
//! built, signed, and broadcast through the Zebra node. Housekeeping
//! then sweeps Treasury funds to the vault and replenishes the fee-note
//! pool. Mempool eviction events are verified against the node before any
//! name lock, note reservation, or pending OTP challenge is released.
//!
//! State is held by `Wallet`, `Registry`, and `MintState`; this entry
//! point only sequences their calls.

use std::convert::Infallible;
use std::time::Duration;

use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::WalletWrite as _;
use zcash_client_backend::scanning::Nullifiers;
use zcash_client_backend::scanning::ScanningKeys;
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zip32::AccountId;

use zns_mint::boot::Boot;
use zns_mint::mint::treasury::memo::RequestMemo;
use zns_mint::mint::{decrypt_name_notes, signer};
use zns_mint::mint::{
    Name, NameNote, MintState, SubmissionKind, TREASURY_ACCOUNT,
    TX_EXPIRY_BUFFER,
};
use zns_mint::wallet::NoteLocator;
use zns_mint::zcash::{self, CanonicalBlockSource, JsonRpc, SubmitOutcome};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    // ── Setup ────────────────────────────────────────────────────────────
    #[cfg(feature = "regtest")]
    let boot = Boot::run_regtest().await;
    #[cfg(not(feature = "regtest"))]
    let boot = Boot::run().await;

    let boot_height = boot.height();
    let (network, mut chain, wallet, registry, treasury_keys, registry_keys) = boot.into_parts();
    let rpc = JsonRpc::new();
    let source = CanonicalBlockSource::new();

    let mut wallet = wallet;
    let mut registry = registry;
    let mut mint = MintState::recovering(boot_height);

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

    // Mempool eviction candidates: `Invalidated` events and post-reconnect
    // baseline absences queue here and drain through one verification site.
    let mut eviction_candidates: Vec<zcash_primitives::transaction::TxId> = Vec::new();
    let mut mempool_stream: Option<_> = None;

    'outer: loop {
        let stream = match chain.chain_tip_change_stream().await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(%e, "tip stream open failed; reconnecting");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue 'outer;
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
                    Ok(new_stream) => {
                        match rpc.get_raw_mempool().await {
                            Ok(present) => {
                                for txid in mint.unconfirmed_txids() {
                                    if !present.contains(&txid) {
                                        eviction_candidates.push(txid);
                                    }
                                }
                            }
                            Err(e) => tracing::warn!(%e, "mempool re-baseline failed"),
                        }
                        mempool_stream = Some(new_stream);
                        mempool_alive = true;
                    }
                    Err(e) => {
                        tracing::warn!(%e, "mempool stream open failed");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                }
            }

            // Drain: establish each candidate's death against the node before
            // releasing anything — a transaction that re-entered the mempool,
            // or was mined in the gap between evidence and check, is alive.
            while let Some(txid) = eviction_candidates.pop() {
                let Some(submission) = mint.submissions.get(&txid) else {
                    continue; // not ours, or already gone
                };
                if submission.confirmed_at.is_some() {
                    continue; // already reconciled through a block
                }
                let at = wallet
                    .applied_tip_metadata()
                    .map(|m| m.block_height())
                    .unwrap_or(boot_height);
                let branch_id =
                    zcash_protocol::consensus::BranchId::for_height(&network, at);
                let present = loop {
                    match rpc.get_raw_transaction(branch_id, txid).await {
                        Ok(found) => break found.is_some(),
                        Err(e) => {
                            tracing::warn!(%e, %txid, "eviction verification failed; retrying");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                };
                if present {
                    tracing::debug!(%txid, "invalidation raced re-entry or mining; alive");
                    continue;
                }
                // Residual risk, accepted: a queue-evicted transaction the
                // node still considers valid could later be mined — a
                // double-spend race with exactly one winner. Availability,
                // never safety.
                if let Some(submission) = mint.evict(&txid) {
                    tracing::warn!(
                        %txid,
                        kind = submission.kind.as_str(),
                        "submission evicted from mempool; reservations released"
                    );
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
                            mempool_alive = false;
                            mempool_stream = None;
                            continue;
                        }
                    };
                    match item {
                        Ok((zebra_indexer_proto::MempoolChangeKind::Invalidated, txid)) => {
                            eviction_candidates.push(txid);
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
                        continue 'outer;
                    };
                    let (height, hash) = zcash::tip_height_hash(&message);

                    match wallet.applied_tip_metadata() {
                        // Duplicate event at our tip — nothing to do.
                        Some(applied)
                            if height == applied.block_height()
                                && hash == applied.block_hash() => {}
                        // Shorter tip, or same height under a different hash:
                        // the best chain diverged from our applied prefix.
                        // Walk applied heights backwards until one matches the
                        // node's best chain, then truncate everything to that
                        // common ancestor — this spans all state by nature.
                        Some(applied) if height <= applied.block_height() => {
                            tracing::warn!(
                                applied = u32::from(applied.block_height()),
                                best = u32::from(height),
                                "reorg detected; rewinding to common ancestor"
                            );
                            let mut ancestor = wallet
                                .applied_tip_metadata()
                                .map(|m| m.block_height())
                                .unwrap_or(boot_height);
                            while ancestor > zcash_protocol::consensus::BlockHeight::from(0u32) {
                                let chain_hash = match rpc.get_block_hash(ancestor).await {
                                    Ok(hash) => hash,
                                    Err(e) => {
                                        tracing::warn!(%e, "ancestor walk fetch failed; retrying");
                                        tokio::time::sleep(Duration::from_secs(5)).await;
                                        continue;
                                    }
                                };
                                if wallet
                                    .block_metadata_at(ancestor)
                                    .is_some_and(|m| m.block_hash() == chain_hash)
                                {
                                    break;
                                }
                                ancestor = zcash_protocol::consensus::BlockHeight::from_u32(
                                    u32::from(ancestor) - 1,
                                );
                            }
                            tracing::warn!(ancestor = u32::from(ancestor), "rewinding to ancestor");
                            match wallet.truncate_to_height(ancestor) {
                                Ok(_) => {}
                                Err(e) => tracing::error!(?e, "wallet truncation failed"),
                            }
                            registry.truncate_to_height(ancestor);
                            mint.invalidate_after_reorg(&registry, &wallet, ancestor);
                        }
                        // Advance (taller tip, or fresh boot with nothing
                        // applied yet).
                        _ => {}
                    }

                    // Catch up: apply blocks one at a time from the wallet's
                    // applied tip through `height`, retrying transient I/O
                    // indefinitely.
                    loop {
                        let done = wallet
                            .applied_tip_metadata()
                            .is_some_and(|tip| tip.block_height() >= height);
                        if done {
                            break;
                        }
                        // The `ChainState` at the wallet's applied tip —
                        // `put_blocks`' continuity connection point.
                        let from_height = wallet
                            .applied_tip_metadata()
                            .map(|m| m.block_height())
                            .unwrap_or(boot_height);
                        let from_state = loop {
                            match rpc.chain_state_at(from_height).await {
                                Ok(state) => break state,
                                Err(e) => {
                                    tracing::warn!(%e, "treestate fetch failed; retrying");
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                }
                            }
                        };
                        let next_height = zcash_protocol::consensus::BlockHeight::from_u32(
                            u32::from(from_state.block_height()) + 1,
                        );
                        match rpc.get_block(&network, next_height).await {
                            Ok(block) => {
                                // ZNS pass first (needs `&block`); the
                                // standard pass consumes it.
                                let candidates = decrypt_name_notes(
                                    &network,
                                    &block,
                                    &registry_ivk,
                                    registry_recipient,
                                );

                                let prior_metadata = wallet.applied_tip_metadata();
                                let (header, batches) =
                                    decrypt_block(&network, block, &scanning_keys);
                                let nullifiers = Nullifiers::empty();
                                // The published Treasury UA omits a
                                // transparent receiver, so no transparent
                                // output is ever attributed to a wallet
                                // account: the closure permanently yields
                                // `None`.
                                let scanned = match scan_block(
                                    &network,
                                    next_height,
                                    &header,
                                    batches,
                                    &scanning_keys,
                                    &nullifiers,
                                    prior_metadata.as_ref(),
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
                                        tokio::time::sleep(Duration::from_secs(5)).await;
                                        continue;
                                    }
                                };

                                // Registry evidence is judged against the
                                // pre-put wallet (its fee-note set evolves per
                                // transaction inside `apply_block` itself).
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
                                registry = registry.apply_block(
                                    &network,
                                    &wallet,
                                    &scanned,
                                    &name_notes,
                                );

                                // The wallet's own record of its Name Notes —
                                // before `put_blocks` consumes the
                                // `ScannedBlock`.
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

                                let confirmed: Vec<_> = scanned
                                    .transactions()
                                    .iter()
                                    .map(|tx| tx.txid())
                                    .collect();
                                let scanned_height = scanned.height();
                                match wallet.put_blocks(&from_state, vec![scanned]) {
                                    Ok(()) => mint.reconcile(&confirmed, scanned_height),
                                    Err(e) => tracing::error!(?e, "put_blocks failed"),
                                }
                            }
                            Err(e) => {
                                tracing::warn!(%e, "block fetch failed; retrying");
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                    }

                    // Settle: Treasury intake, then housekeeping — once per
                    // observed tip, after the restart recovery window.
                    if let Some(applied) = wallet.applied_tip_metadata() {
                        let tip = applied.block_height();
                        if !mint.recovery_complete(tip) {
                            tracing::info!(until = ?tip, "recovery window active; settlement paused");
                        } else {
                            let target = zcash_protocol::consensus::BlockHeight::from_u32(
                                u32::from(tip) + 1,
                            );
                            let tip_hash = applied.block_hash();
                            let mut excluded = mint.reserved_locators();

                            // Intake: every confirmed Treasury request note,
                            // exactly once. No maturity wait — claims mint
                            // immediately, and other request types are gated
                            // by witness/anchor availability in their builders.
                            let intake: Vec<_> = wallet
                                .ironwood_notes_for(TREASURY_ACCOUNT)
                                .filter(|note| note.mined_height.is_some())
                                .collect();
                            for note in intake {
                                let locator =
                                    NoteLocator::ironwood(TREASURY_ACCOUNT, note.note.rho());
                                if mint.intake_seen(locator) {
                                    continue;
                                }
                                let memo = match RequestMemo::parse(&note.memo) {
                                    Ok(memo) => memo,
                                    Err(_) => {
                                        // Not a ZNS request memo (or
                                        // malformed): never revisit.
                                        mint.mark_intake_seen(locator);
                                        continue;
                                    }
                                };
                                let value = note.note.value().inner();
                                let confirmed_height =
                                    note.mined_height.expect("filtered on Some");
                                let Some(name) = Name::parse(memo.name()) else {
                                    mint.mark_intake_seen(locator);
                                    continue;
                                };
                                // The request's UA validated at the single
                                // boundary; invalid UAs end this note's
                                // handling (never revisited).
                                let Some(ua) = NameNote::parse_ua(&network, memo.ua()) else {
                                    mint.mark_intake_seen(locator);
                                    continue;
                                };
                                let ua_string = memo.ua().to_string();

                                let outcome = match &memo {
                                    RequestMemo::Claim { .. } => {
                                        zns_mint::mint::claim::process_claim(
                                            &network,
                                            name.clone(),
                                            &ua_string,
                                            value,
                                            confirmed_height,
                                            tip,
                                            target,
                                            &mut excluded,
                                            &mut wallet,
                                            &registry,
                                            &registry_keys,
                                            &mut mint,
                                        )
                                    }
                                    // OTP relay request: the controller (the
                                    // record's bound UA) receives the OTP, the
                                    // requester's UA rides the memo.
                                    RequestMemo::Update { otp: None, .. }
                                    | RequestMemo::Release { otp: None, .. } => {
                                        let Some(record) = registry.record(&name) else {
                                            continue;
                                        };
                                        zns_mint::mint::treasury::relay::process_otp_relay(
                                            &network,
                                            &name,
                                            memo.action(),
                                            &ua,
                                            record.ua.as_ref().expect(
                                                "relay requires a live controller",
                                            ),
                                            record.commitment,
                                            locator,
                                            value,
                                            tip,
                                            target,
                                            &mut wallet,
                                            &treasury_keys,
                                            &mut mint,
                                        )
                                    }
                                    // Transition with OTP: update binds to the
                                    // requested UA, release to the current
                                    // controller UA.
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
                                            &network,
                                            name.clone(),
                                            memo.action(),
                                            bound_ua,
                                            otp,
                                            record.commitment,
                                            tip,
                                            target,
                                            &mut excluded,
                                            &mut wallet,
                                            &registry,
                                            &registry_keys,
                                            &mut mint,
                                        )
                                    }
                                };

                                if let Some(outcome) = outcome {
                                    // Broadcast and record the submission.
                                    match outcome.result {
                                        Ok((kind, txid, hex, reserved)) => {
                                            let mut accepted = false;
                                            match source
                                                .submit_transaction(
                                                    &hex,
                                                    &txid.to_string(),
                                                    tip,
                                                    tip_hash,
                                                )
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
                                                    // TipChanged / TxIdMismatch /
                                                    // Rejected: the submission
                                                    // record stands regardless —
                                                    // reservations hold until
                                                    // confirmation or expiry, and
                                                    // can never double-spend.
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
                                            // A relay's OTP becomes deliverable
                                            // only once its transaction is
                                            // definitively accepted for
                                            // broadcast. The challenge travels
                                            // with the submission so eviction
                                            // can discard it later.
                                            let relay_challenge = outcome
                                                .relay_challenge
                                                .as_ref()
                                                .map(|(key, _)| key.clone());
                                            if let Some((key, otp)) = outcome.relay_challenge {
                                                if accepted {
                                                    mint.pending_otps
                                                        .record_issued(key, &otp, tip);
                                                } else {
                                                    mint.pending_otps.release_challenge(&key);
                                                }
                                            }
                                            mint.record_submission(
                                                kind,
                                                txid,
                                                reserved,
                                                outcome.name_binding,
                                                relay_challenge,
                                                zcash_protocol::consensus::BlockHeight::from_u32(
                                                    u32::from(target) + TX_EXPIRY_BUFFER,
                                                ),
                                                &mut excluded,
                                            );
                                            mint.mark_intake_seen(locator);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                ?error,
                                                kind = ?outcome.name_binding.is_some(),
                                                "assembly failed"
                                            );
                                            if let Some(lock) = outcome.name_lock {
                                                mint.release_name(&lock);
                                            }
                                            if let Some((key, _)) = outcome.relay_challenge {
                                                mint.pending_otps.release_challenge(&key);
                                            }
                                            // Invalid request or held lock: not
                                            // marked seen — the next cycle
                                            // re-evaluates.
                                        }
                                    }
                                }
                            }

                            // Housekeeping: vault sweep and fee replenishment —
                            // both no-op below their thresholds and record
                            // their own wallet spend state. Broadcast any
                            // resulting stored transactions (fetch by txid,
                            // serialize, submit, track to expiry).
                            let sweep_tip =
                                zcash_protocol::consensus::BlockHeight::from_u32(
                                    u32::from(target) - 1,
                                );
                            let produced: Vec<(
                                zcash_primitives::transaction::TxId,
                                SubmissionKind,
                            )> = [
                                zns_mint::mint::treasury::vault::sweep_to_vault(
                                    &network,
                                    &mut wallet,
                                    &treasury_keys,
                                )
                                .map(|r| r.map(|txid| (txid, SubmissionKind::AutoSweep))),
                                zns_mint::mint::treasury::replenish::replenish_registry_fees(
                                    &network,
                                    &mut wallet,
                                    &treasury_keys,
                                )
                                .map(|r| r.map(|txid| (txid, SubmissionKind::Replenish))),
                            ]
                            .into_iter()
                            .filter_map(|r| match r {
                                Ok(Some(pair)) => Some(pair),
                                Ok(None) => None,
                                Err(e) => {
                                    tracing::warn!(?e, "housekeeping failed");
                                    None
                                }
                            })
                            .collect();
                            for (txid, kind) in produced {
                                match wallet.get_transaction(txid) {
                                    Ok(Some(tx)) => match signer::serialize_tx(&tx) {
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
                                                    tracing::info!(%txid, kind = kind.as_str(), "submitted")
                                                }
                                                other => tracing::warn!(
                                                    ?other, %txid,
                                                    kind = kind.as_str(),
                                                    "submit not accepted"
                                                ),
                                            }
                                            mint.record_submission(
                                                kind,
                                                txid,
                                                Vec::new(),
                                                None,
                                                None,
                                                zcash_protocol::consensus::BlockHeight::from_u32(
                                                    u32::from(sweep_tip) + 1 + TX_EXPIRY_BUFFER,
                                                ),
                                                &mut excluded,
                                            );
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
            }
        }
    }
}
