//! The Zcash Name Service attested Mint.
//!
//! Boot establishes identity, syncs from the birthday checkpoint to the
//! chain tip, and verifies genesis (40 anchors, minimum Treasury balance).
//! `main` is then a pure run loop: it follows Zebra's canonical chain,
//! scans each new block, enforces the Registry transition law, services
//! Treasury memos (paid claims, update and release requests, OTP echoes),
//! runs the lifecycle (expiry releases), and
//! sweeps the Treasury. The mint authors no genesis state: the anchor
//! pool is created once by the keygen ceremony and replenishes itself
//! through every claim.

use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::WalletRead as _;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::value::Zatoshis;

use tokio::sync::mpsc;

use zns_mint::boot::Boot;
use zns_mint::mint::note::NameNoteQueue;
use zns_mint::mint::note::{assemble, decrypt_treasury_tx};
use zns_mint::mint::otp::{OtpQueue, OtpRequest};
use zns_mint::mint::pricing::fetch_round;
use zns_mint::mint::treasury::{self, RequestQueue};
use zns_mint::mint::{
    relay, watch_mempool, Action, Challenge, MintInbound, Request, REGISTRY_ACCOUNT,
    TREASURY_ACCOUNT,
};
use zns_mint::zcash::{
    CanonicalBlockSource, JsonRpc, MempoolChangeKind, TipSession, TransportError, RETRY_PAUSE,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let Boot {
        network,
        chain,
        mut wallet,
        cursor: mut chain_tip,
        treasury_keys,
        registry_keys,
        sapling_spend,
        sapling_output,
        mut mtp,
        mut oracle,
        mut challenges,
        access_code_key,
        mut registry,
    } = Boot::start().await;

    // A pure function of config — hardcoded node, hardcoded timeouts;
    // reconstructing it loses nothing.
    let rpc = JsonRpc::new();
    let source = CanonicalBlockSource::new();

    // Authorized Name Notes awaiting the chain: the lanes admit, the
    // enactment phase builds and broadcasts.
    let mut name_notes = NameNoteQueue::default();
    // Treasury requests decoded once at block application: what each memo
    // said, what it paid, the block that carried it. The drain at each tip
    // decides entries; a reorg truncates them.
    let mut requests = RequestQueue::default();
    let mut echoes: Vec<(Challenge, Zatoshis, BlockHeight)> = Vec::new();

    zns_mint::metrics::install();
    tracing::info!(
        height = u32::from(chain_tip.block_height()),
        hash = %chain_tip.block_hash(),
        "mint awaiting Zebra tips"
    );

    // The tip session owns the stream's lifecycle — wake, repair, and
    // the re-read of the canonical tip that turns every wake-up into the
    // node's answer, never the announcement's promise. The orchestrator
    // holds position (the wallet) and never sees transport state.
    // The watcher forwards Zebra's change kind and txid. The run loop owns
    // OtpQueue and admits or invalidates requests as those events arrive.
    let (mempool_tx, mut mempool_rx) = mpsc::channel(64);
    tokio::spawn(watch_mempool(chain.clone(), mempool_tx));

    let mut connection = TipSession::open(chain).await;
    'run: loop {
        let (best_height, _) = tokio::select! {
            tip = connection.next_tip(&source) => match tip {
                Ok(tip) => tip,
                Err(error) => panic!("FATAL: Zebra returned an invalid canonical tip: {error}"),
            },
            Some((kind, txid)) = mempool_rx.recv() => {
                let mtp_now = mtp.current().expect("FATAL: MTP unavailable at the applied tip");
                match kind {
                    MempoolChangeKind::Invalidated => challenges.invalidate(txid, mtp_now),
                    MempoolChangeKind::Mined => {}
                    MempoolChangeKind::Added => {
                        let branch_id = BranchId::for_height(&network, BlockHeight::from_u32(u32::MAX));
                        if let Some(transaction) = rpc.get_raw_transaction(branch_id, txid).await.ok().flatten() {
                            for (_action_index, paid, memo) in decrypt_treasury_tx(
                                &transaction,
                                &treasury_keys.orchard_fvk(),
                            ) {
                                let MintInbound::Request(request) = MintInbound::decode(&network, &memo) else {
                                    continue;
                                };
                                let (name, action, requested_ua, term) = match &request {
                                    Request::Update { name, ua, term } => (name, Action::Update, ua, *term),
                                    Request::Release { name, ua } => (name, Action::Release, ua, None),
                                    Request::Claim { .. } => continue,
                                };
                                let Some(record) = registry.record(name).cloned() else { continue; };
                                let trigger_height = chain_tip.block_height() + 1;
                                if !record.admits(action, requested_ua, term, trigger_height, mtp_now)
                                    || paid < oracle.challenge_fee()
                                {
                                    continue;
                                }
                                let (_, pending) = OtpRequest::pending_challenge(
                                    name, action, requested_ua, record.commitment, term, mtp_now,
                                );
                                let pending = challenges.admit_request(pending, txid, mtp_now);
                                if !challenges.is_relayed(&pending)
                                    && relay(
                                        &network, &mut wallet, &treasury_keys, &sapling_spend,
                                        &sapling_output, &record.ua, &source, &pending, "mempool",
                                    ).await
                                {
                                    challenges.challenge_issued(&pending);
                                }
                            }
                        }
                    }
                }
                continue;
            }
        };

        // Compare the wallet's own cursor with Zebra at the same height.
        // If they disagree, walk backward until both name the same block;
        // no state above that common ancestor survives.
        let mut ancestor = chain_tip.block_height().min(best_height);
        loop {
            let wallet_hash = wallet.block_hash_at(ancestor);
            if wallet_hash.is_none() {
                panic!(
                    "FATAL: no common ancestor within the wallet's applied chain \
                     (data exhausted at height {})",
                    u32::from(ancestor)
                );
            }
            let canonical_hash = loop {
                match source.get_block_hash(ancestor).await {
                    Ok(hash) => break hash,
                    Err(error) if error.is_retryable() => {
                        tracing::warn!(
                            %error,
                            height = u32::from(ancestor),
                            "ancestor hash unavailable; retrying"
                        );
                        tokio::time::sleep(RETRY_PAUSE).await;
                    }
                    Err(TransportError::NotOnBestChain) => {
                        tracing::warn!(
                            height = u32::from(ancestor),
                            "ancestor left the best chain mid-walk; re-converging"
                        );
                        continue 'run;
                    }
                    Err(error) => {
                        panic!("FATAL: Zebra returned an invalid ancestor hash: {error}")
                    }
                }
            };
            if wallet_hash == Some(canonical_hash) {
                break;
            }
            // Height 0 has no predecessor. Subtracting would wrap; the walk
            // has already exhausted the chain.
            let Some(prev) = u32::from(ancestor).checked_sub(1) else {
                panic!(
                    "FATAL: no common ancestor within the wallet's applied chain \
                     (data exhausted at height {})",
                    u32::from(ancestor)
                );
            };
            ancestor = BlockHeight::from_u32(prev);
        }

        if ancestor < chain_tip.block_height() {
            // The wallet commits first. A refusal leaves the other faculties
            // where they were. They then follow the height that committed,
            // which can be the boot origin below the requested ancestor.
            chain_tip = wallet
                .truncate_to(ancestor)
                .expect("FATAL: wallet could not rewind to the common ancestor");
            let rewound = chain_tip.block_height();
            registry.truncate_to_height(rewound);

            // Rebuild the entire MTP window at the committed height. Retaining a
            // partial old window and appending the same heights again would
            // mix histories after a deep reorg.
            mtp = zns_mint::mint::mtp::MtpTracker::default();
            mtp.backfill(rewound, |height| {
                let source = source.clone();
                async move {
                    let (_, _, timestamp) = source.get_block_header(height).await?;
                    Ok::<_, zns_mint::zcash::TransportError>(
                        u32::try_from(timestamp.as_seconds())
                            .expect("Zcash header timestamps fit u32"),
                    )
                }
            })
            .await
            .expect("FATAL: MTP reconstruction after reorg failed");
            challenges = OtpQueue::new();
            name_notes.truncate_to(rewound);
            requests.truncate_to(rewound);
            echoes.retain(|(_, _, height)| *height <= rewound);
            tracing::warn!(
                height = u32::from(rewound),
                hash = %chain_tip.block_hash(),
                "mint rewound to canonical ancestor"
            );
        }

        // MTP still names the previous tip's day. Catch-up may cross a
        // midnight; `today` after apply is the same local the oracle
        // gets, and the sweep sees the diff.
        let previous_day = mtp
            .current_day()
            .expect("FATAL: MTP unavailable before catch-up");

        // Apply every missing canonical block in strict order: fetch with
        // retry, verify the terminal block, call `apply_block` — the
        // application itself is the one body shared with boot.
        while chain_tip.block_height() < best_height {
            let from_height = chain_tip.block_height();
            let next_height = from_height + 1;

            let from_state = loop {
                match source.chain_state_at(from_height).await {
                    Ok(state) => break state,
                    Err(error) if error.is_retryable() => {
                        tracing::warn!(
                            %error,
                            height = u32::from(from_height),
                            "previous chain state unavailable; retrying"
                        );
                        tokio::time::sleep(RETRY_PAUSE).await;
                    }
                    Err(TransportError::NotOnBestChain) => {
                        tracing::warn!(
                            height = u32::from(from_height),
                            "the chain moved under the tree-state fetch; re-converging"
                        );
                        continue 'run;
                    }
                    Err(error) => {
                        panic!("FATAL: Zebra returned an invalid previous chain state: {error}")
                    }
                }
            };

            let block = loop {
                match source.get_block(&network, next_height).await {
                    Ok(block) => break block,
                    Err(error) if error.is_retryable() => {
                        tracing::warn!(
                            %error,
                            height = u32::from(next_height),
                            "canonical block unavailable; retrying"
                        );
                        tokio::time::sleep(RETRY_PAUSE).await;
                    }
                    Err(TransportError::NotOnBestChain) => {
                        tracing::warn!(
                            height = u32::from(next_height),
                            "the chain moved under the block fetch; re-converging"
                        );
                        continue 'run;
                    }
                    Err(error) => {
                        panic!("FATAL: Zebra returned an invalid canonical block: {error}")
                    }
                }
            };
            // The chain may move under the fetches; a non-extending block
            // discards the cycle — the reorg's own queued tip notification
            // wakes the reconcile walk.
            if block.header().prev_block != chain_tip.block_hash() {
                tracing::warn!(
                    height = u32::from(next_height),
                    "fetched block does not extend the applied chain; re-converging"
                );
                continue 'run;
            }

            let arrivals = zns_mint::mint::apply_block(
                &network,
                &registry_keys,
                &treasury_keys,
                &from_state,
                block,
                next_height,
                &mut wallet,
                &mut registry,
                &mut mtp,
                &mut chain_tip,
            );
            for (txid, inbound, paid) in arrivals {
                match inbound {
                    MintInbound::Request(request) => {
                        requests.record(txid, request, paid, next_height);
                    }
                    MintInbound::Echo(echo) => echoes.push((echo, paid, next_height)),
                    MintInbound::Unrecognized => {
                        tracing::info!(
                            txid = %txid,
                            value_zec = paid.into_u64() as f64 / 1e8,
                            height = u32::from(next_height),
                            "treasury received non-request payment"
                        );
                    }
                }
            }
        }

        tracing::info!(
            height = u32::from(chain_tip.block_height()),
            "scanned to tip"
        );
        let tip = chain_tip.block_height();
        let tip_hash = chain_tip.block_hash();
        let target_height = tip + 1;
        let mtp_now = mtp
            .current()
            .expect("FATAL: MTP unavailable at the applied tip");

        let today = mtp
            .current_day()
            .expect("FATAL: MTP unavailable at the applied tip");
        oracle.accumulate(fetch_round().await, today, mtp_now);
        // Transient or unusable tip data → skip this rule pass and wait
        // for another notification; a chain race re-converges.
        let exact_tip = match source.canonical_tip().await {
            Ok(tip) => tip,
            Err(error) if error.is_retryable() => {
                tracing::warn!(
                    %error,
                    "post-catch-up tip unavailable; skipping rules until next notification"
                );
                continue;
            }
            Err(TransportError::NotOnBestChain) => {
                tracing::warn!("tip lane returned NotOnBestChain; re-converging");
                continue 'run;
            }
            Err(error) => {
                tracing::error!(%error, "post-catch-up tip unusable; skipping rules this notification");
                continue;
            }
        };
        if exact_tip != (tip, tip_hash) {
            tracing::warn!(
                scanned_height = u32::from(tip),
                scanned_hash = %tip_hash,
                zebra_height = u32::from(exact_tip.0),
                zebra_hash = %exact_tip.1,
                "tip moved during price fetch; skipping rules until next notification"
            );
            continue;
        }

        // The three gauges: chain level, money level, price level.
        let treasury_zats = wallet
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .expect("FATAL: balance summary failed")
            .expect("FATAL: chain knowledge missing before gauge")
            .account_balances()
            .get(&TREASURY_ACCOUNT)
            .expect("FATAL: treasury account missing from summary")
            .total()
            .into_u64();
        zns_mint::metrics::snapshot(tip, treasury_zats, oracle.current().into_u64());

        // Treasury requests. Each memo was decoded once, at block
        // application; the drain decides each entry exactly once. A
        // decided entry leaves the queue; a deferred relay — Treasury
        // fee funds missing, or the node rejected the challenge — waits
        // for the next tip. Nothing is re-read.
        let mut index = 0;
        while index < requests.len() {
            let (txid, request, paid, note_height) = requests.entry(index);
            let decided = 'lane: {
                match request {
                    Request::Claim {
                        name,
                        ua,
                        term,
                        code,
                    } => {
                        // One open claim per name at a time: the Registry
                        // lags the mempool by a block; the queue holds an
                        // order only until its send. A rival payment that
                        // slips past both may spend another anchor — any
                        // duplicate the chain still carries is ignored,
                        // first confirmed wins.
                        if name_notes.claim_pending(name) {
                            tracing::debug!(
                                name = %name.as_str(),
                                "claim already pending for this name"
                            );
                            break 'lane true;
                        }
                        // Pre-sale gate: read-only table lookup.
                        // Unavailability defers with the queue; a deny is
                        // decided. Redemption is the name already live.
                        let name_live = registry
                            .record(name)
                            .is_some_and(|r| r.action != Action::Release);
                        match zns_mint::mint::presale::decide(
                            zns_mint::mint::presale::lookup_name(name, mtp_now).await,
                            code.as_ref(),
                            name_live,
                            access_code_key.as_bytes(),
                            name.as_str(),
                        ) {
                            zns_mint::mint::presale::Decision::Retry => {
                                tracing::debug!(
                                    name = %name.as_str(),
                                    "pre-sale lookup unavailable; claim waits"
                                );
                                break 'lane false;
                            }
                            zns_mint::mint::presale::Decision::Deny => {
                                tracing::debug!(
                                    name = %name.as_str(),
                                    "pre-sale claim refused"
                                );
                                break 'lane true;
                            }
                            zns_mint::mint::presale::Decision::Allow => {}
                        }
                        // Payment gate: the quote at first sight is binding.
                        // An underpaid claim, or one whose quote does not
                        // fit, is dead and silent; a new payment settles
                        // a new evaluation.
                        let Some(price) = oracle.quote(name, *term) else {
                            break 'lane true;
                        };
                        if paid < price {
                            break 'lane true;
                        }
                        let Some(claim_note) = registry.authorize(
                            &mut challenges,
                            Request::Claim {
                                name: name.clone(),
                                ua: ua.clone(),
                                term: *term,
                                code: code.clone(),
                            },
                            None,
                            note_height,
                            mtp_now,
                        ) else {
                            tracing::debug!(
                                name = %name.as_str(),
                                "claim not authorized"
                            );
                            break 'lane true;
                        };
                        // Enactment below resolves the anchor and broadcasts.
                        name_notes.admit(note_height, claim_note);
                        true
                    }
                    request @ (Request::Update { .. } | Request::Release { .. }) => {
                        let (name, action, requested_ua, term) = match request {
                            Request::Update { name, ua, term } => (name, Action::Update, ua, *term),
                            Request::Release { name, ua } => (name, Action::Release, ua, None),
                            Request::Claim { .. } => unreachable!(),
                        };
                        let Some(record) = registry.record(name).cloned() else {
                            break 'lane true;
                        };
                        if !record.admits(action, requested_ua, term, note_height, mtp_now)
                            || paid < oracle.challenge_fee()
                        {
                            break 'lane true;
                        }
                        let (_, pending) = OtpRequest::pending_challenge(
                            name,
                            action,
                            requested_ua,
                            record.commitment,
                            term,
                            mtp_now,
                        );
                        challenges.admit_request(pending, *txid, mtp_now);
                        true
                    }
                }
            };
            if decided {
                requests.remove(index);
            } else {
                index += 1;
            }
        }

        // Queue admission is independent from submission. Retry every still-
        // requested mempool or confirmed entry once during each tip pass.
        for pending in challenges.requested(mtp_now) {
            let Some(record) = registry
                .record(&pending.name)
                .filter(|record| record.commitment == pending.tip_rcm)
            else {
                continue;
            };
            if relay(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &record.ua,
                &source,
                &pending,
                "tip",
            )
            .await
            {
                challenges.challenge_issued(&pending);
            }
        }

        // Confirmed OTP responses wait in the run loop until the tip pass.
        // Requests run first; a voided echo leaves its challenge available.
        for (echo, paid, note_height) in std::mem::take(&mut echoes) {
            let _ = 'lane: {
                // The echo lane: an OTP response. Decided in every outcome —
                // an echo never waits for money; the renewal or
                // upgrade fee declines on shortfall, it does not defer.
                let Some(record) = registry.record(&echo.name).cloned() else {
                    break 'lane true; // no record: no mint-issued challenge can match
                };
                if record.action.is_release() {
                    break 'lane true;
                }
                let Some(sent) = challenges.awaiting(&echo, record.commitment, mtp_now) else {
                    break 'lane true; // no pending challenge: dead
                };
                // The renewal or upgrade fee, binding at first
                // sight: a shortfall voids the attempt and never
                // consumes — the challenge stands, retryable with
                // the same OTP inside D_OTP.
                if let Some(term) = sent.term {
                    let Some(price) = oracle.quote(&echo.name, term) else {
                        tracing::debug!(
                            name = %echo.name.as_str(),
                            "update quote does not fit — attempt void, challenge stands"
                        );
                        break 'lane true;
                    };
                    if paid < price {
                        tracing::debug!(
                            name = %echo.name.as_str(),
                            paid = paid.into_u64(),
                            "update respond underpaid — attempt void, challenge stands"
                        );
                        break 'lane true;
                    }
                }
                let digits = sent.code.digits();
                let authorized = match echo.action {
                    Action::Update => Request::Update {
                        name: echo.name.clone(),
                        ua: echo.ua.clone(),
                        term: sent.term,
                    },
                    Action::Release => Request::Release {
                        name: echo.name.clone(),
                        ua: echo.ua.clone(),
                    },
                    Action::Claim => unreachable!("claims never carry an OTP"),
                };
                let Some(transition_note) = registry.authorize(
                    &mut challenges,
                    authorized,
                    Some(&digits),
                    note_height,
                    mtp_now,
                ) else {
                    break 'lane true;
                };
                // The seam where a voluntary release exists:
                // the OTP that authorized it is consumed here,
                // and the resulting note is indistinguishable
                // from a unilateral one on chain. This line is
                // the only durable record of the cause.
                if echo.action.is_release() {
                    tracing::info!(
                        name = %echo.name.as_str(),
                        "voluntary release authorized"
                    );
                }
                name_notes.admit(note_height, transition_note);
                true
            };
        }

        // Lifecycle releases, §4.5: the registry owns the clocks and
        // their plural; the sweep drains the batch each tip.
        // `releases_due` re-derives the same notes per tip, so
        // admission is idempotent.
        for (name, release_note) in registry.releases_due(mtp_now) {
            tracing::info!(name = %name.as_str(), "lifecycle release authorized");
            name_notes.admit(tip, release_note);
        }

        // --- NameNote enactment ---
        // The order drain: one broadcast per decision. An order leaves
        // the queue when it is sent — the wallet's retained transaction
        // is then the record of the open commitment until the chain
        // resolves it — or when the world overtakes it. Nothing here
        // re-enacts a sent order: the wallet answers for it.
        let mut index = 0;
        while index < name_notes.len() {
            let (note, origin) = {
                let (note, origin) = name_notes.entry(index);
                (note.clone(), origin)
            };
            // Authority: a claim spends a lineage pool anchor; an update
            // or release spends the predecessor — the record's nullifier
            // matched by commitment.
            let authority_nf = if note.action().is_claim() {
                // The name must still be claimable: free, or released
                // after the payment arrived.
                let claimable = match registry.record(note.name()) {
                    None => true,
                    Some(record) => record.action.is_release() && origin > record.confirmed_height,
                };
                if !claimable {
                    tracing::debug!(
                        name = %note.name().as_str(),
                        "claim order dropped: the name is live on the chain"
                    );
                    name_notes.remove(index);
                    continue;
                }
                match registry.anchor_pool().iter().copied().find(|nf| {
                    wallet
                        .unspent_ironwood_note_by_nullifier(
                            REGISTRY_ACCOUNT,
                            *nf,
                            TargetHeight::from(tip),
                        )
                        .is_some()
                }) {
                    Some(nf) => nf,
                    None => {
                        tracing::warn!(
                            name = %note.name().as_str(),
                            "no available claim anchor (all locked or spent)"
                        );
                        index += 1;
                        continue;
                    }
                }
            } else {
                match registry
                    .record(note.name())
                    .filter(|record| {
                        !record.action.is_release() && Some(record.commitment) == note.prev_rcm()
                    })
                    .map(|record| record.nullifier)
                {
                    Some(nf) => nf,
                    None => {
                        tracing::debug!(
                            name = %note.name().as_str(),
                            action = note.action().as_str(),
                            "order dropped: its predecessor is no longer current"
                        );
                        name_notes.remove(index);
                        continue;
                    }
                }
            };
            // A release whose predecessor the wallet will not release is
            // this order's own open send — re-derivation re-admits
            // releases every tip they stay due, so the churn self-heals;
            // an update in the same shape may be racing a sibling, and
            // stays queued instead.
            if note.action().is_release()
                && wallet
                    .unspent_ironwood_note_by_nullifier(
                        REGISTRY_ACCOUNT,
                        authority_nf,
                        TargetHeight::from(tip),
                    )
                    .is_none()
            {
                tracing::debug!(
                    name = %note.name().as_str(),
                    "release order sent: its transaction is still open"
                );
                name_notes.remove(index);
                continue;
            }

            let Some(transaction) = assemble::prepare(
                &network,
                &mut wallet,
                &treasury_keys,
                &registry_keys,
                &sapling_spend,
                &sapling_output,
                note.clone(),
                authority_nf,
                tip,
                target_height,
            ) else {
                tracing::debug!(
                    name = %note.name().as_str(),
                    action = note.action().as_str(),
                    "NameNote order awaits Treasury fee funds"
                );
                index += 1;
                continue;
            };

            if source.submit(&transaction, "NameNote").await {
                tracing::info!(
                    txid = %transaction.txid(),
                    name = %note.name().as_str(),
                    action = note.action().as_str(),
                    "NameNote order sent — the wallet holds it until the chain answers"
                );
                name_notes.remove(index);
            } else {
                tracing::error!(
                    txid = %transaction.txid(),
                    name = %note.name().as_str(),
                    action = note.action().as_str(),
                    "NameNote submission rejected — inputs stranded until expiry"
                );
                index += 1;
            }
        }

        if today > previous_day {
            if let Some(tx) = treasury::sweep_to_vault(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
            ) {
                source.submit(&tx, "vault sweep").await;
            }
        }

        tracing::debug!(
            height = u32::from(tip),
            hash = %tip_hash,
            "mint rules applied at canonical tip"
        );
    }
}
