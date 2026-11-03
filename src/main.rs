//! The Zcash Name Service attested Mint.
//!
//! Boot establishes identity, syncs from the wallet origin checkpoint to the
//! chain tip, and verifies genesis (ceremony adoption closed, minimum Treasury balance).
//! `main` is then a pure run loop: it follows Zebra's canonical chain,
//! scans each new block, enforces the Registry transition law, services
//! Treasury memos (paid claims, update and release requests, OTP responses,
//! buy requests), runs the lifecycle (expiry releases), and
//! sweeps the Treasury. The mint authors no genesis state: the anchor
//! pool is created once by the keygen ceremony and replenishes itself
//! through every claim.

use time::Timestamp;
use tokio::sync::mpsc;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::Zatoshis;

use zns_mint::boot::Boot;
use zns_mint::mint::note::{assemble, NameNoteQueue};
use zns_mint::mint::presale;
use zns_mint::mint::pricing::{fetch_round, Oracle};
use zns_mint::mint::registry::Registry;
use zns_mint::mint::sale::Market;
use zns_mint::mint::treasury;
use zns_mint::mint::treasury::{
    access_code_penalty, zero_conf_candidate, ChallengeAnswer, OtpQueue, RefundQueue,
};
use zns_mint::mint::{
    relay, relay_buy, relay_challenge, spends_transparent, MintInbound, OtpMemo, Request,
    REGISTRY_ACCOUNT, TREASURY_ACCOUNT,
};
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{
    CanonicalBlockSource, MempoolChangeKind, TipSession, TransportError, RETRY_PAUSE,
};
use zns_mint::TreasuryKeys;

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
        birthday,
        chain,
        source,
        mut wallet,
        treasury_keys,
        registry_keys,
        sapling_spend,
        sapling_output,
        mut mtp,
        mut oracle,
        mut challenges,
        access_code_key,
        mut protected_names,
        presale_client,
        mut fee_rule,
        mut registry,
        mut name_notes,
        mut requests,
        mut refunds,
        mut market,
        treasury_address,
        registry_ufvk,
        seed_fingerprint,
        capsule_hash,
        #[cfg(not(feature = "non-tee"))]
        guest,
    } = Boot::start().await;

    zns_mint::metrics::install();
    zns_mint::metrics::identity(&treasury_address, &registry_ufvk);
    zns_mint::metrics::ceremony(&seed_fingerprint, &capsule_hash);
    #[cfg(not(feature = "non-tee"))]
    zns_mint::metrics::guest(&guest.measurement, &guest.guest_policy);
    // The wallet scan is finished. The run loop has not started.
    zns_mint::metrics::serving(false);
    tracing::info!(
        height = u32::from(wallet.tip().block_height()),
        hash = %wallet.tip().block_hash(),
        "mint awaiting Zebra tips"
    );

    // The tip session owns the stream: announcements are the answer,
    // failures repair and read the canonical tip. The loop never sees
    // transport state.
    let mut connection = TipSession::open(chain.clone()).await;
    let (mempool_tx, mut mempool_rx) = mpsc::channel(64);
    tokio::spawn(zns_mint::mint::watch_mempool(chain, mempool_tx));
    let mut held: Vec<HeldEcho> = Vec::new();
    zns_mint::metrics::serving(true);
    'run: loop {
        // Every pass ends here, however it ended: the names the queues
        // still hold are in flight until the next tip.
        zns_mint::metrics::requests_in_flight(
            requests
                .names()
                .chain(challenges.unrelayed())
                .chain(market.names())
                .chain(name_notes.authorized_names()),
            challenges.relayed(),
        );
        let best_height = tokio::select! {
            tip = connection.next_tip(&source) => {
                tip.unwrap_or_else(|error| {
                    panic!("FATAL: Zebra returned an invalid canonical tip: {error}")
                })
                .0
            }
            event = mempool_rx.recv() => {
                let Some((kind, txid)) = event else {
                    panic!("FATAL: mempool watcher ended");
                };
                let mtp_now = mtp
                    .current()
                    .expect("FATAL: MTP unavailable before a mempool relay");
                consider_mempool(
                    &network,
                    &source,
                    &mut wallet,
                    &treasury_keys,
                    &sapling_spend,
                    &sapling_output,
                    &fee_rule,
                    &registry,
                    &mut name_notes,
                    &market,
                    &mut challenges,
                    &mut held,
                    &mut refunds,
                    &oracle,
                    kind,
                    txid,
                    mtp_now,
                )
                .await;
                continue;
            }
        };
        // The pre-sale read runs while the blocks below are fetched and
        // applied. If this pass restarts, the read is cancelled.
        let presale_read = presale::PendingRead::start(&presale_client);

        // Compare the wallet's own cursor with Zebra at the same height.
        // If they disagree, walk backward until both name the same block;
        // no state above that common ancestor survives.
        let mut ancestor = wallet.tip().block_height().min(best_height);
        loop {
            assert!(
                ancestor >= birthday,
                "FATAL: canonical fork crossed the mint birthday"
            );
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

        if ancestor < wallet.tip().block_height() {
            // The wallet commits first. A refusal leaves the other faculties
            // where they were. They then follow the height that committed,
            // which can be the boot origin below the requested ancestor.
            let rewound = wallet
                .truncate_to(ancestor)
                .expect("FATAL: wallet could not rewind to the common ancestor")
                .block_height();
            assert!(
                rewound >= birthday,
                "FATAL: wallet rewind crossed the mint birthday"
            );
            registry.truncate_to_height(rewound);

            // Rebuild the entire MTP window at the committed height. Retaining a
            // partial old window and appending the same heights again would
            // mix histories after a deep reorg.
            mtp = zns_mint::mint::mtp::MtpTracker::default();
            mtp.backfill(rewound, |height| {
                let source = source.clone();
                async move {
                    let (_, _, timestamp) = source.get_block_header(height).await?;
                    Ok::<_, TransportError>(
                        u32::try_from(timestamp.as_seconds())
                            .expect("Zcash header timestamps fit u32"),
                    )
                }
            })
            .await
            .expect("FATAL: MTP reconstruction after reorg failed");
            // Echoes in blocks that remain can never match: the queue is
            // empty after the rewind. Echoes above the ancestor return
            // with those blocks.
            held.retain(|echo| echo.height <= rewound);
            for echo in held.drain(..) {
                refunds.admit(
                    &fee_rule,
                    echo.txid,
                    &echo.response.ua,
                    &echo.response.name,
                    echo.height,
                    echo.paid,
                );
            }
            challenges = OtpQueue::new();
            market.truncate_to(rewound);
            market.expire(
                mtp.current().expect("FATAL: MTP unavailable after reorg"),
                rewound,
            );
            name_notes.rewind_to(rewound);
            name_notes.reconcile_seen(&network, &registry);
            requests.truncate_to(rewound);
            refunds.truncate_to(rewound);
            tracing::warn!(
                height = u32::from(rewound),
                hash = %wallet.tip().block_hash(),
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
        while wallet.tip().block_height() < best_height {
            let from_height = wallet.tip().block_height();
            let next_height = from_height + 1;

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
            if block.header().prev_block != wallet.tip().block_hash() {
                tracing::warn!(
                    height = u32::from(next_height),
                    "fetched block does not extend the applied chain; re-converging"
                );
                continue 'run;
            }
            let wall = time::OffsetDateTime::now_utc().unix_timestamp();
            mtp.header_time_ok(block.header().time, wall)
                .unwrap_or_else(|reason| {
                    panic!("FATAL: {reason} at height {}", u32::from(next_height))
                });

            let payments = zns_mint::mint::sale::transparent_payments(&block);
            let arrivals = zns_mint::mint::apply_block(
                &network,
                birthday,
                &registry_keys,
                &treasury_keys,
                block,
                next_height,
                &mut wallet,
                &mut registry,
                &mut mtp,
            );
            name_notes.reconcile_seen(&network, &registry);
            // The block's own clock: a challenge expired by it completes
            // nothing in it, and the law reads it.
            let block_mtp = mtp
                .current()
                .expect("FATAL: MTP unavailable at the applied block");
            challenges.expire(block_mtp);
            settle_held(
                &fee_rule,
                &oracle,
                &registry,
                &mut name_notes,
                &mut challenges,
                &market,
                &mut refunds,
                &mut held,
                block_mtp,
            );
            market.expire(block_mtp, next_height);
            market.reconcile(
                |name| {
                    registry
                        .record(name)
                        .map(|record| (record.ua.clone(), record.commitment))
                },
                next_height,
            );
            for (txid, inbound, paid) in arrivals {
                match inbound {
                    MintInbound::Request(request) => {
                        requests.record(txid, request, paid, next_height);
                    }
                    // The right code spends its OTP, and the transition it
                    // authorizes is ruled on at the block that carried it.
                    // A refused response goes back to the memo address,
                    // less the refund fee.
                    MintInbound::Response(response) => {
                        if response.action.is_list() || response.action.is_delist() {
                            let owner = registry
                                .record(&response.name)
                                .map(|record| record.ua.clone());
                            market.answer(&response, owner.as_ref(), next_height);
                            refunds.admit(
                                &fee_rule,
                                txid,
                                &response.ua,
                                &response.name,
                                next_height,
                                paid,
                            );
                            continue;
                        }
                        take_controller_echo(
                            &fee_rule,
                            &oracle,
                            &registry,
                            &mut name_notes,
                            &mut challenges,
                            &market,
                            &mut refunds,
                            &mut held,
                            txid,
                            response,
                            paid,
                            next_height,
                            block_mtp,
                        );
                    }
                    MintInbound::List(_) | MintInbound::Delist(_) | MintInbound::Buy(_) => {
                        if let Some(name) = market.admit(
                            txid,
                            &inbound,
                            paid,
                            &registry,
                            &fee_rule,
                            next_height,
                            block_mtp,
                            |name| name_notes.note_pending(name),
                            |name| access_code_key.buy_otp(&txid, name),
                            |inbound| match inbound {
                                MintInbound::List(list) => Some(access_code_key.list_otp(
                                    &txid,
                                    &list.name,
                                    list.price,
                                    &list.pay_to,
                                )),
                                MintInbound::Delist(delist) => {
                                    Some(access_code_key.delist_otp(&txid, &delist.name))
                                }
                                _ => None,
                            },
                        ) {
                            challenges.drop_challenges(&name);
                        }
                    }
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
            market.observe(
                |name| registry.record(name).map(|record| record.ua.clone()),
                &payments,
                block_mtp,
                next_height,
            );
        }

        tracing::info!(
            height = u32::from(wallet.tip().block_height()),
            "scanned to tip"
        );
        let tip = wallet.tip().block_height();
        let tip_hash = wallet.tip().block_hash();
        let target_height = tip + 1;
        let mtp_now = mtp
            .current()
            .expect("FATAL: MTP unavailable at the applied tip");

        let today = mtp
            .current_day()
            .expect("FATAL: MTP unavailable at the applied tip");
        // The tip check below covers the price round and the pre-sale
        // read alike. Only the read's unspent timeout can delay the pass.
        let (round, ()) = tokio::join!(fetch_round(), presale_read.install(&mut protected_names));
        // The rate when the requests below were first seen: a day this
        // round publishes does not reprice them.
        let rate = oracle.current();
        oracle.accumulate(round, today, mtp_now);
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
        // The node's fee rate for every transaction this pass builds. A
        // failed read keeps the last rate the node gave.
        match source.standard_fee().await {
            Ok(rule) => {
                if rule.marginal_fee() != fee_rule.marginal_fee() {
                    tracing::info!(
                        zats_per_action = rule.marginal_fee().into_u64(),
                        "fee rate changed"
                    );
                }
                fee_rule = rule;
            }
            Err(error) => tracing::warn!(%error, "fee rate unavailable; keeping the last rate"),
        }

        // The three gauges: chain level, money level, price level.
        let treasury_zats = wallet
            .get_wallet_summary(zns_mint::wallet::CONFIRMATIONS)
            .expect("FATAL: balance summary failed")
            .expect("FATAL: chain knowledge missing before gauge")
            .account_balances()
            .get(&TREASURY_ACCOUNT)
            .expect("FATAL: treasury account missing from summary")
            .total()
            .into_u64();
        zns_mint::metrics::snapshot(tip, treasury_zats, oracle.current().into_u64());

        // Each request is decided once, in queue order.
        for (txid, request, paid, note_height) in requests.pending() {
            requests.resolved(txid);
            match &request {
                Request::Claim {
                    name,
                    ua,
                    term,
                    code,
                } => {
                    // Early access: only a listed name, with its code.
                    let Some(offered) = code.as_ref() else {
                        refunds.admit(&fee_rule, txid, ua, name, note_height, paid);
                        continue;
                    };
                    if !protected_names.is_protected(name, mtp_now) {
                        refunds.admit(&fee_rule, txid, ua, name, note_height, paid);
                        continue;
                    }
                    // The quote at first sight is binding. A quote above
                    // the money supply is dead; the payment is kept.
                    let Some(price) = Oracle::quote_at(rate, name, *term) else {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            paid = paid.into_u64(),
                            "quote above the money supply; payment kept"
                        );
                        continue;
                    };
                    if paid < price {
                        refunds.admit(&fee_rule, txid, ua, name, note_height, paid);
                        continue;
                    }
                    if !access_code_key.accepts(name, Some(offered)) {
                        tracing::info!(%txid, name = %name.as_str(), "wrong access code");
                        refunds.admit(
                            &fee_rule,
                            txid,
                            ua,
                            name,
                            note_height,
                            (paid - access_code_penalty(price)).unwrap_or(Zatoshis::ZERO),
                        );
                        continue;
                    }
                    // A refusal keeps the payment unless the name is taken.
                    let Some(claim_note) =
                        registry.authorize_claim(name.clone(), ua.clone(), *term, mtp_now)
                    else {
                        if !registry.is_available(name) {
                            refunds.admit(&fee_rule, txid, ua, name, note_height, paid);
                        } else {
                            tracing::info!(
                                %txid,
                                name = %name.as_str(),
                                paid = paid.into_u64(),
                                "claim not authorized; payment kept"
                            );
                        }
                        continue;
                    };
                    // The earliest payment owns the name until its claim is observed.
                    if name_notes.admit(note_height, claim_note) {
                        challenges.drop_challenges(name);
                    } else {
                        refunds.admit(&fee_rule, txid, ua, name, note_height, paid);
                    }
                }
                Request::Update { .. } | Request::Release { .. } => {
                    if !market.allows_transition(request.name()) {
                        tracing::info!(
                            %txid,
                            name = %request.name().as_str(),
                            "challenge kept: a buy is open"
                        );
                        challenges.refuse_unmined(txid);
                        continue;
                    }
                    if registry
                        .authorize_challenge(&name_notes, &request, target_height, mtp_now)
                        .is_none()
                    {
                        tracing::info!(
                            %txid,
                            name = %request.name().as_str(),
                            paid = paid.into_u64(),
                            "challenge not authorized"
                        );
                        challenges.refuse_unmined(txid);
                        continue;
                    }
                    if !covers_challenge_fee(&fee_rule, paid) {
                        tracing::info!(
                            %txid,
                            name = %request.name().as_str(),
                            paid = paid.into_u64(),
                            "below the challenge fee"
                        );
                        challenges.refuse_unmined(txid);
                        continue;
                    }
                    challenges.admit(request.clone(), mtp_now);
                    challenges.confirm_mined(txid, note_height);
                }
                Request::List { .. } | Request::Delist { .. } => {}
            }
        }

        settle_held(
            &fee_rule,
            &oracle,
            &registry,
            &mut name_notes,
            &mut challenges,
            &market,
            &mut refunds,
            &mut held,
            mtp_now,
        );

        // Queue admission is independent from submission. Retry every
        // requested challenge once during each tip pass.
        for pending in challenges.requested() {
            if !market.allows_transition(pending.request.name()) {
                continue;
            }
            let Some(record) =
                registry.authorize_challenge(&name_notes, &pending.request, target_height, mtp_now)
            else {
                continue;
            };
            if relay(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &fee_rule,
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

        for pending in market.unrelayed_challenges() {
            if !market.allows_transition(pending.request.name()) {
                continue;
            }
            let Some(record) =
                registry.authorize_challenge(&name_notes, &pending.request, target_height, mtp_now)
            else {
                continue;
            };
            let challenge = treasury::OtpChallenge {
                request: pending.request.clone(),
                code: pending.code.clone(),
                expires_at: pending.expires_at,
                attempts: 0,
            };
            if relay_challenge(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &fee_rule,
                &record.ua,
                &source,
                &challenge,
            )
            .await
            {
                market.challenge_relayed(&pending.code);
            }
        }

        for otp in market.unrelayed() {
            if relay_buy(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &fee_rule,
                &source,
                &otp,
            )
            .await
            {
                market.relayed(&otp.name);
            }
        }

        // A paid sale binds the buyer while the holder is unchanged,
        // before the lifecycle admits its own release of the same name.
        for note in market.poll(&registry, |name| name_notes.note_pending(name), tip) {
            let name = note.name().clone();
            if name_notes.admit(tip, note) {
                challenges.drop_challenges(&name);
            }
        }

        // A broadcast order whose expiry height has passed can be signed
        // again, or dropped below once the tip median would release it.
        name_notes.expire_sent(tip);
        // Drop an update the tip median would already release, so a
        // release note can be admitted below. A broadcast still inside
        // its expiry window stays.
        for note in name_notes.authorized_notes() {
            if note.action().is_update()
                && registry
                    .record(note.name())
                    .is_some_and(|record| record.is_release_due(mtp_now))
            {
                tracing::info!(
                    name = %note.name().as_str(),
                    "update dropped: the tip median would release the name"
                );
                name_notes.drop_note(note.name());
            }
        }

        // Lifecycle releases, §4.5: the registry owns the clocks and
        // their plural; each tip admits the release notes.
        // `releases_due` re-derives the same notes per tip, so
        // admission is idempotent.
        for (name, release_note) in registry.releases_due(mtp_now) {
            // A buy holds the name past a deadline that falls while it is open.
            if name_notes.note_pending(&name) || !market.allows_transition(&name) {
                continue;
            }
            tracing::info!(name = %name.as_str(), "lifecycle release authorized");
            if name_notes.admit(tip, release_note) {
                challenges.drop_challenges(&name);
            }
        }

        for note in name_notes.authorized_notes() {
            // Authority: a claim spends the first pool anchor the wallet
            // can still spend. A pending spend stays out until it is
            // mined or expires. An update or release spends the
            // predecessor — the record's nullifier matched by commitment.
            let authority_nf = if note.action().is_claim() {
                // The name must still be absent from the applied-tip registry.
                if !registry.is_available(note.name()) {
                    tracing::debug!(
                        name = %note.name().as_str(),
                        "claim order dropped: the name is live on the chain"
                    );
                    name_notes.drop_note(note.name());
                    continue;
                }
                match registry.spendable_claim_anchor(|nf| {
                    wallet
                        .unspent_ironwood_note_by_nullifier(
                            REGISTRY_ACCOUNT,
                            nf,
                            TargetHeight::from(tip),
                        )
                        .is_some()
                }) {
                    Some(nf) => nf,
                    None => {
                        tracing::warn!(
                            name = %note.name().as_str(),
                            anchors = registry.anchor_pool().len(),
                            "no spendable claim anchor"
                        );
                        continue;
                    }
                }
            } else {
                match registry
                    .record(note.name())
                    .and_then(|record| record.nullifier(&note))
                {
                    Some(nf) => nf,
                    None => {
                        tracing::debug!(
                            name = %note.name().as_str(),
                            action = note.action().as_str(),
                            "order dropped: its predecessor is no longer current"
                        );
                        name_notes.drop_note(note.name());
                        continue;
                    }
                }
            };
            let (transaction, fee) = match assemble::prepare(
                &network,
                &mut wallet,
                &treasury_keys,
                &registry_keys,
                &sapling_spend,
                &sapling_output,
                &fee_rule,
                note.clone(),
                authority_nf,
                tip,
                target_height,
            ) {
                Ok(transaction) => transaction,
                Err(assemble::PrepareError::FeeUnfunded) => {
                    tracing::debug!(
                        name = %note.name().as_str(),
                        action = note.action().as_str(),
                        "NameNote order awaits Treasury fee funds"
                    );
                    continue;
                }
                Err(assemble::PrepareError::AuthorityUnavailable) => {
                    tracing::debug!(
                        name = %note.name().as_str(),
                        action = note.action().as_str(),
                        "NameNote order awaits its authority note"
                    );
                    continue;
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        name = %note.name().as_str(),
                        action = note.action().as_str(),
                        "NameNote order could not be built"
                    );
                    continue;
                }
            };

            if source.submit(&transaction, "NameNote").await {
                wallet.record_sent(&transaction, target_height, fee);
                name_notes.mark_sent(note.name(), transaction.expiry_height());
                tracing::info!(
                    txid = %transaction.txid(),
                    name = %note.name().as_str(),
                    action = note.action().as_str(),
                    "NameNote order sent"
                );
            } else {
                tracing::error!(
                    txid = %transaction.txid(),
                    name = %note.name().as_str(),
                    action = note.action().as_str(),
                    "NameNote submission rejected — order will retry"
                );
            }
        }

        // A refund is built on the pass after its payment's block, like a
        // Name Note, one transaction each. The wallet owns it from there,
        // like a sweep. One the Treasury cannot fund yet, or the node
        // refused, stays due.
        for refund in refunds.due(tip) {
            match treasury::issue_refund(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &fee_rule,
                &refund,
            ) {
                Ok(Some(tx)) => {
                    if source.submit(&tx, "refund").await {
                        refunds.paid(&refund);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        %error,
                        payment = %refund.payment(),
                        name = %refund.name().as_str(),
                        "refund not built"
                    );
                }
            }
        }

        // A new MTP day sweeps the Treasury to the vault once. While a
        // refund is queued, its money stays and the sweep waits a day.
        if today > previous_day && refunds.is_empty() {
            match treasury::sweep_to_vault(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &fee_rule,
            ) {
                Ok(Some(tx)) => {
                    source.submit(&tx, "vault sweep").await;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "vault sweep not built");
                }
            }
        }

        tracing::debug!(
            height = u32::from(tip),
            hash = %tip_hash,
            "mint rules applied at canonical tip"
        );
    }
}

/// An OTP response seen before the request it answers is mined.
struct HeldEcho {
    txid: TxId,
    response: OtpMemo,
    paid: Zatoshis,
    height: BlockHeight,
}

/// The request payment covers the challenge fee at the node's rate.
fn covers_challenge_fee(fee_rule: &FeeRule, paid: Zatoshis) -> bool {
    (fee_rule.marginal_fee() * treasury::FEE_ACTIONS).is_some_and(|fee| paid >= fee)
}

/// Rules on one controller echo. An unmined request holds the echo.
/// A dead request, a wrong code, or a refused transition refunds it.
#[allow(clippy::too_many_arguments)]
fn take_controller_echo(
    fee_rule: &FeeRule,
    oracle: &Oracle,
    registry: &Registry,
    name_notes: &mut NameNoteQueue,
    challenges: &mut OtpQueue,
    market: &Market,
    refunds: &mut RefundQueue,
    held: &mut Vec<HeldEcho>,
    txid: TxId,
    response: OtpMemo,
    paid: Zatoshis,
    height: BlockHeight,
    mtp: Timestamp,
) {
    // A buy holds the name. A code already issued cannot apply an
    // update or a release, and its payment returns.
    if !market.allows_transition(&response.name) {
        challenges.drop_challenges(&response.name);
        refunds.admit(fee_rule, txid, &response.ua, &response.name, height, paid);
        return;
    }
    let sent = match challenges.complete(&response, height) {
        Some(ChallengeAnswer::Held) => {
            held.push(HeldEcho {
                txid,
                response,
                paid,
                height,
            });
            return;
        }
        Some(ChallengeAnswer::Accepted { challenge, at }) => (*challenge, at),
        None => {
            refunds.admit(fee_rule, txid, &response.ua, &response.name, height, paid);
            return;
        }
    };
    let (sent, at) = sent;
    let name = sent.request.name();
    // A term keeps the whole payment once it covers the price; without
    // a term, all of it goes back.
    let rest = match &sent.request {
        Request::Update {
            term: Some(term), ..
        } => oracle
            .quote(name, *term)
            .filter(|price| paid >= *price)
            .map(|_| Zatoshis::ZERO),
        _ => Some(paid),
    };
    let Some(rest) = rest else {
        refunds.admit(fee_rule, txid, &response.ua, name, height, paid);
        return;
    };
    if name_notes.note_pending(name) {
        tracing::debug!(
            %txid,
            name = %name.as_str(),
            "transition already queued; OTP spent"
        );
        refunds.admit(fee_rule, txid, &response.ua, name, height, paid);
        return;
    }
    let authorized = match &sent.request {
        Request::Update { .. } => registry.authorize_update(&sent, mtp),
        Request::Release { .. } => registry.authorize_release(&sent),
        Request::Claim { .. } | Request::List { .. } | Request::Delist { .. } => return,
    };
    let Some(note) = authorized else {
        refunds.admit(fee_rule, txid, &response.ua, name, height, paid);
        return;
    };
    // The only durable record that a release was voluntary.
    if sent.request.action().is_release() {
        tracing::info!(
            %txid,
            name = %name.as_str(),
            "voluntary release authorized"
        );
    }
    if name_notes.admit(at, note) {
        challenges.drop_challenges(name);
    }
    if rest > Zatoshis::ZERO {
        refunds.admit(fee_rule, txid, &response.ua, name, height, rest);
    }
}

/// Replays echoes that were waiting on a request which has since been
/// mined, rejected, or dropped.
#[allow(clippy::too_many_arguments)]
fn settle_held(
    fee_rule: &FeeRule,
    oracle: &Oracle,
    registry: &Registry,
    name_notes: &mut NameNoteQueue,
    challenges: &mut OtpQueue,
    market: &Market,
    refunds: &mut RefundQueue,
    held: &mut Vec<HeldEcho>,
    mtp: Timestamp,
) {
    let waiting = std::mem::take(held);
    for echo in waiting {
        take_controller_echo(
            fee_rule,
            oracle,
            registry,
            name_notes,
            challenges,
            market,
            refunds,
            held,
            echo.txid,
            echo.response,
            echo.paid,
            echo.height,
            mtp,
        );
    }
}

/// Relays at most one challenge for a mempool transaction, or retires
/// one whose request left the mempool. A mined transaction waits for
/// the block pass.
#[allow(clippy::too_many_arguments)]
async fn consider_mempool<P: Parameters + Send + 'static>(
    network: &P,
    source: &CanonicalBlockSource,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    fee_rule: &FeeRule,
    registry: &Registry,
    name_notes: &mut NameNoteQueue,
    market: &Market,
    challenges: &mut OtpQueue,
    held: &mut Vec<HeldEcho>,
    refunds: &mut RefundQueue,
    oracle: &Oracle,
    kind: MempoolChangeKind,
    txid: TxId,
    mtp: Timestamp,
) {
    match kind {
        MempoolChangeKind::Mined => {}
        MempoolChangeKind::Invalidated => {
            if challenges.invalidate(txid) {
                zns_mint::metrics::zero_conf_relay_lost();
            }
            settle_held(
                fee_rule, oracle, registry, name_notes, challenges, market, refunds, held, mtp,
            );
        }
        MempoolChangeKind::Added => {
            let branch = BranchId::for_height(network, wallet.tip().block_height());
            let tx = match source.get_raw_transaction(branch, txid).await {
                Ok(Some(tx)) => tx,
                Ok(None) => {
                    tracing::debug!(%txid, "mempool transaction gone before the fetch");
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, %txid, "mempool transaction not fetched");
                    return;
                }
            };
            if spends_transparent(&tx) {
                return;
            }
            let tip = wallet.tip().block_height();
            let payments = zns_mint::mint::note::decrypt_treasury_transaction(
                network,
                &tx,
                tip,
                treasury_keys,
            );
            let requests: Vec<(Request, Zatoshis)> = payments
                .iter()
                .filter_map(|(paid, memo)| match MintInbound::decode(network, memo) {
                    MintInbound::Request(request) => Some((request, *paid)),
                    _ => None,
                })
                .collect();
            let target = tip + 1;
            let Some(request) = zero_conf_candidate(
                true,
                requests.iter().map(|(request, _)| request),
                |request| {
                    let paid = requests
                        .iter()
                        .find(|(candidate, _)| candidate == request)
                        .map(|(_, paid)| *paid)
                        .expect("the candidate is one of this transaction's requests");
                    !challenges.mempool_blocked(request)
                        && market.allows_transition(request.name())
                        && registry
                            .authorize_challenge(name_notes, request, target, mtp)
                            .is_some()
                        && covers_challenge_fee(fee_rule, paid)
                },
            )
            .cloned() else {
                return;
            };
            let Some(record) = registry.authorize_challenge(name_notes, &request, target, mtp)
            else {
                return;
            };
            if !challenges.admit_unmined(request.clone(), txid, mtp) {
                return;
            }
            let Some(pending) = challenges
                .requested()
                .into_iter()
                .find(|pending| pending.request == request)
            else {
                return;
            };
            if relay(
                network,
                wallet,
                treasury_keys,
                spend_prover,
                output_prover,
                fee_rule,
                &record.ua,
                source,
                &pending,
                "mempool",
            )
            .await
            {
                challenges.challenge_issued(&pending);
            }
        }
    }
}
