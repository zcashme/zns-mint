//! The Zcash Name Service attested Mint.
//!
//! Boot establishes identity, syncs from the wallet origin checkpoint to the
//! chain tip, and verifies genesis (ceremony adoption closed, minimum Treasury balance).
//! `main` is then a pure run loop: it follows Zebra's canonical chain,
//! scans each new block, enforces the Registry transition law, services
//! Treasury memos (paid claims, update and release requests, OTP echoes),
//! runs the lifecycle (expiry releases), and
//! sweeps the Treasury. The mint authors no genesis state: the anchor
//! pool is created once by the keygen ceremony and replenishes itself
//! through every claim.

use zcash_client_backend::data_api::WalletRead as _;
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use zns_mint::boot::Boot;
use zns_mint::mint::note::assemble;
use zns_mint::mint::presale;
use zns_mint::mint::pricing::fetch_round;
use zns_mint::mint::treasury;
use zns_mint::mint::treasury::{OtpChallenge, OtpQueue, RefundQueue};
use zns_mint::mint::{relay, Action, MintInbound, Request, TREASURY_ACCOUNT};
use zns_mint::zcash::{TipSession, TransportError, RETRY_PAUSE};

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
        mut echoes,
        treasury_address,
        registry_ufvk,
        seed_fingerprint,
        capsule_hash,
        guest,
    } = Boot::start().await;

    zns_mint::metrics::install();
    zns_mint::metrics::identity(&treasury_address, &registry_ufvk);
    zns_mint::metrics::ceremony(&seed_fingerprint, &capsule_hash);
    if let Some(guest) = &guest {
        zns_mint::metrics::guest(&guest.measurement, &guest.guest_policy);
    }
    tracing::info!(
        height = u32::from(wallet.tip().block_height()),
        hash = %wallet.tip().block_hash(),
        "mint awaiting Zebra tips"
    );

    // The tip session owns the stream: announcements are the answer,
    // failures repair and read the canonical tip. The loop never sees
    // transport state.
    let mut connection = TipSession::open(chain).await;
    // Refunds not yet built live here. A restart forgets them, as it
    // forgets an unsent challenge; boot does not re-decide historical
    // payments.
    let mut refunds = RefundQueue::new();
    'run: loop {
        // Every pass ends here, however it ended: the names the queues
        // still hold are in flight until the next tip.
        zns_mint::metrics::requests_in_flight(
            requests
                .names()
                .chain(challenges.unrelayed())
                .chain(echoes.iter().map(|(_, echo, _, _)| &echo.name))
                .chain(name_notes.authorized_names()),
            challenges.relayed(),
        );
        let (best_height, _) = connection.next_tip(&source).await.unwrap_or_else(|error| {
            panic!("FATAL: Zebra returned an invalid canonical tip: {error}")
        });
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
                    Ok::<_, zns_mint::zcash::TransportError>(
                        u32::try_from(timestamp.as_seconds())
                            .expect("Zcash header timestamps fit u32"),
                    )
                }
            })
            .await
            .expect("FATAL: MTP reconstruction after reorg failed");
            challenges = OtpQueue::new();
            name_notes.rewind_to(rewound);
            name_notes.reconcile_seen(&network, &registry);
            requests.truncate_to(rewound);
            refunds.truncate_to(rewound);
            echoes.retain(|(_, _, _, height)| *height <= rewound);
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

            let arrivals = zns_mint::mint::apply_block(
                &network,
                birthday,
                &registry_keys,
                &treasury_keys,
                &from_state,
                block,
                next_height,
                &mut wallet,
                &mut registry,
                &mut mtp,
            );
            name_notes.reconcile_seen(&network, &registry);
            for (txid, inbound, paid) in arrivals {
                match inbound {
                    MintInbound::Request(request) => {
                        requests.record(txid, request, paid, next_height);
                    }
                    MintInbound::Echo(echo) => {
                        echoes.push((txid, echo, paid, next_height));
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
        challenges.prune(mtp_now);

        let today = mtp
            .current_day()
            .expect("FATAL: MTP unavailable at the applied tip");
        // The tip check below covers the price round and the pre-sale
        // read alike. Only the read's unspent timeout can delay the pass.
        let (round, ()) = tokio::join!(fetch_round(), presale_read.install(&mut protected_names));
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

        // Treasury requests. Each memo was decoded once, at block
        // application; the deciding pass resolves each pending entry
        // exactly once, in queue order. A resolved entry leaves the
        // queue — refused by a gate, or handed to the queue that owns
        // its retries. Nothing defers; nothing is re-read.
        for (txid, request, paid, note_height) in requests.pending() {
            let resolved = 'lane: {
                match &request {
                    Request::Claim {
                        name,
                        ua,
                        term,
                        code,
                    } => {
                        // The earliest payment owns the name until its claim
                        // is observed. A later payment does not start a
                        // second Name Note.
                        // Early-access regime: only a listed name may claim,
                        // and only with its per-name access code. No code,
                        // or a name that is not listed, keeps the payment.
                        // A wrong code keeps 1% of the quote, then the fee.
                        let Some(offered) = code.as_ref() else {
                            tracing::debug!(
                                name = %name.as_str(),
                                "pre-sale claim refused: no access code"
                            );
                            break 'lane true;
                        };
                        if !protected_names.is_protected(name, mtp_now) {
                            tracing::debug!(
                                name = %name.as_str(),
                                "pre-sale claim refused: name not listed"
                            );
                            break 'lane true;
                        }
                        if !access_code_key.accepts(name, Some(offered)) {
                            let Some(price) = oracle.quote(name, *term) else {
                                tracing::debug!(
                                    name = %name.as_str(),
                                    "wrong access code; quote does not fit"
                                );
                                break 'lane true;
                            };
                            refunds.admit(
                                &fee_rule,
                                txid,
                                ua,
                                name,
                                note_height,
                                paid,
                                treasury::access_code_penalty(price),
                                "wrong access code",
                            );
                            break 'lane true;
                        }
                        // Payment gate: the quote at first sight is binding.
                        // A payment below the quote goes back to the memo
                        // address, less the refund fee.
                        // A quote that does not fit is dead. A new payment
                        // settles a new evaluation.
                        let Some(price) = oracle.quote(name, *term) else {
                            break 'lane true;
                        };
                        if paid < price {
                            refunds.admit(
                                &fee_rule,
                                txid,
                                ua,
                                name,
                                note_height,
                                paid,
                                Zatoshis::ZERO,
                                "underpaid",
                            );
                            break 'lane true;
                        }
                        // A name that already has a record, or a Name Note
                        // already queued, is refunded. Any other refusal
                        // keeps the payment.
                        let Some(claim_note) =
                            registry.authorize_claim(name.clone(), ua.clone(), *term, mtp_now)
                        else {
                            if !registry.is_available(name) {
                                refunds.admit(
                                    &fee_rule,
                                    txid,
                                    ua,
                                    name,
                                    note_height,
                                    paid,
                                    Zatoshis::ZERO,
                                    "registered name",
                                );
                            } else {
                                tracing::debug!(
                                    name = %name.as_str(),
                                    "claim not authorized"
                                );
                            }
                            break 'lane true;
                        };
                        // Enactment below resolves the anchor and broadcasts.
                        if !name_notes.admit(note_height, claim_note) {
                            refunds.admit(
                                &fee_rule,
                                txid,
                                ua,
                                name,
                                note_height,
                                paid,
                                Zatoshis::ZERO,
                                "queued name",
                            );
                        }
                        true
                    }
                    request @ (Request::Update { .. } | Request::Release { .. }) => {
                        let (name, action, requested_ua, term) = match request {
                            Request::Update { name, ua, term } => (name, Action::Update, ua, *term),
                            Request::Release { name, ua } => (name, Action::Release, ua, None),
                            Request::Claim { .. } => unreachable!(),
                        };
                        let Some(record) = registry.authorize_challenge(
                            &name_notes,
                            name,
                            action,
                            requested_ua,
                            term,
                            target_height,
                            mtp_now,
                        ) else {
                            break 'lane true;
                        };
                        if paid < oracle.challenge_fee() {
                            break 'lane true;
                        }
                        let pending = OtpChallenge::issue(
                            name.clone(),
                            action,
                            requested_ua.clone(),
                            record.commitment,
                            term,
                            mtp_now,
                        );
                        challenges.admit(pending, txid);
                        true
                    }
                }
            };
            if resolved {
                requests.resolved(txid);
            }
        }

        // A broadcast order whose expiry height has passed can be signed
        // again, or dropped below once the tip median would release it.
        name_notes.expire_sent(tip);
        // Drop an update the tip median would already release. An echo
        // for that name can then be decided, and a release note can be
        // admitted below. A broadcast still inside its expiry window stays.
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

        // OTP responses are decided before relays. An underpaid renewal is
        // queued for a refund here. A voided OTP response leaves its challenge
        // available.
        for (txid, echo, paid, note_height) in std::mem::take(&mut echoes) {
            let _ = 'lane: {
                // An OTP response is decided on this pass. It never waits
                // for money. A renewal or upgrade below its quote does
                // not consume the challenge.
                let Some(record) = registry.record(&echo.name).cloned() else {
                    break 'lane true; // no record — released or unknown: no mint-issued challenge can match
                };
                let Some(sent) = challenges.answer(&echo, record.commitment) else {
                    break 'lane true; // no match, including a wrong code: payment kept
                };
                if let Some(term) = sent.term {
                    let Some(price) = oracle.quote(&echo.name, term) else {
                        tracing::debug!(
                            name = %echo.name.as_str(),
                            "update quote does not fit — attempt void, challenge stands"
                        );
                        break 'lane true;
                    };
                    if paid < price {
                        refunds.admit(
                            &fee_rule,
                            txid,
                            &echo.ua,
                            &echo.name,
                            note_height,
                            paid,
                            Zatoshis::ZERO,
                            "underpaid",
                        );
                        break 'lane true;
                    }
                }
                // A Name Note already queued owns this name. The payment
                // goes back minus the fee, and the challenge stays.
                if name_notes.note_pending(&echo.name) {
                    refunds.admit(
                        &fee_rule,
                        txid,
                        &echo.ua,
                        &echo.name,
                        note_height,
                        paid,
                        Zatoshis::ZERO,
                        "queued name",
                    );
                    break 'lane true;
                }
                let authorized = match echo.action {
                    Action::Update => registry.authorize_update(&sent, mtp_now),
                    Action::Release => registry.authorize_release(&sent),
                    // Challenges never claim, and `OtpMemo::decode` refuses
                    // the verb; treat a claim echo as a dead memo regardless.
                    Action::Claim => break 'lane true,
                };
                let Some(transition_note) = authorized else {
                    tracing::debug!(
                        name = %echo.name.as_str(),
                        action = echo.action.as_str(),
                        "echo refused by the law — payment kept"
                    );
                    break 'lane true;
                };
                challenges.consume(&sent); // spent exactly when the law accepts
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

        // Queue admission is independent from submission. Retry every
        // requested challenge once during each tip pass.
        for pending in challenges.requested() {
            let Some(record) = registry.authorize_challenge(
                &name_notes,
                &pending.name,
                pending.action,
                &pending.ua,
                pending.term,
                target_height,
                mtp_now,
            ) else {
                continue;
            };
            if record.commitment != pending.tip_rcm {
                continue;
            }
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

        // Lifecycle releases, §4.5: the registry owns the clocks and
        // their plural; each tip admits the release notes.
        // `releases_due` re-derives the same notes per tip, so
        // admission is idempotent.
        for (name, release_note) in registry.releases_due(mtp_now) {
            if name_notes.note_pending(&name) {
                continue;
            }
            tracing::info!(name = %name.as_str(), "lifecycle release authorized");
            name_notes.admit(tip, release_note);
        }

        for note in name_notes.authorized_notes() {
            // Authority: a claim spends a lineage pool anchor; an update
            // or release spends the predecessor — the record's nullifier
            // matched by commitment.
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
                match registry.anchor_pool().iter().next().copied() {
                    Some(nf) => nf,
                    None => {
                        tracing::warn!(
                            name = %note.name().as_str(),
                            "no claim anchor in the pool"
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
                name_notes.mark_sent(note.name(), target_height + DEFAULT_TX_EXPIRY_DELTA);
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
        // Name Note. The wallet owns it from there, like a sweep.
        for tx in treasury::refund(
            &network,
            &mut wallet,
            &treasury_keys,
            &sapling_spend,
            &sapling_output,
            &fee_rule,
            &mut refunds,
        ) {
            source.submit(&tx, "refund").await;
        }

        // A new MTP day sweeps the Treasury to the vault once. What the
        // refunds still owe stays behind.
        if today > previous_day {
            match treasury::sweep_to_vault(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &fee_rule,
                refunds.owed_total(),
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
