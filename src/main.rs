//! The Zcash Name Service attested Mint.
//!
//! Boot establishes identity, syncs from the birthday checkpoint to the
//! chain tip, and verifies genesis (40 anchors, minimum Treasury balance).
//! `main` is then a pure run loop: it follows Zebra's canonical chain,
//! scans each new block, enforces the Registry transition law, services
//! Treasury memos (paid claims, update and release requests, OTP echoes),
//! runs the lifecycle (expiry releases and liveness challenges), and
//! sweeps the Treasury. The mint authors no genesis state: the anchor
//! pool is created once by the keygen ceremony and replenishes itself
//! through every claim.

use std::time::Duration;

use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::{WalletRead as _, WalletWrite as _};
use zcash_primitives::transaction::fees::zip317::MINIMUM_FEE;
use zcash_protocol::consensus::BlockHeight;

use zns_mint::boot::Boot;
use zns_mint::mint::note::assemble;
use zns_mint::mint::note::NameNoteQueue;
use zns_mint::mint::otp::{OtpCode, OtpQueue, OtpRequest, D_OTP};
use zns_mint::mint::pricing::fetch_round;
use zns_mint::mint::registry::NameRecord;
use zns_mint::mint::treasury::{self, RequestQueue};
use zns_mint::mint::{
    Action, Challenge, Expiry, MintInbound, Request, CHALLENGE_LEAD, LIVENESS_RETRY_COOLDOWN,
    REGISTRY_ACCOUNT, TREASURY_ACCOUNT,
};
use zns_mint::zcash::{CanonicalBlockSource, JsonRpc, TipSession};

const RETRY_PAUSE: Duration = Duration::from_secs(5);

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
    let mut connection = TipSession::open(chain).await;
    loop {
        let (best_height, best_hash) = match connection.next_tip(&source).await {
            Ok(tip) => tip,
            Err(error) => panic!("FATAL: Zebra returned an invalid canonical tip: {error}"),
        };
        wallet
            .update_chain_tip(best_height)
            .expect("FATAL: wallet rejected Zebra's canonical tip");

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
                match rpc.get_block_hash(ancestor).await {
                    Ok(hash) => break hash,
                    Err(error) if error.is_retryable() => {
                        tracing::warn!(
                            %error,
                            height = u32::from(ancestor),
                            "ancestor hash unavailable; retrying"
                        );
                        tokio::time::sleep(RETRY_PAUSE).await;
                    }
                    Err(error) => {
                        panic!("FATAL: Zebra returned an invalid ancestor hash: {error}")
                    }
                }
            };
            if wallet_hash == Some(canonical_hash) {
                break;
            }
            ancestor = BlockHeight::from_u32(u32::from(ancestor) - 1);
        }

        if ancestor < chain_tip.block_height() {
            registry.truncate_to_height(ancestor);
            chain_tip = wallet
                .truncate_to(ancestor)
                .expect("FATAL: wallet could not rewind to the common ancestor");

            // Rebuild the entire MTP window at the ancestor. Retaining a
            // partial old window and appending the same heights again would
            // mix histories after a deep reorg.
            mtp = zns_mint::mint::mtp::MtpTracker::default();
            mtp.backfill(ancestor, |height| {
                let rpc = rpc.clone();
                async move {
                    let (_, _, timestamp) = rpc.get_block_header(height).await?;
                    Ok::<_, zns_mint::zcash::TransportError>(
                        u32::try_from(timestamp.as_seconds())
                            .expect("Zcash header timestamps fit u32"),
                    )
                }
            })
            .await
            .expect("FATAL: MTP reconstruction after reorg failed");
            challenges = OtpQueue::new();
            name_notes.truncate_to(ancestor);
            requests.truncate_to(ancestor);
            tracing::warn!(
                height = u32::from(ancestor),
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
                match rpc.chain_state_at(from_height).await {
                    Ok(state) => break state,
                    Err(error) if error.is_retryable() => {
                        tracing::warn!(
                            %error,
                            height = u32::from(from_height),
                            "previous chain state unavailable; retrying"
                        );
                        tokio::time::sleep(RETRY_PAUSE).await;
                    }
                    Err(error) => {
                        panic!("FATAL: Zebra returned an invalid previous chain state: {error}")
                    }
                }
            };

            let block = loop {
                match rpc.get_block(&network, next_height).await {
                    Ok(block) => break block,
                    Err(error) if error.is_retryable() => {
                        tracing::warn!(
                            %error,
                            height = u32::from(next_height),
                            "canonical block unavailable; retrying"
                        );
                        tokio::time::sleep(RETRY_PAUSE).await;
                    }
                    Err(error) => {
                        panic!("FATAL: Zebra returned an invalid canonical block: {error}")
                    }
                }
            };
            if next_height == best_height {
                assert_eq!(
                    block.header().hash(),
                    best_hash,
                    "FATAL: fetched terminal block does not match Zebra's exact tip"
                );
            }

            zns_mint::mint::apply_block(
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
                &mut requests,
                &mut name_notes,
            );
        }

        assert_eq!(chain_tip.block_height(), best_height);
        assert_eq!(chain_tip.block_hash(), best_hash);
        tracing::info!(height = u32::from(best_height), "scanned to tip");
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
        let exact_tip = loop {
            match source.exact_tip().await {
                Ok(tip) => break tip,
                Err(error) if error.is_retryable() => {
                    tracing::warn!(%error, "post-price tip check unavailable; retrying");
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
                Err(error) => panic!("FATAL: Zebra returned an invalid tip: {error}"),
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
            .expect("FATAL: Zebra tip not recorded before gauge")
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
            let (inbound, paid, note_height) = requests.entry(index);
            let decided = 'lane: {
                match inbound {
                    MintInbound::Unrecognized(txid) => {
                        tracing::info!(
                            txid = %txid,
                            value_zec = paid.into_u64() as f64 / 1e8,
                            height = u32::from(note_height),
                            "treasury received non-request payment"
                        );
                        break 'lane true;
                    }
                    MintInbound::Echo(echo) => {
                        // The echo lane: an OTP response. Decided in every outcome —
                        // an echo never waits for money; the renewal or
                        // upgrade fee declines on shortfall, it does not defer.
                        let Some(record) = registry.record(&echo.name).cloned() else {
                            break 'lane true; // no record: no mint-issued challenge can match
                        };
                        if record.action.is_release() {
                            break 'lane true;
                        }
                        let Some(sent) = challenges.awaiting(echo, mtp_now) else {
                            break 'lane true; // no pending challenge: dead
                        };
                        // The renewal or upgrade fee, binding at first
                        // sight: a shortfall voids the attempt and never
                        // consumes — the challenge stands, retryable with
                        // the same OTP inside D_OTP.
                        if let Some(term) = sent.term {
                            if paid < oracle.quote(&echo.name, term) {
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
                        // The clone preserves the challenge if authorize
                        // declines after consuming it — a term whose
                        // extension overflows.
                        let mut authorized_challenges = challenges.clone();
                        let Some(transition_note) = registry.authorize(
                            &mut authorized_challenges,
                            authorized,
                            Some(&digits),
                            note_height,
                            mtp_now,
                        ) else {
                            break 'lane true;
                        };
                        challenges = authorized_challenges;
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
                    }
                    MintInbound::Request(Request::Claim {
                        name,
                        ua,
                        term,
                        code,
                    }) => {
                        // One open claim per name: the Registry lags the
                        // mempool by a block; the queue does not. A rival
                        // payment stays Treasury income.
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
                            today,
                            zns_mint::mint::presale::lookup_name(name).await,
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
                        let price = oracle.quote(name, *term);
                        // Payment gate: the quote at first sight is binding.
                        // An underpaid claim is dead and silent; a new
                        // payment settles a new evaluation.
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
                    MintInbound::Request(
                        request @ (Request::Update { .. } | Request::Release { .. }),
                    ) => {
                        // The relay lane: the mint challenges the controller.
                        // The two ways money can refuse — no fee funds,
                        // node rejection — defer; everything else is
                        // decided.
                        let (name, action, requested_ua, term) = match request {
                            Request::Update { name, ua, term } => {
                                (name.clone(), Action::Update, ua.clone(), *term)
                            }
                            Request::Release { name, ua } => {
                                (name.clone(), Action::Release, ua.clone(), None)
                            }
                            Request::Claim { .. } => unreachable!("claims are routed above"),
                        };
                        let Some(record) = registry.record(&name).cloned() else {
                            tracing::debug!(
                                name = %name.as_str(),
                                "request for an unregistered name"
                            );
                            // Deferral would be attacker-bought memory: the
                            // payer re-requests once the claim lands.
                            break 'lane true;
                        };
                        if record.action.is_release()
                            || record.expires_at.expired(mtp_now)
                            || note_height <= record.confirmed_height
                            || (action.is_release() && requested_ua != record.ua)
                            // A forever name has no runway to bank and no
                            // second upgrade to buy; refuse any term at the
                            // relay, before a challenge spends anything.
                            || (record.expires_at == Expiry::Never && term.is_some())
                            || challenges.pending(
                                &name,
                                action,
                                &requested_ua,
                                record.commitment,
                                mtp_now,
                            )
                        {
                            break 'lane true;
                        }

                        let code = OtpCode::generate();
                        let challenge = Challenge {
                            code: code.clone(),
                            name: name.clone(),
                            action,
                            ua: requested_ua.clone(),
                        };
                        let Some(memo) = challenge.encode(&network) else {
                            break 'lane true;
                        };
                        let relay_value = MINIMUM_FEE;
                        let Some(transaction) = treasury::challenge(
                            &network,
                            &mut wallet,
                            &treasury_keys,
                            &sapling_spend,
                            &sapling_output,
                            &record.ua,
                            memo,
                            relay_value,
                        ) else {
                            tracing::debug!(
                                name = %name.as_str(),
                                action = action.as_str(),
                                "controller challenge awaits Treasury funds"
                            );
                            break 'lane false; // deferred
                        };

                        let pending = OtpRequest {
                            name: name.clone(),
                            action,
                            ua: requested_ua,
                            tip_rcm: record.commitment,
                            code,
                            expires_at: mtp_now + time::Duration::seconds(D_OTP),
                            term,
                        };
                        if source.submit(&transaction, "controller challenge").await {
                            challenges.issue(pending);
                            tracing::info!(
                                txid = %transaction.txid(),
                                name = %name.as_str(),
                                action = action.as_str(),
                                "controller challenged"
                            );
                            true
                        } else {
                            tracing::debug!(
                                name = %name.as_str(),
                                action = action.as_str(),
                                "controller challenge rejected — deferred"
                            );
                            false
                        }
                    }
                }
            };
            if decided {
                requests.remove(index);
            } else {
                index += 1;
            }
        }

        // Lifecycle releases, §4.5: the registry owns the clocks and
        // their plural; the sweep drains the batch each tip.
        // `releases_due` re-derives the same notes per tip, so
        // admission is idempotent.
        for (name, release_note) in registry.releases_due(mtp_now) {
            tracing::info!(name = %name.as_str(), "lifecycle release authorized");
            name_notes.admit(tip, release_note);
        }

        // Liveness lead, §4.5.4: during the final OTP window the mint
        // challenges the current controller to renew liveness. The
        // snapshot stays — the lead loop needs each record.
        let records = registry
            .name_chain()
            .map(|(name, record)| (name.clone(), record.clone()))
            .collect::<Vec<(zns_mint::mint::Name, NameRecord)>>();
        for (name, record) in records {
            if record.action.is_release() {
                continue;
            }

            // Liveness lead: while `mtp_now` is within CHALLENGE_LEAD of the
            // deadline, ask the current controller to prove control. Skip if
            // an OTP is still in play OR the same record was challenged
            // inside its cooldown. Both are anti-spam bounds; without them a
            // 7-day lead would issue up to ~336 challenges per name.
            //
            // Liveness is a mint-originated Relay, not a WP §5 Request →
            // Relay → Respond authorization: the mint hasn't been asked
            // anything, it is reminding the controller a deadline is near.
            // Liveness is only *satisfied* when a fresh update Name Note
            // lands (a real §5 flow the controller initiates), which resets
            // `release_deadline` via `NameRecord::from_received`.
            //
            // The `liveness_issued` ledger lives in `OtpQueue`, which resets
            // on restart and on any reorg (both call `OtpQueue::new()`), so
            // a re-challenge inside the cooldown can occur after either.
            // Harmless — an extra reminder to a live controller — but worth
            // knowing when reading the logs.
            let due_in = record.release_deadline.as_seconds() - mtp_now.as_seconds();
            let cooldown = time::Duration::seconds(LIVENESS_RETRY_COOLDOWN);
            if due_in > CHALLENGE_LEAD
                || challenges.pending(
                    &name,
                    Action::Update,
                    &record.ua,
                    record.commitment,
                    mtp_now,
                )
                || challenges.liveness_recently_issued(&name, record.commitment, mtp_now, cooldown)
            {
                continue;
            }

            let code = OtpCode::generate();
            let challenge = Challenge {
                code: code.clone(),
                name: name.clone(),
                action: Action::Update,
                ua: record.ua.clone(),
            };
            let memo = challenge
                .encode(&network)
                .expect("liveness challenges are always encodable");
            let relay_value = MINIMUM_FEE;
            let Some(transaction) = treasury::challenge(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
                &record.ua,
                memo,
                relay_value,
            ) else {
                tracing::debug!(
                    name = %name.as_str(),
                    "liveness challenge awaits Treasury funds"
                );
                continue;
            };

            let pending = OtpRequest {
                name: name.clone(),
                action: Action::Update,
                ua: record.ua.clone(),
                tip_rcm: record.commitment,
                code,
                expires_at: mtp_now + time::Duration::seconds(D_OTP),
                term: None,
            };
            let accepted = source.submit(&transaction, "liveness challenge").await;
            if accepted {
                challenges.issue(pending);
                challenges.mark_liveness_issued(name.clone(), record.commitment, mtp_now);
                tracing::info!(
                    txid = %transaction.txid(),
                    name = %name.as_str(),
                    "liveness challenge submitted"
                );
            }
        }

        // --- NameNote enactment ---
        // One assembly and submission path for every authorized Name
        // Note. The wallet's spent marks hold a sent order's inputs until
        // its expiry height, so nothing is re-enactable before then.
        for (note, origin) in name_notes.iter().map(|(n, o)| (n.clone(), o)) {
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
                        "claim order waits: the name is live on the chain"
                    );
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
                            "order waits: its predecessor is no longer current"
                        );
                        continue;
                    }
                }
            };

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
                continue;
            };

            if source.submit(&transaction, "NameNote").await {
                tracing::info!(
                    txid = %transaction.txid(),
                    name = %note.name().as_str(),
                    action = note.action().as_str(),
                    "NameNote order in flight"
                );
            } else {
                tracing::error!(
                    txid = %transaction.txid(),
                    name = %note.name().as_str(),
                    action = note.action().as_str(),
                    "NameNote submission rejected — inputs stranded until expiry"
                );
            }
        }

        if let Some(tx) = treasury::sweep_to_vault(
            &network,
            &mut wallet,
            &treasury_keys,
            &sapling_spend,
            &sapling_output,
            today,
            previous_day,
        ) {
            source.submit(&tx, "vault sweep").await;
        }

        tracing::debug!(
            height = u32::from(tip),
            hash = %tip_hash,
            "mint rules applied at canonical tip"
        );
    }
}
