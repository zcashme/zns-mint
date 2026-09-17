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

use std::convert::Infallible;
use std::time::Duration;

use futures_util::StreamExt as _;
use incrementalmerkletree::Position;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletWrite as _;
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_client_backend::scanning::Nullifiers;
use zcash_protocol::consensus::BlockHeight;

use zns_mint::boot::Boot;
use zns_mint::mint::note::assemble;
use zns_mint::mint::note::NameNoteQueue;
use zns_mint::mint::otp::{required_relay_value, OtpCode, OtpQueue, OtpRequest, D_OTP};
use zns_mint::mint::registry::{NameRecord, ReceivedNameNote};
use zns_mint::mint::treasury::{self, parse_request, RequestQueue};
use zns_mint::mint::{
    Action, Challenge, Request, CHALLENGE_LEAD, LIVENESS_RETRY_COOLDOWN, MINT_BIRTHDAY,
    REGISTRY_ACCOUNT, TREASURY_ACCOUNT,
};
use zns_mint::zcash::{self, CanonicalBlockSource, ChainClient, JsonRpc, TipStream};

const RETRY_PAUSE: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let Boot {
        network,
        mut chain,
        mut wallet,
        cursor: mut chain_tip,
        treasury_keys,
        registry_keys,
        sapling_spend,
        sapling_output,
        mut mtp,
        mut oracle,
        mut challenges,
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

    let mut tips = tip_stream(&mut chain).await;
    loop {
        let notification = match tips.next().await {
            Some(Ok(notification)) => notification,
            Some(Err(error)) => {
                tracing::warn!(%error, "Zebra tip stream failed; reconnecting");
                tips = tip_stream(&mut chain).await;
                continue;
            }
            None => {
                tracing::warn!("Zebra tip stream ended; reconnecting");
                tips = tip_stream(&mut chain).await;
                continue;
            }
        };
        let (announced_height, announced_hash) = zcash::tip_height_hash(&notification);
        tracing::info!(
            height = u32::from(announced_height),
            "tip notification received"
        );
        let (best_height, best_hash) = loop {
            match source.exact_tip().await {
                Ok(tip) => break tip,
                Err(error) if error.is_retryable() => {
                    tracing::warn!(%error, "exact Zebra tip unavailable; retrying");
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
                Err(error) => panic!("FATAL: Zebra returned an invalid canonical tip: {error}"),
            }
        };
        if announced_height != best_height || announced_hash != best_hash {
            tracing::debug!(
                announced_height = u32::from(announced_height),
                announced_hash = %announced_hash,
                best_height = u32::from(best_height),
                best_hash = %best_hash,
                "coalesced Zebra tip notification"
            );
        }
        assert!(
            best_height >= MINT_BIRTHDAY - 1,
            "FATAL: Zebra tip is below the mint birthday"
        );
        wallet
            .update_chain_tip(best_height)
            .expect("FATAL: wallet rejected Zebra's canonical tip");

        // Compare the wallet's own cursor with Zebra at the same height.
        // If they disagree, walk backward until both name the same block;
        // no state above that common ancestor survives.
        let mut ancestor = chain_tip.block_height().min(best_height);
        loop {
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
            if wallet.block_hash_at(ancestor) == Some(canonical_hash) {
                break;
            }
            if ancestor == MINT_BIRTHDAY - 1 {
                panic!("FATAL: canonical fork crossed the mint birthday");
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

        // Apply every missing canonical block in strict order. All derived
        // state is prepared first; the wallet commit is the irreversible
        // boundary; Registry, MTP, and the cursor are installed afterward.
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
            assert_eq!(
                from_state.block_height(),
                from_height,
                "FATAL: previous chain-state height mismatch"
            );
            assert_eq!(
                from_state.block_hash(),
                chain_tip.block_hash(),
                "FATAL: previous chain state does not describe the applied cursor"
            );

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
            assert_eq!(
                block.header().prev_block,
                chain_tip.block_hash(),
                "FATAL: fetched block does not continue the applied cursor"
            );
            if next_height == best_height {
                assert_eq!(
                    block.header().hash(),
                    best_hash,
                    "FATAL: fetched terminal block does not match Zebra's exact tip"
                );
            }

            let block_time = block.header().time;
            let candidates = zns_mint::mint::decrypt_name_notes(&network, &block, &registry_keys);
            let treasury_memos =
                zns_mint::mint::note::decrypt_treasury_memos(&block, &treasury_keys);
            let received_name_notes = candidates
                .iter()
                .map(|candidate| {
                    ReceivedNameNote::new(
                        candidate.txid,
                        candidate.action_index,
                        candidate.nullifier,
                        candidate.payload.clone(),
                    )
                })
                .collect::<Vec<_>>();

            let (header, batches) = decrypt_block(&network, block, wallet.scanning_keys());
            let nullifiers = Nullifiers::unspent(&wallet)
                .expect("FATAL: wallet could not expose its unspent nullifiers");
            let scanned = scan_block(
                &network,
                next_height,
                &header,
                batches,
                wallet.scanning_keys(),
                &nullifiers,
                Some(&chain_tip),
                |_| {
                    Ok::<
                        Option<(
                            zip32::AccountId,
                            Option<transparent::keys::TransparentKeyScope>,
                        )>,
                        Infallible,
                    >(None)
                },
            )
            .expect("FATAL: a canonical block failed deterministic wallet scanning");

            let mut next_mtp = mtp.clone();
            next_mtp.update(next_height, block_time);
            let block_mtp = next_mtp
                .current()
                .expect("FATAL: MTP unavailable after applying a block");

            let (next_registry, accepted_name_notes) =
                registry.apply_block(&network, &scanned, &received_name_notes, block_mtp);

            let ironwood_start = scanned
                .ironwood()
                .final_tree_size()
                .checked_sub(
                    u32::try_from(scanned.ironwood().commitments().len())
                        .expect("Ironwood block action count fits u32"),
                )
                .expect("FATAL: scanner returned an impossible Ironwood tree size");
            let accepted_name_notes = accepted_name_notes
                .into_iter()
                .map(|index| {
                    let candidate = &candidates[index];
                    let position = Position::from(
                        u64::from(ironwood_start)
                            + u64::try_from(candidate.ordinal).expect("Name Note ordinal fits u64"),
                    );
                    (index, position)
                })
                .collect::<Vec<_>>();
            let next_metadata = scanned.to_block_metadata();

            wallet
                .put_blocks(&from_state, vec![scanned])
                .expect("FATAL: wallet block commit failed");
            // Upstream's ScannedBlock drops note plaintexts; the Treasury
            // lane's memos were decrypted above. Decoded once, here, they
            // are recorded as the requests they carry — nothing is stored
            // for later re-reading; the block is the durable source,
            // refetched on every application. Boot never runs this:
            // arrivals from history are balance, not instruction.
            for (txid, _action_index, paid, memo) in treasury_memos {
                match parse_request(&network, &memo) {
                    Some(request) => requests.record(request, paid, next_height),
                    None => tracing::info!(
                        txid = %txid,
                        value_zec = paid.into_u64() as f64 / 1e8,
                        height = u32::from(next_height),
                        "treasury received non-request payment"
                    ),
                }
            }
            for (index, position) in accepted_name_notes {
                let candidate = &candidates[index];
                wallet.store_name_note(
                    next_height,
                    position,
                    candidate.txid,
                    candidate.action_index,
                    candidate.note,
                    candidate.nullifier,
                    candidate.ephemeral_key.clone(),
                    candidate.memo,
                );
                // The block fulfilled the order.
                name_notes.fulfill(&candidate.payload);
            }
            mtp = next_mtp;
            registry = next_registry;
            chain_tip = next_metadata;

            tracing::debug!(
                height = u32::from(next_height),
                hash = %chain_tip.block_hash(),
                "canonical block applied"
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

        oracle.accumulate(zns_mint::mint::pricing::fetch_round().await, mtp_now);
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
            continue;
        }

        // The three gauges: chain level, money level, price level.
        let treasury_zats: u64 = wallet
            .unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip))
            .iter()
            .map(|n| n.note().value().inner())
            .chain(
                wallet
                    .unspent_sapling_notes(TREASURY_ACCOUNT, TargetHeight::from(tip))
                    .iter()
                    .map(|n| n.note().value().inner()),
            )
            .sum();
        zns_mint::metrics::snapshot(tip, treasury_zats, oracle.current().into_u64());

        // Treasury requests. Each memo was decoded once, at block
        // application; the drain decides each entry exactly once. A
        // decided entry leaves the queue; a deferred relay — Treasury
        // fee funds missing, or the node rejected the challenge — waits
        // for the next tip. Nothing is re-read.
        let mut index = 0;
        while index < requests.len() {
            let (request, paid, note_height) = requests.entry(index);
            let decided = 'lane: {
                match (request.action, request.otp) {
                    (Action::Claim, Some(_)) => break 'lane true, // malformed: dead
                    (Action::Update | Action::Release, Some(otp)) => {
                        // The echo lane: an OTP response. Decided in every
                        // outcome — an echo never waits for money.
                        let Some(record) = registry.record(&request.name).cloned() else {
                            break 'lane true; // no record: no mint-issued challenge can match
                        };
                        if record.action == Action::Release {
                            break 'lane true;
                        }
                        let Some(code) = OtpCode::from_digits(&otp) else {
                            break 'lane true;
                        };
                        let challenge = Challenge {
                            code,
                            name: request.name.clone(),
                            action: request.action,
                            ua: request.ua.clone(),
                        };
                        let Some(sent) = challenges.awaiting(&challenge, mtp_now) else {
                            break 'lane true; // no pending challenge: dead
                        };
                        let digits = sent.code.digits();
                        let authorized = match request.action {
                            Action::Update => Request::Update {
                                name: request.name.clone(),
                                ua: request.ua.clone(),
                                term: sent.term,
                            },
                            Action::Release => Request::Release {
                                name: request.name.clone(),
                                ua: request.ua.clone(),
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
                        name_notes.admit(note_height, transition_note);
                        true
                    }

                    (Action::Claim, None) => {
                        let name = request.name.clone();
                        let ua = request.ua.clone();
                        let term = request.term;
                        // One open claim per name: the Registry lags the
                        // mempool by a block; the queue does not. A rival
                        // payment stays Treasury income.
                        if name_notes.claim_pending(&name) {
                            tracing::debug!(
                                name = %name.as_str(),
                                "claim already pending for this name"
                            );
                            break 'lane true;
                        }
                        let price = oracle.quote_forever(&name);
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
                                ua,
                                term,
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

                    (Action::Update | Action::Release, None) => {
                        // The relay lane: the mint challenges the controller.
                        // The two ways money can refuse — no fee funds,
                        // node rejection — defer; everything else is
                        // decided.
                        let name = request.name.clone();
                        let action = request.action;
                        let requested_ua = request.ua.clone();
                        let term = request.term;
                        let Some(record) = registry.record(&name).cloned() else {
                            tracing::debug!(
                                name = %name.as_str(),
                                "request for an unregistered name"
                            );
                            // Deferral would be attacker-bought memory: the
                            // payer re-requests once the claim lands.
                            break 'lane true;
                        };
                        if record.action == Action::Release
                            || record.expires_at.expired(mtp_now)
                            || note_height <= record.confirmed_height
                            || (action == Action::Release && requested_ua != record.ua)
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
                        let relay_value = required_relay_value(&network, target_height);
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

        // Lifecycle. Expiry or a missed liveness deadline releases the
        // current Name Note without an OTP. During the final OTP window,
        // the mint challenges the current controller to renew liveness.
        let records = registry
            .name_chain()
            .map(|(name, record)| (name.clone(), record.clone()))
            .collect::<Vec<(zns_mint::mint::Name, NameRecord)>>();
        for (name, record) in records {
            if record.action == Action::Release {
                continue;
            }

            if let Some((release_note, reason)) = registry.release_due(&name, mtp_now) {
                // The deadline clock authorized a release; `release_due`
                // re-derives the same note each tip, so admission is
                // idempotent.
                tracing::debug!(
                    name = %name.as_str(),
                    reason = reason.as_str(),
                    "lifecycle release authorized"
                );
                name_notes.admit(tip, release_note);
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
            let relay_value = required_relay_value(&network, target_height);
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
            let authority_nf = match note.action() {
                Action::Claim => {
                    // The name must still be claimable: free, or released
                    // after the payment arrived.
                    let claimable = match registry.record(note.name()) {
                        None => true,
                        Some(record) => {
                            record.action == Action::Release && origin > record.confirmed_height
                        }
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
                }
                Action::Update | Action::Release => {
                    match registry
                        .record(note.name())
                        .filter(|record| {
                            record.action != Action::Release
                                && Some(record.commitment) == note.prev_rcm()
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

/// Opens the tip stream, retrying until Zebra answers.
async fn tip_stream(chain: &mut ChainClient) -> TipStream {
    loop {
        match chain.chain_tip_change_stream().await {
            Ok(tips) => return tips,
            Err(error) => {
                tracing::warn!(%error, "Zebra tip stream unavailable; reconnecting");
                tokio::time::sleep(RETRY_PAUSE).await;
            }
        }
    }
}
