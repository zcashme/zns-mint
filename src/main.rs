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
use zcash_client_backend::data_api::{
    NullifierQuery, WalletRead as _, WalletWrite as _,
};
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_client_backend::scanning::Nullifiers;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use zns_mint::boot::Boot;
use zns_mint::mint::note::assemble;
use zns_mint::mint::otp::{required_relay_value, OtpCode, OtpQueue, OtpRequest, D_OTP};
use zns_mint::mint::registry::{NameRecord, ReceivedNameNote};
use zns_mint::mint::treasury;
use zns_mint::mint::{
    Action, Challenge, Request, Term, MINT_BIRTHDAY, REGISTRY_ACCOUNT, TREASURY_ACCOUNT,
};
use zns_mint::zcash::{self, CanonicalBlockSource, ChainClient, JsonRpc, SubmitOutcome, TipStream};

const RETRY_PAUSE: Duration = Duration::from_secs(5);
const CHALLENGE_WINDOW: i64 = D_OTP;

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

    // Notes mined at or before the boot tip are not requests. The
    // Registry rebuilt from Name Notes is the source of truth; whatever
    // the Treasury happened to be holding when the mint went live is
    // balance, not instruction.
    let live_from = chain_tip.block_height();

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
            let name_notes = candidates
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

            // Compute the set of anchor nullifiers from the wallet:
            // unspent zero-value Registry Ironwood notes that are not
            // current Name Notes. The wallet is the source of truth;
            // the Registry only enforces the transition law.
            let name_note_nullifiers: std::collections::BTreeSet<_> =
                registry.name_chain().map(|(_, rec)| rec.nullifier).collect();
            let anchor_nullifiers: std::collections::BTreeSet<orchard::note::Nullifier> = wallet
                .get_ironwood_nullifiers(NullifierQuery::Unspent)
                .expect("FATAL: wallet could not expose its nullifiers")
                .into_iter()
                .filter(|(acct, _)| *acct == REGISTRY_ACCOUNT)
                .filter_map(|(_, nf)| {
                    let note = wallet.unspent_ironwood_note_by_nullifier(
                        REGISTRY_ACCOUNT,
                        nf,
                        TargetHeight::from(next_height),
                    )?;
                    (note.note().value().inner() == 0
                        && !name_note_nullifiers.contains(&nf))
                        .then_some(nf)
                })
                .collect();

            let mut next_mtp = mtp.clone();
            next_mtp.update(next_height, block_time);
            let block_mtp = next_mtp
                .current()
                .expect("FATAL: MTP unavailable after applying a block");

            let (next_registry, accepted_name_notes) =
                registry.apply_block(&network, &scanned, &name_notes, block_mtp, &anchor_nullifiers);

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
            for (index, position) in accepted_name_notes {
                let candidate = &candidates[index];
                wallet.store_name_note(
                    next_height,
                    position,
                    candidate.txid,
                    candidate.action_index,
                    candidate.note.clone(),
                    candidate.nullifier,
                    candidate.ephemeral_key.clone(),
                    candidate.memo,
                );
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
        tracing::info!(
            height = u32::from(best_height),
            "scanned to tip"
        );
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

        // Treasury messages. Each inbound note carries exactly one memo —
        // a paid claim, an update or release request, or an OTP echo — so
        // every note is decoded once and dispatched once. Notes mined
        // before the mint went live are balance, not instruction.
        let mut anchors_exhausted = false;
        for note in wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip)) {
            let Some(note_height) = note.mined_height() else {
                continue;
            };
            if note_height <= live_from {
                continue;
            }
            let memo = wallet
                .get_memo(*note.internal_note_id())
                .expect("FATAL: Treasury memo lookup failed");
            let Some(memo) = memo else { continue };
            let memo = memo.encode();
            let raw = memo.as_array();

            let Some(request) = Request::decode(&network, raw) else {
                // Not a request: an OTP echo, or junk.
                if let Some(challenge) = Challenge::decode(&network, raw) {
                    // OTP echoes return an authorized transition. The
                    // challenge memory is cloned so a rejected submission
                    // leaves the pending request alive for a later echo.
                    let Some(record) = registry.record(&challenge.name).cloned() else {
                        continue;
                    };
                    if record.action == Action::Release {
                        continue;
                    }
                    let Some(sent) = challenges.awaiting(&challenge, mtp_now) else {
                        continue;
                    };
                    let digits = sent.code.digits();
                    let request = match challenge.action {
                        Action::Update => Request::Update {
                            name: challenge.name.clone(),
                            ua: challenge.ua.clone(),
                            extend_years: sent.extend_years,
                        },
                        Action::Release => Request::Release {
                            name: challenge.name.clone(),
                            ua: challenge.ua.clone(),
                        },
                        Action::Claim => continue,
                    };
                    let mut authorized_challenges = challenges.clone();
                    let Some(transition_note) = registry.authorize(
                        &mut authorized_challenges,
                        request,
                        Some(&digits),
                        note_height,
                        mtp_now,
                    )
                    else {
                        continue;
                    };
                    let Some(transaction) = assemble::prepare(
                        &network,
                        &mut wallet,
                        &treasury_keys,
                        &registry_keys,
                        &sapling_spend,
                        &sapling_output,
                        transition_note,
                        record.nullifier,
                        Some(&note),
                        tip,
                        target_height,
                    ) else {
                        tracing::debug!(
                            name = %challenge.name.as_str(),
                            action = challenge.action.as_str(),
                            "authorized transition awaits Treasury fee funds"
                        );
                        continue;
                    };

                    let accepted = loop {
                        match source.send_transaction(&transaction).await {
                            Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => break true,
                            Ok(SubmitOutcome::Rejected(error)) => {
                                tracing::error!(
                                    %error,
                                    txid = %transaction.txid(),
                                    name = %challenge.name.as_str(),
                                    action = challenge.action.as_str(),
                                    "authorized transition rejected"
                                );
                                break false;
                            }
                            Err(error) if error.is_retryable() => {
                                tracing::warn!(
                                    %error,
                                    txid = %transaction.txid(),
                                    "transition submission uncertain; retrying"
                                );
                                tokio::time::sleep(RETRY_PAUSE).await;
                            }
                            Err(error) => {
                                panic!("FATAL: transition submission failed: {error}")
                            }
                        }
                    };
                    if accepted {
                        challenges = authorized_challenges;
                        tracing::info!(
                            txid = %transaction.txid(),
                            name = %challenge.name.as_str(),
                            action = challenge.action.as_str(),
                            "authorized transition submitted"
                        );
                    }
                } else {
                    tracing::debug!(
                        height = u32::from(note_height),
                        "Treasury note carries no decodable ZNS memo"
                    );
                }
                continue;
            };

            match request {
                Request::Claim { name, ua, term } => {
                    // A registration spends one current claim anchor, spends
                    // the inbound payment note, draws the network fee from
                    // separate eligible Treasury notes, and creates both
                    // the Name Note and the next zero-value claim anchor.
                    if anchors_exhausted {
                        continue;
                    }
                    let price = match term {
                        Term::Forever => oracle.quote_forever(&name),
                        Term::Years(years) => Zatoshis::from_u64(
                            oracle
                                .quote_annual(&name)
                                .into_u64()
                                .checked_mul(years)
                                .expect("registration quote fits u64"),
                        )
                        .expect("registration quote fits the Zcash monetary range"),
                    };
                    // Payment gate: the quote is commercial policy — an
                    // underpaid claim is retained and re-checked against
                    // the moving quote on every tip.
                    let payment_value = Zatoshis::from_u64(note.note().value().inner())
                        .expect("note value fits in the Zcash monetary range");
                    if payment_value < price {
                        tracing::debug!(
                            name = %name.as_str(),
                            paid = payment_value.into_u64(),
                            quoted = price.into_u64(),
                            "claim underpaid; retained for re-quote"
                        );
                        continue;
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
                        continue;
                    };
                    let name_note_nullifiers: std::collections::BTreeSet<_> = registry
                        .name_chain()
                        .map(|(_, rec)| rec.nullifier)
                        .collect();
                    let authority_nf = wallet
                        .get_ironwood_nullifiers(NullifierQuery::Unspent)
                        .expect("FATAL: wallet could not expose its nullifiers")
                        .into_iter()
                        .filter(|(acct, _)| *acct == REGISTRY_ACCOUNT)
                        .find_map(|(_, nf)| {
                            let anchor = wallet.unspent_ironwood_note_by_nullifier(
                                REGISTRY_ACCOUNT,
                                nf,
                                TargetHeight::from(tip),
                            )?;
                            (anchor.note().value().inner() == 0
                                && !name_note_nullifiers.contains(&nf))
                                .then_some(nf)
                        });
                    let Some(authority_nf) = authority_nf else {
                        anchors_exhausted = true;
                        tracing::warn!(
                            name = %name.as_str(),
                            "no available claim anchor (all locked or spent)"
                        );
                        continue;
                    };
                    let Some(transaction) = assemble::prepare(
                        &network,
                        &mut wallet,
                        &treasury_keys,
                        &registry_keys,
                        &sapling_spend,
                        &sapling_output,
                        claim_note,
                        authority_nf,
                        Some(&note),
                        tip,
                        target_height,
                    ) else {
                        tracing::debug!(
                            name = %name.as_str(),
                            "registration awaits Treasury funds"
                        );
                        continue;
                    };

                    if source.submit(&transaction, "registration").await {
                        tracing::info!(
                            txid = %transaction.txid(),
                            name = %name.as_str(),
                            "registration in flight"
                        );
                    } else {
                        tracing::error!(
                            txid = %transaction.txid(),
                            name = %name.as_str(),
                            "registration rejected — inputs stranded until expiry"
                        );
                    }
                }

                Request::Update { .. } | Request::Release { .. } => {
                    // Update and release requests are relays: the mint
                    // sends a one-time code to the current controller and
                    // the pending authorization lives only after Zebra
                    // accepts the challenge transaction. The request note
                    // itself stays put; the sweeps reclaim it.
                    let (name, action, requested_ua, extend_years) = match request {
                        Request::Update {
                            name,
                            ua,
                            extend_years,
                        } => (name, Action::Update, ua, extend_years),
                        Request::Release { name, ua } => (name, Action::Release, ua, None),
                        Request::Claim { .. } => unreachable!("claims dispatched above"),
                    };
                    let Some(record) = registry.record(&name).cloned() else {
                        tracing::debug!(
                            name = %name.as_str(),
                            "request for an unregistered name"
                        );
                        continue;
                    };
                    if record.action == Action::Release
                        || record.expires_at.expired(mtp_now)
                        || note_height <= record.confirmed_height
                        || (action == Action::Release && requested_ua != record.ua)
                        || challenges.pending(&name, action, &requested_ua, record.commitment, mtp_now)
                    {
                        continue;
                    }

                    let code = OtpCode::generate();
                    let challenge = Challenge {
                        code: code.clone(),
                        name: name.clone(),
                        action,
                        ua: requested_ua.clone(),
                    };
                    let Some(memo) = challenge.encode(&network) else {
                        continue;
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
                        continue;
                    };

                    let pending = OtpRequest {
                        name: name.clone(),
                        action,
                        ua: requested_ua,
                        tip_rcm: record.commitment,
                        code,
                        expires_at: mtp_now + time::Duration::seconds(D_OTP),
                        extend_years,
                    };
                    let accepted = loop {
                        match source.send_transaction(&transaction).await {
                            Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => break true,
                            Ok(SubmitOutcome::Rejected(error)) => {
                                tracing::error!(
                                    %error,
                                    txid = %transaction.txid(),
                                    name = %name.as_str(),
                                    action = action.as_str(),
                                    "controller challenge rejected"
                                );
                                break false;
                            }
                            Err(error) if error.is_retryable() => {
                                tracing::warn!(
                                    %error,
                                    txid = %transaction.txid(),
                                    "challenge submission uncertain; retrying"
                                );
                                tokio::time::sleep(RETRY_PAUSE).await;
                            }
                            Err(error) => panic!("FATAL: challenge submission failed: {error}"),
                        }
                    };
                    if accepted {
                        challenges.issue(pending);
                        tracing::info!(
                            txid = %transaction.txid(),
                            name = %name.as_str(),
                            action = action.as_str(),
                            "controller challenged"
                        );
                    }
                }
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

            if let Some(release_note) = registry.release_due(&name, mtp_now) {
                let Some(transaction) = assemble::prepare(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                    &registry_keys,
                    &sapling_spend,
                    &sapling_output,
                    release_note,
                    record.nullifier,
                    None,
                    tip,
                    target_height,
                ) else {
                    tracing::debug!(
                        name = %name.as_str(),
                        "lifecycle release awaits Treasury fee funds"
                    );
                    continue;
                };
                loop {
                    match source.send_transaction(&transaction).await {
                        Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => {
                            tracing::info!(
                                txid = %transaction.txid(),
                                name = %name.as_str(),
                                "lifecycle release submitted"
                            );
                            break;
                        }
                        Ok(SubmitOutcome::Rejected(error)) => {
                            tracing::error!(
                                %error,
                                txid = %transaction.txid(),
                                name = %name.as_str(),
                                "lifecycle release rejected"
                            );
                            break;
                        }
                        Err(error) if error.is_retryable() => {
                            tracing::warn!(
                                %error,
                                txid = %transaction.txid(),
                                "release submission uncertain; retrying"
                            );
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                        Err(error) => {
                            panic!("FATAL: lifecycle release submission failed: {error}")
                        }
                    }
                }
                continue;
            }

            let due_in = record.release_deadline.as_seconds() - mtp_now.as_seconds();
            if due_in > CHALLENGE_WINDOW
                || challenges.pending(
                    &name,
                    Action::Update,
                    &record.ua,
                    record.commitment,
                    mtp_now,
                )
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
                extend_years: None,
            };
            let accepted = source.submit(&transaction, "liveness challenge").await;
            if accepted {
                challenges.issue(pending);
                tracing::info!(
                    txid = %transaction.txid(),
                    name = %name.as_str(),
                    "liveness challenge submitted"
                );
            }
        }

        if let Some(tx) = treasury::sweep_ironwood_to_vault(
            &network, &mut wallet, &treasury_keys, &sapling_spend, &sapling_output, tip, target_height,
        ) {
            source.submit(&tx, "Ironwood vault sweep").await;
        }

        if let Some(tx) = treasury::sweep_sapling_to_vault(
            &network, &mut wallet, &treasury_keys, &sapling_spend, &sapling_output,
        ) {
            source.submit(&tx, "Sapling vault sweep").await;
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
