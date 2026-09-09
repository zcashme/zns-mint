//! The Zcash Name Service attested Mint.
//!
//! This binary is deliberately linear. Boot establishes the process identity
//! and capabilities; `main` then follows Zebra's canonical chain, rebuilds the
//! Registry from its zero-value anchor and Name Notes, and applies the mint's
//! rules at every observed tip. The anchor root is created once by the keygen
//! ceremony (`zns-keygen`), never here: the mint authenticates it on every
//! rescan and suspends all Registry rules until it is recovered. The ordering
//! is visible here because ordering is part of the protocol.

use std::convert::Infallible;
use std::time::Duration;

use futures_util::StreamExt as _;
use incrementalmerkletree::Position;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{
    NullifierQuery, SentTransaction, WalletRead as _, WalletWrite as _,
};
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_client_backend::scanning::{Nullifiers, ScanningKeys};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::{FeeRule, P2PKH_STANDARD_OUTPUT_SIZE};
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;
use zcash_protocol::value::Zatoshis;

use zns_mint::boot::{block_metadata, Boot};
use zns_mint::mint::note::assemble;
use zns_mint::mint::otp::{required_relay_value, OtpCode, OtpQueue, OtpRequest, D_OTP};
use zns_mint::mint::registry::{NameRecord, ReceivedNameNote, Registry};
use zns_mint::mint::treasury::{
    sweep_sapling_to_vault, SWEEP_RESERVE, SWEEP_THRESHOLD, VAULT_ADDRESS,
};
use zns_mint::mint::{
    Action, Challenge, Request, Term, MINT_BIRTHDAY, REGISTRY_ACCOUNT, TREASURY_ACCOUNT,
};
use zns_mint::zcash::{self, CanonicalBlockSource, JsonRpc, SubmitOutcome};

const RETRY_PAUSE: Duration = Duration::from_secs(5);
const TRANSACTION_EXPIRY_BUFFER: u32 = 20;
const CHALLENGE_WINDOW: i64 = D_OTP;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let Boot {
        network,
        mut chain,
        mut wallet,
        origin,
        treasury_keys,
        registry_keys,
        sapling_spend,
        sapling_output,
        mut mtp,
        mut oracle,
        mut challenges,
    } = Boot::start().await;

    let rpc = JsonRpc::new();
    let source = CanonicalBlockSource::new();
    let scanning_keys = ScanningKeys::from_account_ufvks(wallet.ufvk_map().clone());
    let mut chain_tip = block_metadata(&origin);
    let mut registry: Option<Registry> = None;

    tracing::info!(
        height = u32::from(chain_tip.block_height()),
        hash = %chain_tip.block_hash(),
        "mint awaiting Zebra tips"
    );

    'reconnect: loop {
        let mut tips = match chain.chain_tip_change_stream().await {
            Ok(tips) => tips,
            Err(error) => {
                tracing::warn!(%error, "Zebra tip stream unavailable; reconnecting");
                tokio::time::sleep(RETRY_PAUSE).await;
                continue 'reconnect;
            }
        };

        'tips: loop {
            let notification = match tips.next().await {
                Some(Ok(notification)) => notification,
                Some(Err(error)) => {
                    tracing::warn!(%error, "Zebra tip stream failed; reconnecting");
                    continue 'reconnect;
                }
                None => {
                    tracing::warn!("Zebra tip stream ended; reconnecting");
                    continue 'reconnect;
                }
            };
            let (announced_height, announced_hash) = zcash::tip_height_hash(&notification);

            // A pushed notification is a wake-up, not the authoritative read.
            // Re-read height and hash atomically through JSON-RPC so a burst of
            // coalesced notifications cannot make the mint act on a stale tip.
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
            if best_height < MINT_BIRTHDAY - 1 {
                panic!("FATAL: Zebra tip is below the mint birthday");
            }
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
                if registry
                    .as_ref()
                    .is_some_and(|registry| ancestor < registry.claim_anchor_height())
                {
                    registry = None;
                } else if let Some(registry) = registry.as_mut() {
                    registry.truncate_to_height(ancestor);
                }
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
                let candidates =
                    zns_mint::mint::decrypt_name_notes(&network, &block, &registry_keys);
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

                let (header, batches) = decrypt_block(&network, block, &scanning_keys);
                let nullifiers = Nullifiers::unspent(&wallet)
                    .expect("FATAL: wallet could not expose its unspent nullifiers");
                let scanned = scan_block(
                    &network,
                    next_height,
                    &header,
                    batches,
                    &scanning_keys,
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

                // Root recovery: adopt the first transaction that both spends
                // a known Treasury note and produces an ordinary zero-value
                // Registry output. The Treasury spend is the authorship proof —
                // anyone can send a zero-valued note to the public Registry
                // address, but only the mint can spend a Treasury note.
                // Canonical order does the rest: a claim can only follow the
                // root on the same fork. ZNS Name Notes use a different
                // decryption domain and never enter this lane.
                let recovered_anchor = if registry.is_none() {
                    let treasury_nullifiers: std::collections::BTreeSet<_> = wallet
                        .get_ironwood_nullifiers(NullifierQuery::All)
                        .expect("FATAL: wallet could not expose its nullifiers")
                        .into_iter()
                        .filter(|(account, _)| *account == TREASURY_ACCOUNT)
                        .map(|(_, nullifier)| nullifier)
                        .collect();
                    let mut nullifiers_by_tx: std::collections::BTreeMap<
                        zcash_primitives::transaction::TxId,
                        Vec<orchard::note::Nullifier>,
                    > = std::collections::BTreeMap::new();
                    for (_, txid, nullifiers) in scanned.ironwood().nullifier_map() {
                        nullifiers_by_tx
                            .entry(*txid)
                            .or_default()
                            .extend(nullifiers.iter().copied());
                    }
                    scanned.transactions().iter().find_map(|transaction| {
                        let authored =
                            nullifiers_by_tx
                                .get(&transaction.txid())
                                .is_some_and(|nullifiers| {
                                    nullifiers
                                        .iter()
                                        .any(|nullifier| treasury_nullifiers.contains(nullifier))
                                });
                        if !authored {
                            return None;
                        }
                        transaction.ironwood_outputs().iter().find_map(|output| {
                            (*output.account_id() == REGISTRY_ACCOUNT
                                && output.note().0.value().inner() == 0)
                                .then(|| output.nf().copied())
                                .flatten()
                        })
                    })
                } else {
                    None
                };

                let mut next_mtp = mtp.clone();
                next_mtp.update(next_height, block_time);
                let block_mtp = next_mtp
                    .current()
                    .expect("FATAL: MTP unavailable after applying a block");

                let (next_registry, accepted_name_notes) = match registry.as_ref() {
                    Some(registry) => {
                        let (next, accepted) =
                            registry.apply_block(&network, &scanned, &name_notes, block_mtp);
                        (Some(next), accepted)
                    }
                    None => match recovered_anchor {
                        Some(anchor) => {
                            let root = Registry::new(anchor, next_height);
                            let (next, accepted) =
                                root.apply_block(&network, &scanned, &name_notes, block_mtp);
                            tracing::info!(
                                height = u32::from(next_height),
                                nullifier = %hex::encode(anchor.to_bytes()),
                                "recovered Registry claim anchor"
                            );
                            (Some(next), accepted)
                        }
                        None => (None, Vec::new()),
                    },
                };

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
                                + u64::try_from(candidate.ordinal)
                                    .expect("Name Note ordinal fits u64"),
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
            let tip = chain_tip.block_height();
            let tip_hash = chain_tip.block_hash();
            let target_height = tip + 1;
            let expiry_height = BlockHeight::from_u32(
                u32::from(target_height)
                    .checked_add(TRANSACTION_EXPIRY_BUFFER)
                    .expect("target height plus expiry buffer fits u32"),
            );
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
                continue 'tips;
            }

            // No Registry rule can run before a canonical root exists. The
            // root anchor is created once by the keygen ceremony and confirmed
            // on-chain before this binary ever ships; the mint authenticates it
            // (the recovery lane above) but never creates it. Until it is
            // recovered, every Registry action is suspended.
            let Some(registry) = registry.as_mut() else {
                tracing::warn!("Registry root anchor not yet recovered; mint rules suspended");
                continue 'tips;
            };

            // Registration messages. A registration spends the exact current
            // claim anchor, spends the inbound Treasury payment, uses separate
            // eligible Treasury notes for the network fee, and creates both
            // the Name Note and the next zero-value claim anchor.
            let registration_messages =
                wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
            for payment in registration_messages {
                let Some(payment_height) = payment.mined_height() else {
                    continue;
                };
                let memo = wallet
                    .get_memo(*payment.internal_note_id())
                    .expect("FATAL: Treasury memo lookup failed");
                let Some(memo) = memo else { continue };
                let memo = memo.encode();
                let decoded = Request::decode(&network, memo.as_array());
                let Some(Request::Claim { ref name, term, .. }) = decoded else {
                    continue;
                };
                // The decoded request is moved into `authorize` below; the
                // name is needed in logs afterward, so own it here.
                let name = name.clone();
                if registry.record(&name).is_some_and(|record| {
                    record.action != Action::Release || payment_height <= record.confirmed_height
                }) {
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
                let Some(claim_note) = registry.authorize(
                    &mut challenges,
                    decoded.expect("claim pattern matched above"),
                    None,
                    mtp_now,
                ) else {
                    continue;
                };
                let Some(transaction) = assemble::register(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                    &registry_keys,
                    &sapling_spend,
                    &sapling_output,
                    claim_note,
                    registry.claim_anchor(),
                    &payment,
                    price,
                    tip,
                    target_height,
                ) else {
                    tracing::debug!(name = %name.as_str(), "registration awaits Treasury fee funds");
                    continue;
                };

                loop {
                    match source.send_transaction(&transaction).await {
                        Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => {
                            tracing::info!(
                                txid = %transaction.txid(),
                                name = %name.as_str(),
                                "registration submitted"
                            );
                            break;
                        }
                        Ok(SubmitOutcome::Rejected(error)) => {
                            tracing::error!(
                                %error,
                                txid = %transaction.txid(),
                                name = %name.as_str(),
                                "registration rejected"
                            );
                            break;
                        }
                        Err(error) if error.is_retryable() => {
                            tracing::warn!(
                                %error,
                                txid = %transaction.txid(),
                                "registration submission uncertain; retrying"
                            );
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                        Err(error) => panic!("FATAL: registration submission failed: {error}"),
                    }
                }

                // The claim-anchor spend recorded by assembly prevents a
                // second registration from being built until this one either
                // confirms or expires.
                break;
            }

            // Update and release requests. These consume the inbound request
            // note while sending a challenge to the current controller. The
            // pending authorization becomes live only after Zebra accepts the
            // challenge transaction.
            let challenge_messages =
                wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
            for request_note in challenge_messages {
                let Some(request_height) = request_note.mined_height() else {
                    continue;
                };
                let memo = wallet
                    .get_memo(*request_note.internal_note_id())
                    .expect("FATAL: Treasury memo lookup failed");
                let Some(memo) = memo else { continue };
                let memo = memo.encode();
                let Some(request) = Request::decode(&network, memo.as_array()) else {
                    continue;
                };
                let (name, action, requested_ua, extend_years) = match request {
                    Request::Update { name, ua, extend_years } => {
                        (name, Action::Update, ua, extend_years)
                    }
                    Request::Release { name, ua } => (name, Action::Release, ua, None),
                    Request::Claim { .. } => continue,
                };
                let Some(record) = registry.record(&name).cloned() else {
                    continue;
                };
                if record.action == Action::Release
                    || record.expires_at.expired(mtp_now)
                    || request_height <= record.confirmed_height
                    || (action == Action::Release && requested_ua != record.ua)
                    || challenges.pending(
                        &name,
                        action,
                        &requested_ua,
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
                    action,
                    ua: requested_ua.clone(),
                };
                let Some(memo) = challenge.encode(&network) else {
                    continue;
                };
                let relay_value = required_relay_value(&network, target_height);
                let Some(transaction) = assemble::challenge(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                    &sapling_spend,
                    &sapling_output,
                    Some(&request_note),
                    &record.ua,
                    memo,
                    relay_value,
                    tip,
                    target_height,
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

            // Returns authorize transitions.
            let echo_messages =
                wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
            for echo_note in echo_messages {
                if echo_note.mined_height().is_none() {
                    continue;
                }
                let memo = wallet
                    .get_memo(*echo_note.internal_note_id())
                    .expect("FATAL: Treasury memo lookup failed");
                let Some(memo) = memo else { continue };
                let memo = memo.encode();
                let Some(challenge) = Challenge::decode(&network, memo.as_array()) else {
                    continue;
                };
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
                let Some(transition_note) =
                    registry.authorize(&mut authorized_challenges, request, Some(&digits), mtp_now)
                else {
                    continue;
                };
                let Some(transaction) = assemble::transition(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                    &registry_keys,
                    &sapling_spend,
                    &sapling_output,
                    transition_note,
                    record.nullifier,
                    Some(&echo_note),
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
                        Err(error) => panic!("FATAL: transition submission failed: {error}"),
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
                    let Some(transaction) = assemble::transition(
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
                let Some(transaction) = assemble::challenge(
                    &network,
                    &mut wallet,
                    &treasury_keys,
                    &sapling_spend,
                    &sapling_output,
                    None,
                    &record.ua,
                    memo,
                    relay_value,
                    tip,
                    target_height,
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
                let accepted = loop {
                    match source.send_transaction(&transaction).await {
                        Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => break true,
                        Ok(SubmitOutcome::Rejected(error)) => {
                            tracing::error!(
                                %error,
                                txid = %transaction.txid(),
                                name = %name.as_str(),
                                "liveness challenge rejected"
                            );
                            break false;
                        }
                        Err(error) if error.is_retryable() => {
                            tracing::warn!(
                                %error,
                                txid = %transaction.txid(),
                                "liveness challenge submission uncertain; retrying"
                            );
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                        Err(error) => {
                            panic!("FATAL: liveness challenge submission failed: {error}")
                        }
                    }
                };
                if accepted {
                    challenges.issue(pending);
                    tracing::info!(
                        txid = %transaction.txid(),
                        name = %name.as_str(),
                        "liveness challenge submitted"
                    );
                }
            }

            // Ironwood housekeeping is intentionally assembled here instead
            // of using generic wallet selection: only confirmed empty-memo
            // Treasury notes may be swept. Protocol messages and every
            // zero-value Registry authority note are outside this set.
            let mut sweep_notes =
                wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
            sweep_notes.retain(|note| {
                let mined = note.mined_height().is_some();
                let empty_memo = matches!(
                    wallet.get_memo(*note.internal_note_id()),
                    Ok(None) | Ok(Some(Memo::Empty))
                );
                mined && empty_memo
            });
            let sweep_funding = sweep_notes.iter().fold(Zatoshis::ZERO, |total, note| {
                (total
                    + Zatoshis::from_u64(note.note().value().inner())
                        .expect("Treasury note value fits the monetary range"))
                .expect("Treasury balance fits the monetary range")
            });
            if sweep_funding > SWEEP_THRESHOLD {
                let ironwood_actions = sweep_notes.len().max(1);
                let transaction_fee = FeeRule::standard()
                    .fee_required(
                        &network,
                        target_height,
                        std::iter::empty::<
                            zcash_primitives::transaction::fees::transparent::InputSize,
                        >(),
                        [P2PKH_STANDARD_OUTPUT_SIZE],
                        0,
                        0,
                        0,
                        ironwood_actions,
                    )
                    .expect("FATAL: vault-sweep fee is not representable");
                let sweep_amount = (sweep_funding - SWEEP_RESERVE)
                    .and_then(|remaining| remaining - transaction_fee)
                    .expect("sweep threshold covers reserve and fee");
                let anchor = wallet
                    .ironwood_anchor(tip)
                    .expect("FATAL: Ironwood tree access failed")
                    .expect("FATAL: wallet has no Ironwood anchor at its applied tip");
                let mut prepared = Vec::with_capacity(sweep_notes.len());
                for note in &sweep_notes {
                    let path = wallet
                        .ironwood_witness(note.note_commitment_tree_position(), tip)
                        .expect("FATAL: Ironwood tree access failed")
                        .expect("FATAL: sweep input has no witness");
                    prepared.push((note.note().clone(), orchard::tree::MerklePath::from(path)));
                }

                let treasury_fvk = treasury_keys.orchard_fvk();
                let mut builder = Builder::new(
                    network.clone(),
                    target_height,
                    BuildConfig::Standard {
                        sapling_anchor: None,
                        orchard_anchor: None,
                        ironwood_anchor: Some(anchor),
                        orchard_padding: BundlePadding::DEFAULT,
                        ironwood_padding: BundlePadding::DEFAULT,
                    },
                )
                .with_expiry_height(expiry_height);
                for (note, path) in prepared {
                    builder
                        .add_ironwood_spend::<zcash_primitives::transaction::fees::zip317::FeeError>(
                            treasury_fvk.clone(),
                            note,
                            path,
                        )
                        .expect("FATAL: valid Treasury sweep input was rejected");
                }
                builder
                    .add_transparent_output(&VAULT_ADDRESS, sweep_amount)
                    .expect("FATAL: valid vault output was rejected");
                builder
                    .add_ironwood_output::<zcash_primitives::transaction::fees::zip317::FeeError>(
                        Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                        treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                        SWEEP_RESERVE,
                        zcash_protocol::memo::MemoBytes::empty(),
                    )
                    .expect("FATAL: valid Treasury reserve was rejected");
                let built = builder
                    .build(
                        &Default::default(),
                        &[],
                        &[orchard::keys::SpendAuthorizingKey::from(
                            treasury_keys.orchard_spending_key(),
                        )],
                        &mut rand::rngs::OsRng,
                        &sapling_spend,
                        &sapling_output,
                        &FeeRule::standard(),
                    )
                    .expect("FATAL: Ironwood vault sweep proving or signing failed");
                let transaction = built.transaction().clone();
                let sent = SentTransaction::new(
                    &transaction,
                    time::OffsetDateTime::now_utc(),
                    TargetHeight::from(target_height),
                    TREASURY_ACCOUNT,
                    &[],
                    transaction_fee,
                    &[],
                );
                wallet
                    .store_transactions_to_be_sent(&[sent])
                    .expect("FATAL: wallet rejected the Ironwood vault sweep");

                loop {
                    match source.send_transaction(&transaction).await {
                        Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => {
                            tracing::info!(txid = %transaction.txid(), "Ironwood vault sweep submitted");
                            break;
                        }
                        Ok(SubmitOutcome::Rejected(error)) => {
                            tracing::error!(%error, txid = %transaction.txid(), "Ironwood vault sweep rejected");
                            break;
                        }
                        Err(error) if error.is_retryable() => {
                            tracing::warn!(%error, txid = %transaction.txid(), "Ironwood sweep submission uncertain; retrying");
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                        Err(error) => panic!("FATAL: Ironwood sweep submission failed: {error}"),
                    }
                }
            }

            match sweep_sapling_to_vault(
                &network,
                &mut wallet,
                &treasury_keys,
                &sapling_spend,
                &sapling_output,
            ) {
                Ok(Some(txid)) => {
                    let transaction = wallet
                        .get_transaction(txid)
                        .expect("FATAL: Sapling sweep transaction lookup failed")
                        .expect("FATAL: Sapling sweep was not recorded by its builder");
                    loop {
                        match source.send_transaction(&transaction).await {
                            Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => {
                                tracing::info!(%txid, "Sapling vault sweep submitted");
                                break;
                            }
                            Ok(SubmitOutcome::Rejected(error)) => {
                                tracing::error!(%error, %txid, "Sapling vault sweep rejected");
                                break;
                            }
                            Err(error) if error.is_retryable() => {
                                tracing::warn!(%error, %txid, "Sapling sweep submission uncertain; retrying");
                                tokio::time::sleep(RETRY_PAUSE).await;
                            }
                            Err(error) => {
                                panic!("FATAL: Sapling sweep submission failed: {error}")
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::error!(?error, "Sapling vault sweep construction failed"),
            }

            tracing::debug!(
                height = u32::from(tip),
                hash = %tip_hash,
                "mint rules applied at canonical tip"
            );
        }
    }
}
