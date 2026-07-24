//! Live phase: operational state reconciliation and transaction execution.
//!
//! After Rebuild reaches an exact Zebra tip, the mint enters Live. Live is a
//! state reconciler — it derives pending work from canonical Wallet + Registry
//! state, builds and submits transactions, and tracks their confirmation.
//!
//! Live does not consume block events. It reads installed canonical state
//! after each canonical fold and determines what work is still pending.
//! Restart loses all in-memory operational state (OTPs, submissions,
//! reservations); re-derivation from canonical chain state is the recovery
//! path.
//!
//! # Reconciliation order
//!
//! 1. Check pending submissions for confirmation or expiry.
//! 2. Scan Treasury received notes for request memos.
//! 3. For claims: if name is available and payment is sufficient, build and
//!    submit the atomic claim transaction.
//! 4. For update/release without OTP: issue OTP and build the relay transaction.
//! 5. For update/release with OTP: verify, authorize, and submit the Name Note
//!    transition.
//!
//! # Reorg handling
//!
//! On reorg, all cursor-bound operational state is invalidated:
//! - Submissions are cleared (transactions may be reorged out).
//! - Pending OTPs are cleared (challenges are ephemeral).
//! After reorg recovery, Live re-reconciles from the new canonical state.

pub mod submissions;

use std::collections::BTreeSet;

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::auth::{ChallengeKey, OtpCode, PendingOtps};
use crate::key::{RegistryKeys, TreasuryKeys};
use crate::metrics;
use crate::mint::{Action, Name, UnifiedAddress, TREASURY_ACCOUNT};
use crate::registry::{authorize, NameNoteRequest, Registry, Tip};
use crate::treasury::{memo::RequestMemo, Treasury};
use crate::wallet::{NoteLocator, Wallet};
use crate::zcash::JsonRpc;

use submissions::{Submission, SubmissionKind, Submissions};

/// The claim price in zatoshis. Protocol policy — the Treasury retains this
/// amount from each claim payment.
// TODO: move to a policy module when one exists.
const CLAIM_PRICE: u64 = 10_000;

/// The transaction expiry buffer in blocks (~25 minutes at 75s/block).
const TX_EXPIRY_BUFFER: u32 = 20;

/// Operational state owned by the Live phase.
///
/// All fields are in-memory and ephemeral. Restart loses this state.
pub struct LiveState {
    /// Pending OTP challenges, keyed by (name, action, ua).
    pending_otps: PendingOtps,
    /// Submitted transactions awaiting confirmation.
    submissions: Submissions,
}

impl Default for LiveState {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveState {
    pub fn new() -> Self {
        Self {
            pending_otps: PendingOtps::new(),
            submissions: Submissions::new(),
        }
    }

    /// Clears all cursor-bound operational state. Called on reorg.
    pub fn invalidate(&mut self) {
        self.submissions.clear();
        // OTPs are ephemeral; clearing them forces re-issuance after reorg.
        let reserved: BTreeSet<ChallengeKey> =
            self.pending_otps.reserved_challenges().iter().cloned().collect();
        self.pending_otps.release_all(&reserved);
    }

    /// Prunes expired OTPs at the current height.
    pub fn prune_otps(&mut self, current_height: BlockHeight) {
        self.pending_otps.prune(current_height);
    }

    /// All note locators reserved by pending submissions.
    fn reserved_locators(&self) -> BTreeSet<NoteLocator> {
        self.submissions.reserved_locators()
    }
}

/// The result of reconciling canonical state with operational state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingWork {
    /// A claim request with a matching unspent payment.
    Claim {
        name: Name,
        ua: UnifiedAddress,
        payment_locator: NoteLocator,
        payment_value: u64,
    },
    /// An update or release request without an OTP.
    NeedsOtpRelay {
        name: Name,
        action: Action,
        controller_ua: UnifiedAddress,
        request_note_locator: NoteLocator,
    },
    /// An update or release request with an OTP.
    VerifyAndTransition {
        name: Name,
        action: Action,
        ua: UnifiedAddress,
        otp: [u8; 16],
    },
}

/// Reconciles canonical state with operational state and returns pending work.
pub fn reconcile(
    live: &mut LiveState,
    wallet: &Wallet,
    registry: &Registry,
    _treasury: &Treasury,
    cursor_height: BlockHeight,
) -> Vec<PendingWork> {
    let mut work = Vec::new();

    live.prune_otps(cursor_height);

    let reserved = live.reserved_locators();

    let mut seen_claims: BTreeSet<Name> = BTreeSet::new();
    let mut seen_no_otp: BTreeSet<ChallengeKey> = BTreeSet::new();
    let mut seen_with_otp: BTreeSet<ChallengeKey> = BTreeSet::new();

    for note in wallet.orchard_notes_for(TREASURY_ACCOUNT) {
        let Ok(request) = RequestMemo::parse(note.memo.as_array()) else {
            continue;
        };

        let name = match Name::parse(request.name()) {
            Some(n) => n,
            None => continue,
        };

        let locator = NoteLocator::orchard(TREASURY_ACCOUNT, note.note.rho());

        if reserved.contains(&locator) {
            continue;
        }

        match &request {
            RequestMemo::Claim { name: _, ua } => {
                let ua = UnifiedAddress::from_string(ua.clone());

                if seen_claims.contains(&name) {
                    continue;
                }

                let available = match registry.tip(&name) {
                    None => true,
                    Some(tip) => tip.action == Action::Release,
                };

                if !available {
                    continue;
                }

                let payment_value = note.note.value().inner();
                if payment_value < CLAIM_PRICE {
                    metrics::inc_request_invalid("insufficient_payment");
                    continue;
                }

                metrics::inc_request_received("claim");
                seen_claims.insert(name.clone());
                work.push(PendingWork::Claim {
                    name,
                    ua,
                    payment_locator: locator,
                    payment_value,
                });
            }
            RequestMemo::Update { name: _, ua, otp } => {
                let ua = UnifiedAddress::from_string(ua.clone());

                let tip = match registry.tip(&name) {
                    Some(t) if t.action != Action::Release => t,
                    _ => continue,
                };

                let controller_ua = current_controller_ua(tip);

                match otp {
                    None => {
                        let key = ChallengeKey::new(name.clone(), Action::Update, ua.clone());

                        if live.pending_otps.contains(&key) || seen_no_otp.contains(&key) {
                            continue;
                        }

                        metrics::inc_request_received("update");
                        seen_no_otp.insert(key.clone());
                        work.push(PendingWork::NeedsOtpRelay {
                            name,
                            action: Action::Update,
                            controller_ua,
                            request_note_locator: locator,
                        });
                    }
                    Some(otp_bytes) => {
                        let key = ChallengeKey::new(name.clone(), Action::Update, ua.clone());
                        if seen_with_otp.contains(&key) {
                            continue;
                        }

                        metrics::inc_request_received("update");
                        seen_with_otp.insert(key.clone());
                        work.push(PendingWork::VerifyAndTransition {
                            name,
                            action: Action::Update,
                            ua,
                            otp: *otp_bytes,
                        });
                    }
                }
            }
            RequestMemo::Release { name: _, ua, otp } => {
                let ua = UnifiedAddress::from_string(ua.clone());

                let tip = match registry.tip(&name) {
                    Some(t) if t.action != Action::Release => t,
                    _ => continue,
                };

                let controller_ua = current_controller_ua(tip);

                match otp {
                    None => {
                        let key = ChallengeKey::new(name.clone(), Action::Release, ua.clone());

                        if live.pending_otps.contains(&key) || seen_no_otp.contains(&key) {
                            continue;
                        }

                        metrics::inc_request_received("release");
                        seen_no_otp.insert(key.clone());
                        work.push(PendingWork::NeedsOtpRelay {
                            name,
                            action: Action::Release,
                            controller_ua,
                            request_note_locator: locator,
                        });
                    }
                    Some(otp_bytes) => {
                        let key = ChallengeKey::new(name.clone(), Action::Release, ua.clone());
                        if seen_with_otp.contains(&key) {
                            continue;
                        }

                        metrics::inc_request_received("release");
                        seen_with_otp.insert(key.clone());
                        work.push(PendingWork::VerifyAndTransition {
                            name,
                            action: Action::Release,
                            ua,
                            otp: *otp_bytes,
                        });
                    }
                }
            }
        }
    }

    work
}

/// Extracts the current controller's UA from a Registry tip.
fn current_controller_ua(tip: &Tip) -> UnifiedAddress {
    tip.received()
        .map(|r| r.payload().ua().clone())
        .unwrap_or_else(UnifiedAddress::empty)
}

/// Executes pending work: builds, signs, and submits transactions.
pub async fn execute(
    live: &mut LiveState,
    wallet: &mut Wallet,
    registry: &Registry,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    rpc: &JsonRpc,
    cursor_height: BlockHeight,
    work: Vec<PendingWork>,
) -> Vec<Submission> {
    let target_height = BlockHeight::from_u32(u32::from(cursor_height) + 1);
    let expiry_height = BlockHeight::from_u32(
        u32::from(target_height)
            .checked_add(TX_EXPIRY_BUFFER)
            .unwrap_or(u32::from(target_height)),
    );
    let excluded = live.reserved_locators();
    let mut new_submissions = Vec::new();

    for item in work {
        match item {
            PendingWork::Claim {
                name,
                ua,
                payment_locator,
                payment_value: _,
            } => {
                let result = execute_claim(
                    wallet,
                    registry,
                    treasury_keys,
                    registry_keys,
                    &name,
                    &ua,
                    payment_locator,
                    &excluded,
                    cursor_height,
                    target_height,
                );

                match result {
                    Ok((txid, hex, reserved_notes)) => {
                        match rpc.send(&hex).await {
                            Ok(_) => {
                                tracing::info!(
                                    txid = %txid,
                                    name = %name,
                                    "claim transaction submitted"
                                );
                                let sub = Submission {
                                    kind: SubmissionKind::Claim,
                                    txid,
                                    submit_height: cursor_height,
                                    expiry_height,
                                    reserved_notes,
                                    confirmed_at: None,
                                };
                                new_submissions.push(sub.clone());
                                live.submissions.add(sub);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    name = %name,
                                    "claim submission failed"
                                );
                                metrics::inc_spend_error("claim_submit");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = e,
                            name = %name,
                            "claim assembly failed"
                        );
                        metrics::inc_spend_error("claim_assembly");
                    }
                }
            }
            PendingWork::NeedsOtpRelay {
                name,
                action,
                controller_ua,
                request_note_locator: _,
            } => {
                let key = ChallengeKey::new(name.clone(), action, controller_ua.clone());
                let otp = live.pending_otps.issue(key, cursor_height);
                metrics::inc_otps_issued();

                let result = execute_otp_relay(
                    wallet,
                    treasury_keys,
                    &name,
                    action,
                    &controller_ua,
                    &otp,
                    cursor_height,
                    target_height,
                    &excluded,
                );

                match result {
                    Ok(relay) => {
                        match rpc.send(&relay.hex).await {
                            Ok(_) => {
                                tracing::info!(
                                    txid = %relay.txid,
                                    name = %name,
                                    action = action.as_str(),
                                    "OTP relay submitted"
                                );
                                let sub = Submission {
                                    kind: SubmissionKind::OtpRelay,
                                    txid: relay.txid,
                                    submit_height: cursor_height,
                                    expiry_height,
                                    reserved_notes: relay.reserved_notes,
                                    confirmed_at: None,
                                };
                                new_submissions.push(sub.clone());
                                live.submissions.add(sub);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    name = %name,
                                    "OTP relay submission failed"
                                );
                                metrics::inc_spend_error("relay_submit");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = e,
                            name = %name,
                            "OTP relay assembly failed"
                        );
                        metrics::inc_spend_error("relay_assembly");
                    }
                }
            }
            PendingWork::VerifyAndTransition {
                name,
                action,
                ua,
                otp,
            } => {
                let request = match action {
                    Action::Update => authorize::authorize_update(
                        registry,
                        &mut live.pending_otps,
                        cursor_height,
                        name.clone(),
                        ua.clone(),
                        &otp,
                    ),
                    Action::Release => authorize::authorize_release(
                        registry,
                        &mut live.pending_otps,
                        cursor_height,
                        name.clone(),
                        ua.clone(),
                        &otp,
                    ),
                    Action::Claim => unreachable!("claims don't use OTPs"),
                };

                let Some(request) = request else {
                    metrics::inc_request_invalid("authorization_failed");
                    tracing::warn!(
                        name = %name,
                        action = action.as_str(),
                        "transition authorization failed (invalid OTP or name state)"
                    );
                    continue;
                };

                metrics::inc_otps_verified();

                let result = execute_transition(
                    wallet,
                    registry,
                    registry_keys,
                    request,
                    &excluded,
                    cursor_height,
                    target_height,
                );

                match result {
                    Ok((txid, hex, reserved_notes)) => {
                        match rpc.send(&hex).await {
                            Ok(_) => {
                                tracing::info!(
                                    txid = %txid,
                                    name = %name,
                                    action = action.as_str(),
                                    "transition transaction submitted"
                                );
                                let kind = match action {
                                    Action::Update => SubmissionKind::Update,
                                    Action::Release => SubmissionKind::Release,
                                    Action::Claim => unreachable!(),
                                };
                                let sub = Submission {
                                    kind,
                                    txid,
                                    submit_height: cursor_height,
                                    expiry_height,
                                    reserved_notes,
                                    confirmed_at: None,
                                };
                                new_submissions.push(sub.clone());
                                live.submissions.add(sub);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    name = %name,
                                    "transition submission failed"
                                );
                                metrics::inc_spend_error("transition_submit");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = e,
                            name = %name,
                            "transition assembly failed"
                        );
                        metrics::inc_spend_error("transition_assembly");
                    }
                }
            }
        }
    }

    new_submissions
}

/// Builds an atomic claim transaction.
#[allow(clippy::too_many_arguments)]
fn execute_claim(
    wallet: &mut Wallet,
    registry: &Registry,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    name: &Name,
    ua: &UnifiedAddress,
    payment_locator: NoteLocator,
    excluded: &BTreeSet<NoteLocator>,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
) -> Result<(TxId, String, Vec<NoteLocator>), &'static str> {
    let claim_request = NameNoteRequest::Claim(authorize::ClaimRequest {
        name: name.clone(),
        ua: ua.clone(),
    });
    let fee_inputs = crate::registry::transaction::select_registry_fee_inputs(
        wallet,
        &claim_request,
        target_height,
        excluded,
        1, // 1 extra output: the refund
    )?;

    let (txid, hex, _refund_value) = crate::treasury::claim::assemble_atomic_claim(
        wallet,
        registry,
        treasury_keys,
        registry_keys,
        name.clone(),
        ua.clone(),
        payment_locator,
        &fee_inputs,
        CLAIM_PRICE,
        anchor_height,
        target_height,
    )?;

    let mut reserved: Vec<NoteLocator> = fee_inputs.locators().iter().copied().collect();
    reserved.push(payment_locator);

    Ok((txid, hex, reserved))
}

/// Builds an OTP relay transaction.
#[allow(clippy::too_many_arguments)]
fn execute_otp_relay(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    name: &Name,
    action: Action,
    controller_ua: &UnifiedAddress,
    otp: &OtpCode,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &BTreeSet<NoteLocator>,
) -> Result<crate::treasury::relay::RelayAssembly, &'static str> {
    let mut excluded_rhos: BTreeSet<orchard::note::Rho> = BTreeSet::new();
    for locator in excluded {
        if let NoteLocator::Orchard { account_id, rho } = locator {
            if *account_id == TREASURY_ACCOUNT {
                excluded_rhos.insert(*rho);
            }
        }
    }

    crate::treasury::relay::assemble_otp_relay(
        wallet,
        treasury_keys,
        name,
        action,
        controller_ua,
        otp,
        anchor_height,
        target_height,
        &excluded_rhos,
    )
}

/// Builds a Name Note transition (update or release) transaction.
#[allow(clippy::too_many_arguments)]
fn execute_transition(
    wallet: &mut Wallet,
    registry: &Registry,
    registry_keys: &RegistryKeys,
    request: NameNoteRequest,
    excluded: &BTreeSet<NoteLocator>,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
) -> Result<(TxId, String, Vec<NoteLocator>), &'static str> {
    let fee_inputs = crate::registry::transaction::select_registry_fee_inputs(
        wallet,
        &request,
        target_height,
        excluded,
        0, // no extra outputs for update/release
    )?;

    let bundle = crate::registry::transaction::build_transaction(
        wallet,
        registry,
        registry_keys,
        request,
        &fee_inputs,
        anchor_height,
        target_height,
        None, // no refund for update/release
    )?;

    let (txid, hex) = crate::registry::signing::assemble_v6_transaction(
        None,
        Some(bundle),
        None,
        Some(registry_keys),
        None,
        target_height,
    )?;

    let reserved: Vec<NoteLocator> = fee_inputs.locators().iter().copied().collect();

    Ok((txid, hex, reserved))
}

/// Checks pending submissions for confirmation in the latest block.
pub fn check_confirmations(
    live: &mut LiveState,
    block_txids: &[TxId],
    block_height: BlockHeight,
) {
    for txid in block_txids {
        if let Some(confirmed) = live.submissions.confirm(txid, block_height) {
            tracing::info!(
                txid = %txid,
                kind = confirmed.kind.as_str(),
                height = u32::from(block_height),
                "transaction confirmed"
            );
            match confirmed.kind {
                SubmissionKind::Claim => {
                    metrics::inc_names_claimed();
                    metrics::inc_tx_confirmed("claim");
                }
                SubmissionKind::Update => {
                    metrics::inc_names_updated();
                    metrics::inc_tx_confirmed("update");
                }
                SubmissionKind::Release => {
                    metrics::inc_names_released();
                    metrics::inc_tx_confirmed("release");
                }
                SubmissionKind::OtpRelay => {
                    metrics::inc_tx_confirmed("otp_relay");
                }
            }
        }
    }

    // Expire old submissions.
    let expired = live.submissions.expire(block_height);
    for sub in &expired {
        tracing::warn!(
            txid = %sub.txid,
            kind = sub.kind.as_str(),
            "transaction expired without confirmation"
        );
        metrics::inc_tx_expired(sub.kind.as_str());
    }

    // Drain confirmed submissions from the pending set.
    let _confirmed = live.submissions.drain_confirmed();
}