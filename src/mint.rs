//! Shared protocol logic for ZNS minting and wallet operations.

mod note;

// Re-export note functions so existing `crate::mint::` paths keep working.
pub use note::{
    decode_name_note, decode_name_note_payload, encode_name_note, zns_psi_rcm, zns_psi_rcm_raw,
    NameNotePayload,
};

use std::fmt;

use zcash_client_backend::data_api::BlockMetadata;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zip32::AccountId;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// The fully-applied local chain prefix.
///
/// Upstream names this scanner continuity value [`BlockMetadata`]. The mint
/// cursor is a local semantic wrapper around it: the mint has applied every
/// block through this metadata's height/hash/tree sizes.
pub struct ChainCursor {
    metadata: BlockMetadata,
}

impl ChainCursor {
    pub(crate) fn from_metadata(metadata: BlockMetadata) -> Self {
        Self { metadata }
    }

    pub fn metadata(&self) -> &BlockMetadata {
        &self.metadata
    }

    pub fn height(&self) -> BlockHeight {
        self.metadata.block_height()
    }
}

/// A ZNS memo: the fixed 512-byte payload carried by an Orchard note.
///
/// A newtype around upstream [`MemoBytes`] (`zcash_protocol::memo`) that keeps
/// the Zcash memo representation upstream-faithful while overriding `Debug` to
/// redact the contents. ZNS memo contents are shielded user data (names,
/// addresses, ZNS payloads); per AGENTS.md "treat key material as radioactive",
/// they must not leak to logs — the upstream `MemoBytes::Debug` prints hex, which
/// would leak the full payload on any `{:?}` log line.
///
/// Construction goes through [`Memo::from_bytes`] (mirrors upstream's checked
/// constructor) and is called at the sync extraction boundary. Reading goes
/// through [`Memo::as_array`] / [`Memo::into_bytes`], forwarded to the inner
/// `MemoBytes`.
#[derive(Clone, PartialEq, Eq)]
pub struct Memo(MemoBytes);

impl Memo {
    /// Constructs a `Memo` from a byte slice, padding with zeros if shorter
    /// than 512 and rejecting slices longer than 512.
    ///
    /// Mirrors [`MemoBytes::from_bytes`]. Called at the sync extraction
    /// boundary with the `[u8; 512]` from upstream note decryption; the
    /// grammar parser (encode/decode) lives in `mint::note`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, zcash_protocol::memo::Error> {
        MemoBytes::from_bytes(bytes).map(Self)
    }

    /// Returns the raw 512-byte memo array by reference.
    pub fn as_array(&self) -> &[u8; 512] {
        self.0.as_array()
    }

    /// Consumes this `Memo` and returns the underlying 512-byte array.
    pub fn into_bytes(self) -> [u8; 512] {
        self.0.into_bytes()
    }
}

impl fmt::Debug for Memo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Memo(<redacted>)")
    }
}

/// ZNS action kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Point a name to an address
    Claim,
    /// Rebinds a name to a new address
    Update,
    /// Terminates a name's linkage to an address
    Release,
}

impl Action {
    /// Returns the canonical ASCII verb for this action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Claim => "claim",
            Action::Update => "update",
            Action::Release => "release",
        }
    }
}

/// A ZNS name-chain commitment — the trapdoor that links consecutive Name Notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameCommitment(orchard::note::NoteCommitTrapdoor);

impl NameCommitment {
    /// Wraps a `NoteCommitTrapdoor` that was derived via [`zns_psi_rcm`].
    pub fn from_inner(inner: orchard::note::NoteCommitTrapdoor) -> Self {
        Self(inner)
    }

    /// Unwraps back to the upstream type for the `unsafe-zns` builder surface.
    pub fn into_inner(self) -> orchard::note::NoteCommitTrapdoor {
        self.0
    }

    /// Deserializes from the canonical 32-byte little-endian representation.
    ///
    /// Returns `None` if the bytes do not encode a valid Pallas scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        orchard::note::NoteCommitTrapdoor::from_bytes(bytes)
            .into_option()
            .map(Self)
    }

    /// Serializes to the canonical 32-byte little-endian representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A strongly-typed ZcashName
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// Attempts to parse a string into a valid ZNS name.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return None;
        }
        if bytes
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Zcash unified address string (e.g. `u1qz...`).
///
/// Newtype over `String` to distinguish a UA from arbitrary text. The mint
/// never parses or validates UAs — it hashes the string into the ZNS
/// commitment and stores it in the Name Note memo. The resolver/verifier
/// is what parses the UA to extract payment receivers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnifiedAddress(String);

impl UnifiedAddress {
    /// Constructs a `UnifiedAddress` from a string. No validation — the mint
    /// treats the UA as an opaque string.
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    /// The empty UA, used for release actions.
    pub fn empty() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for UnifiedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}


// ===========================================================================
// Operational state
// ===========================================================================

use std::collections::{BTreeMap, BTreeSet};

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::Parameters;

use crate::auth::PendingOtps;
use crate::metrics;
use crate::registry::state::Registry;
use crate::registry::liquidity::RegistryFeeLiquidity;
use crate::treasury::memo::RequestMemo;
use crate::treasury::sweep;
use crate::wallet::{NoteLocator, Wallet};

/// Claim price and request minimum in zatoshis. Protocol policy.
pub const CLAIM_PRICE: u64 = 10_000;
pub const MIN_REQUEST_VALUE: u64 = 10_000;
pub const TX_EXPIRY_BUFFER: u32 = 20;

/// What kind of transaction a submission represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubmissionKind {
    Claim,
    Update,
    Release,
    OtpRelay,
    Replenish,
    AutoSweep,
}

impl SubmissionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Update => "update",
            Self::Release => "release",
            Self::OtpRelay => "otp_relay",
            Self::Replenish => "replenish",
            Self::AutoSweep => "sweep",
        }
    }
}

/// One submitted transaction awaiting confirmation.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Submission {
    pub kind: SubmissionKind,
    pub txid: TxId,
    pub submit_height: BlockHeight,
    pub expiry_height: BlockHeight,
    pub reserved_notes: Vec<NoteLocator>,
    pub confirmed_at: Option<BlockHeight>,
}

impl Submission {
    pub fn is_expired(&self, current_height: BlockHeight) -> bool {
        self.confirmed_at.is_none() && current_height > self.expiry_height
    }
}

/// In-memory operational state for the active mint phase.
pub struct OperationalState {
    pub pending_otps: PendingOtps,
    pub submissions: BTreeMap<TxId, Submission>,
}

impl Default for OperationalState {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationalState {
    pub fn new() -> Self {
        Self {
            pending_otps: PendingOtps::new(),
            submissions: BTreeMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.submissions.clear();
        self.pending_otps = PendingOtps::new();
    }

    pub fn reserved_locators(&self) -> BTreeSet<NoteLocator> {
        self.submissions
            .values()
            .flat_map(|s| s.reserved_notes.iter().copied())
            .collect()
    }
}

/// Work items derived from canonical state.
pub enum WorkItem {
    Claim { name: Name, ua: UnifiedAddress, payment_locator: NoteLocator },
    NeedsOtpRelay { name: Name, action: Action, controller_ua: UnifiedAddress, request_locator: NoteLocator, request_value: u64 },
    VerifyAndTransition { name: Name, action: Action, ua: UnifiedAddress, otp: [u8; 16] },
    ReplenishRegistry { plan: crate::registry::liquidity::RegistryFundingPlan },
    AutoSweep { sweep_amount: u64 },
}

/// Whether a UA string contains an Orchard receiver. Protocol constraint:
/// all ZNS UAs must have one so the Treasury can deliver OTP relay notes.
pub fn has_orchard_receiver(ua: &UnifiedAddress) -> bool {
    let zaddr: zcash_address::ZcashAddress = match ua.as_str().parse() {
        Ok(z) => z,
        Err(_) => return false,
    };
    let parsed: zcash_keys::address::Address = match zaddr
        .convert_if_network(zcash_protocol::consensus::MAIN_NETWORK.network_type())
    {
        Ok(p) => p,
        Err(_) => return false,
    };
    matches!(parsed, zcash_keys::address::Address::Unified(ref ua) if ua.orchard().is_some())
}

/// Scans Treasury notes for request memos and derives pending work.
pub fn reconcile(
    ops: &mut OperationalState,
    wallet: &Wallet,
    registry: &Registry,
    cursor_height: BlockHeight,
) -> Vec<WorkItem> {
    use crate::auth::ChallengeKey;

    let pruned = ops.pending_otps.prune(cursor_height);
    if pruned > 0 {
        metrics::inc_otps_never_returned(pruned as u64);
    }
    let reserved = ops.reserved_locators();
    let mut work = Vec::new();
    let mut seen_claims: BTreeSet<Name> = BTreeSet::new();
    let mut seen_no_otp: BTreeSet<ChallengeKey> = BTreeSet::new();
    let mut seen_with_otp: BTreeSet<ChallengeKey> = BTreeSet::new();

    for note in wallet.orchard_notes_for(TREASURY_ACCOUNT) {
        let Ok(request) = RequestMemo::parse(note.memo.as_array()) else { continue };
        let Some(name) = Name::parse(request.name()) else { continue };
        let locator = NoteLocator::orchard(TREASURY_ACCOUNT, note.note.rho());
        if reserved.contains(&locator) { continue }

        match &request {
            RequestMemo::Claim { ua, .. } => {
                if seen_claims.contains(&name) { continue }
                let available = match registry.tip(&name) {
                    None => true,
                    Some(t) => t.action == Action::Release,
                };
                if !available { continue }
                let value = note.note.value().inner();
                if value < CLAIM_PRICE {
                    metrics::inc_request_invalid("insufficient_payment");
                    continue;
                }
                metrics::inc_request_received("claim");
                seen_claims.insert(name.clone());
                work.push(WorkItem::Claim {
                    name, ua: UnifiedAddress::from_string(ua.clone()),
                    payment_locator: locator,
                });
            }
            RequestMemo::Update { ua, otp, .. } => {
                let ua = UnifiedAddress::from_string(ua.clone());
                let tip = match registry.tip(&name) {
                    Some(t) if t.action != Action::Release => t,
                    _ => continue,
                };
                let controller_ua = tip.received()
                    .map(|r| r.payload().ua().clone())
                    .unwrap_or_else(UnifiedAddress::empty);

                match otp {
                    None => {
                        let key = ChallengeKey::new(name.clone(), Action::Update, ua.clone());
                        if ops.pending_otps.contains(&key) || seen_no_otp.contains(&key) { continue }
                        let value = note.note.value().inner();
                        if value < MIN_REQUEST_VALUE {
                            metrics::inc_request_invalid("insufficient_request_value");
                            continue;
                        }
                        if !has_orchard_receiver(&controller_ua) {
                            metrics::inc_request_invalid("no_orchard_receiver");
                            continue;
                        }
                        metrics::inc_request_received("update");
                        seen_no_otp.insert(key);
                        work.push(WorkItem::NeedsOtpRelay {
                            name, action: Action::Update, controller_ua,
                            request_locator: locator, request_value: value,
                        });
                    }
                    Some(otp_bytes) => {
                        let key = ChallengeKey::new(name.clone(), Action::Update, ua.clone());
                        if seen_with_otp.contains(&key) { continue }
                        metrics::inc_request_received("update");
                        seen_with_otp.insert(key);
                        work.push(WorkItem::VerifyAndTransition {
                            name, action: Action::Update, ua, otp: *otp_bytes,
                        });
                    }
                }
            }
            RequestMemo::Release { ua, otp, .. } => {
                let ua = UnifiedAddress::from_string(ua.clone());
                let tip = match registry.tip(&name) {
                    Some(t) if t.action != Action::Release => t,
                    _ => continue,
                };
                let controller_ua = tip.received()
                    .map(|r| r.payload().ua().clone())
                    .unwrap_or_else(UnifiedAddress::empty);

                match otp {
                    None => {
                        let key = ChallengeKey::new(name.clone(), Action::Release, ua.clone());
                        if ops.pending_otps.contains(&key) || seen_no_otp.contains(&key) { continue }
                        let value = note.note.value().inner();
                        if value < MIN_REQUEST_VALUE {
                            metrics::inc_request_invalid("insufficient_request_value");
                            continue;
                        }
                        if !has_orchard_receiver(&controller_ua) {
                            metrics::inc_request_invalid("no_orchard_receiver");
                            continue;
                        }
                        metrics::inc_request_received("release");
                        seen_no_otp.insert(key);
                        work.push(WorkItem::NeedsOtpRelay {
                            name, action: Action::Release, controller_ua,
                            request_locator: locator, request_value: value,
                        });
                    }
                    Some(otp_bytes) => {
                        let key = ChallengeKey::new(name.clone(), Action::Release, ua.clone());
                        if seen_with_otp.contains(&key) { continue }
                        metrics::inc_request_received("release");
                        seen_with_otp.insert(key);
                        work.push(WorkItem::VerifyAndTransition {
                            name, action: Action::Release, ua, otp: *otp_bytes,
                        });
                    }
                }
            }
        }
    }

    // Registry fee-note liquidity (subtracting reserved Ironwood notes).
    let reserved_ironwood = ops.reserved_locators().iter()
        .filter(|loc| matches!(loc, NoteLocator::Ironwood { .. }))
        .count();
    let mut liquidity = RegistryFeeLiquidity::from_wallet(wallet);
    liquidity.fee_note_count = liquidity.fee_note_count.saturating_sub(reserved_ironwood);
    let has_pending_replenish = ops.submissions.values()
        .any(|s| s.kind == SubmissionKind::Replenish && s.confirmed_at.is_none());
    if let Some(plan) = liquidity.treasury_funding_plan() {
        if !has_pending_replenish {
            work.push(WorkItem::ReplenishRegistry { plan });
        }
    }

    // Treasury auto-sweep.
    let balance = wallet.balance(TREASURY_ACCOUNT).into_u64();
    let has_pending_sweep = ops.submissions.values()
        .any(|s| s.kind == SubmissionKind::AutoSweep && s.confirmed_at.is_none());
    if let Some(amount) = sweep::sweep_policy(balance) {
        if !has_pending_sweep {
            work.push(WorkItem::AutoSweep { sweep_amount: amount });
        }
    }

    work
}

/// Marks submissions confirmed if their txid appears in a block.
/// Expires and drains old submissions.
pub fn check_confirmations(ops: &mut OperationalState, txids: &[TxId], height: BlockHeight) {
    for txid in txids {
        if let Some(confirmed) = ops.submissions.get_mut(txid) {
            if confirmed.confirmed_at.is_none() {
                confirmed.confirmed_at = Some(height);
            }
            let confirmed = confirmed.clone();
            tracing::info!(txid = %txid, kind = confirmed.kind.as_str(), "confirmed");
            match confirmed.kind {
                SubmissionKind::Claim => { metrics::inc_names_claimed(); metrics::inc_tx_confirmed("claim"); }
                SubmissionKind::Update => { metrics::inc_names_updated(); metrics::inc_tx_confirmed("update"); }
                SubmissionKind::Release => { metrics::inc_names_released(); metrics::inc_tx_confirmed("release"); }
                SubmissionKind::OtpRelay => { metrics::inc_tx_confirmed("otp_relay"); }
                SubmissionKind::Replenish => { metrics::inc_tx_confirmed("replenish"); }
                SubmissionKind::AutoSweep => { metrics::inc_tx_confirmed("sweep"); }
            }
        }
    }
    let expired: Vec<TxId> = ops.submissions.iter()
        .filter(|(_, s)| s.is_expired(height))
        .map(|(txid, _)| *txid)
        .collect();
    for txid in &expired {
        if let Some(sub) = ops.submissions.remove(txid) {
            tracing::warn!(txid = %sub.txid, kind = sub.kind.as_str(), "expired");
            metrics::inc_tx_expired(sub.kind.as_str());
        }
    }
    let confirmed_txids: Vec<TxId> = ops.submissions.iter()
        .filter(|(_, s)| s.confirmed_at.is_some())
        .map(|(txid, _)| *txid)
        .collect();
    for txid in confirmed_txids { ops.submissions.remove(&txid); }
}
