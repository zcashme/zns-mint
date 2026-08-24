//! Shared protocol logic for ZNS minting and wallet operations.

pub mod claim;
pub mod note;
pub mod otp;
pub mod registry;
pub mod treasury;
pub mod v6;

// Re-export note functions so existing `crate::mint::` paths keep working.
pub use note::{
    decode_name_note, decode_name_note_payload, encode_name_note,
    zns_psi_rcm, zns_psi_rcm_raw,
    note_commitment_cmx,
    NameNotePayload,
};

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

/// A ZNS memo: the fixed 512-byte payload carried by a shielded note.
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
#[derive(Clone)]
pub struct Memo(MemoBytes);

impl PartialEq for Memo {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.as_array().ct_eq(other.as_array()))
    }
}
impl Eq for Memo {}

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


// ===========================================================================
// Operational state
// ===========================================================================

use std::collections::{BTreeMap, BTreeSet};

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::value::COIN;

use crate::mint::otp::{ChallengeKey, OtpCode, PendingOtps};
use crate::mint::registry::Registry;
use crate::wallet::NoteLocator;

/// Claim price and request minimum in zatoshis. Protocol policy.
///
/// One ZEC is 100,000,000 zatoshis. Claim payments may exceed this amount;
/// atomic claim settlement returns any excess to the payer.
pub const CLAIM_PRICE: u64 = COIN;
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

    /// Whether this kind represents a name lifecycle transition
    /// (claim, update, release) that locks a name while in flight.
    pub fn is_lifecycle(self) -> bool {
        matches!(self, Self::Claim | Self::Update | Self::Release)
    }
}

/// One submitted transaction awaiting confirmation.
///
/// The txid is the `BTreeMap` key — not a field here. Name locking is
/// derived from `name_binding` + `kind` on in-flight submissions, so no
/// separate lock handle is stored.
#[derive(Clone, Debug)]
pub struct Submission {
    pub kind: SubmissionKind,
    pub expiry_height: BlockHeight,
    pub reserved_notes: Vec<NoteLocator>,
    pub name_binding: Option<NameBinding>,
    pub confirmed_at: Option<BlockHeight>,
}

impl Submission {
    pub fn is_expired(&self, current_height: BlockHeight) -> bool {
        self.confirmed_at.is_none() && current_height > self.expiry_height
    }
}

/// Exclusive ownership of one canonical name state while a lifecycle
/// transaction is being assembled but not yet submitted.
///
/// This is a capability token: only the caller that acquired it via
/// [`OperationalState::reserve_name`] can release it via
/// [`OperationalState::release_name`]. Once the transaction is submitted,
/// the binding moves into the [`Submission`] and the name is locked by
/// derivation — the pre-submit lock is consumed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameLock {
    pub(crate) binding: NameBinding,
}

/// Nonexclusive canonical binding for any name-dependent live operation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameBinding {
    name: Name,
    record_commitment: Option<[u8; 32]>,
}

/// In-memory operational state for the active mint phase.
///
/// Tracks four concerns, each with a lifecycle that ends when the
/// blockchain catches up or time runs out:
///
/// 1. **Notes in flight** — `submissions` maps each broadcast txid to its
///    reserved notes, kind, and expiry. Prevents re-spending. Pruned by
///    [`reconcile`](Self::reconcile) when confirmed or expired.
/// 2. **Names locked** — derived from #1: a name is locked if any
///    unconfirmed lifecycle submission carries its binding, or if a
///    pre-submit lock is held during assembly. No separate set.
/// 3. **OTPs issued** — [`PendingOtps`], already its own well-designed struct.
/// 4. **Recovery cooldown** — `recovery_until` blocks all work after restart
///    until previous-process mempool txs confirm or expire.
pub struct OperationalState {
    pub pending_otps: PendingOtps,
    pub submissions: BTreeMap<TxId, Submission>,
    pre_submit_locks: BTreeSet<NameBinding>,
    recovery_until: Option<BlockHeight>,
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
            pre_submit_locks: BTreeSet::new(),
            recovery_until: None,
        }
    }

    /// Creates Live state after a process restart.
    ///
    /// No unconfirmed submission state survives a restart. Waiting a full
    /// transaction-expiry window prevents reconstruction from immediately
    /// competing with an already-broadcast transaction.
    pub fn recovering(cursor_height: BlockHeight) -> Self {
        Self {
            recovery_until: Some(cursor_height + TX_EXPIRY_BUFFER),
            ..Self::new()
        }
    }

    /// Releases only work whose name-tip binding changed across a reorg.
    /// Unrelated names and non-lifecycle Treasury work remain reserved.
    pub fn invalidate_after_reorg(
        &mut self,
        registry: &Registry,
        wallet: &crate::wallet::Wallet,
        ancestor_height: BlockHeight,
    ) {
        self.pending_otps.invalidate_changed_tips(registry);
        for submission in self.submissions.values_mut() {
            if submission.confirmed_at.is_some_and(|height| height > ancestor_height) {
                submission.confirmed_at = None;
            }
        }
        self.submissions.retain(|_, submission| {
            submission.name_binding.as_ref().is_none_or(|binding| binding.matches_registry(registry))
                && (submission.confirmed_at.is_some()
                    || submission.reserved_notes.iter().all(|locator| wallet.contains_unspent_locator(*locator)))
        });
    }

    pub fn reserved_locators(&self) -> BTreeSet<NoteLocator> {
        self.submissions
            .values()
            .flat_map(|s| s.reserved_notes.iter().copied())
            .collect()
    }

    /// Acquires the only lifecycle lock for `name` at its observed tip.
    ///
    /// Returns a [`NameLock`] capability token. The lock lives in
    /// `pre_submit_locks` until the transaction is recorded via
    /// [`record_submission`](Self::record_submission) (which consumes it)
    /// or released via [`release_name`](Self::release_name) (on failure).
    pub fn reserve_name(
        &mut self,
        name: &Name,
        record_commitment: Option<NameCommitment>,
    ) -> Option<NameLock> {
        if self.is_name_locked(name) {
            return None;
        }

        let binding = self.name_binding(name, record_commitment);
        self.pre_submit_locks.insert(binding.clone());
        Some(NameLock { binding })
    }

    /// Releases a pre-submit name lock acquired by [`reserve_name`](Self::reserve_name).
    ///
    /// No-op if the binding was already consumed by `record_submission`.
    pub fn release_name(&mut self, lock: &NameLock) {
        self.pre_submit_locks.remove(&lock.binding);
    }

    /// Whether `name` is locked by a pre-submit lock or an in-flight lifecycle
    /// submission. OTP relays carry a `name_binding` for reorg invalidation
    /// but do not lock the name — only lifecycle kinds (claim/update/release) do.
    fn is_name_locked(&self, name: &Name) -> bool {
        self.pre_submit_locks.iter().any(|b| &b.name == name)
            || self.submissions.values().any(|s| {
                s.kind.is_lifecycle()
                    && s.name_binding.as_ref().is_some_and(|b| &b.name == name)
            })
    }

    /// Records a submitted transaction, reserves its notes, and consumes any
    /// pre-submit name lock matching the binding.
    ///
    /// For lifecycle submissions (claim/update/release), the `name_binding`
    /// was previously inserted into `pre_submit_locks` by `reserve_name`;
    /// this method removes it — the name is now locked by derivation from
    /// the submission itself. For relays and non-name work, the `remove` is
    /// a no-op (the binding was never in `pre_submit_locks`).
    pub fn record_submission(
        &mut self,
        kind: SubmissionKind,
        txid: TxId,
        reserved_notes: Vec<NoteLocator>,
        name_binding: Option<NameBinding>,
        expiry_height: BlockHeight,
        excluded: &mut BTreeSet<NoteLocator>,
    ) {
        if let Some(ref binding) = name_binding {
            self.pre_submit_locks.remove(binding);
        }
        for loc in &reserved_notes {
            excluded.insert(*loc);
        }
        self.submissions.insert(txid, Submission {
            kind,
            expiry_height,
            reserved_notes,
            name_binding,
            confirmed_at: None,
        });
    }

    /// Reconciles in-flight submissions with confirmed blocks.
    ///
    /// Marks any submission whose txid appears in `confirmed_txids` as
    /// confirmed, then prunes all confirmed and expired submissions in one
    /// pass. Name locking is derived from submissions, so pruning a
    /// submission automatically unlocks its name — no explicit release.
    pub fn reconcile(&mut self, confirmed_txids: &[TxId], height: BlockHeight) {
        // 1. Mark newly confirmed.
        for txid in confirmed_txids {
            if let Some(sub) = self.submissions.get_mut(txid) {
                if sub.confirmed_at.is_none() {
                    sub.confirmed_at = Some(height);
                    tracing::info!(txid = %txid, kind = sub.kind.as_str(), "confirmed");
                }
            }
        }
        // 2. Prune confirmed and expired in one pass.
        self.submissions.retain(|txid, sub| {
            if sub.confirmed_at.is_some() {
                false
            } else if sub.is_expired(height) {
                tracing::warn!(txid = %txid, kind = sub.kind.as_str(), "expired");
                false
            } else {
                true
            }
        });
    }

    /// Binds a nonexclusive relay/submission to one observed Registry tip.
    pub fn name_binding(
        &self,
        name: &Name,
        record_commitment: Option<NameCommitment>,
    ) -> NameBinding {
        NameBinding {
            name: name.clone(),
            record_commitment: record_commitment.map(|commitment| commitment.to_bytes()),
        }
    }

    pub fn recovery_complete(&mut self, current_height: BlockHeight) -> bool {
        match self.recovery_until {
            Some(until) if current_height <= until => false,
            Some(_) => {
                self.recovery_until = None;
                true
            }
            None => true,
        }
    }
}

impl NameLock {
    /// Returns the canonical binding carried into a submitted lifecycle action.
    pub fn binding(&self) -> NameBinding {
        self.binding.clone()
    }
}

impl NameBinding {
    fn matches_registry(&self, registry: &Registry) -> bool {
        match self.record_commitment {
            Some(expected) => registry
                .record(&self.name)
                .is_some_and(|record| record.commitment.to_bytes() == expected),
            None => registry.record(&self.name).is_none(),
        }
    }
}

/// The result of processing a single Treasury note request.
pub struct RequestOutcome {
    pub result: Result<(SubmissionKind, TxId, String, Vec<NoteLocator>), AssemblyError>,
    pub name_lock: Option<NameLock>,
    pub name_binding: Option<NameBinding>,
    pub relay_challenge: Option<(ChallengeKey, OtpCode)>,
}

/// Whether a UA string contains an Orchard receiver. Protocol constraint:
/// all ZNS UAs must have one so the Treasury can deliver OTP relay notes.
pub fn has_orchard_receiver<P: Parameters>(
    network: &P,
    ua: &UnifiedAddress,
) -> bool {
    let zaddr: zcash_address::ZcashAddress = match ua.as_str().parse() {
        Ok(z) => z,
        Err(_) => return false,
    };
    let parsed: zcash_keys::address::Address = match zaddr
        .convert_if_network(network.network_type())
    {
        Ok(p) => p,
        Err(_) => return false,
    };
    matches!(parsed, zcash_keys::address::Address::Unified(ref ua) if ua.orchard().is_some())
}

// ===========================================================================
// Assembly error type
// ===========================================================================

/// Typed error for transaction assembly, signing, and submission.
///
/// Replaces `&'static str` returns throughout the assembly path. Follows the
/// upstream convention of typed error enums (cf. `orchard::builder::SpendError`,
/// `zcash_keys::keys::DerivationError`).
#[derive(Debug, thiserror::Error)]
pub enum AssemblyError {
    #[error("no commitment tree anchor available")]
    NoAnchor,
    #[error("witness not found for note")]
    NoWitness,
    #[error("note not found in wallet")]
    NoteNotFound,
    #[error("note is from the wrong account")]
    WrongAccount,
    #[error("insufficient available notes for funding")]
    InsufficientFunds,
    #[error("note value insufficient for the required fee")]
    InsufficientValue,
    #[error("OTP relay request value must equal exactly twice the ZIP-317 fee")]
    IncorrectRelayValue,
    #[error("builder creation failed")]
    BuilderCreation,
    #[error("builder add operation failed")]
    BuilderAdd,
    #[error("bundle build produced no bundle")]
    BuildFailed,
    #[error("proof creation failed")]
    ProofCreation,
    #[error("proof verification failed before broadcast")]
    ProofVerification,
    #[error("signing authorization failed")]
    SigningAuth,
    #[error("transaction serialization failed")]
    Serialize,
    #[error("wrong bundle version for the pool")]
    WrongVersion,
    #[error("orchard and ironwood circuit versions disagree")]
    CircuitMismatch,
    #[error("action count overflow")]
    ActionOverflow,
    #[error("ZIP-317 fee computation overflow")]
    FeeOverflow,
    #[error("value arithmetic overflow")]
    ValueOverflow,
    #[error("name became unavailable before assembly")]
    NameUnavailable,
    #[error("request predecessor commitment does not match Registry tip")]
    PredecessorMismatch,
    #[error("claims do not use OTPs")]
    ClaimNoOtp,
    #[error("controller UA has no Orchard receiver")]
    NoOrchardReceiver,
    #[error("failed to encode memo")]
    MemoEncode,
    #[error("UFVK not found in wallet")]
    UfvkNotFound,
    #[error("sighash mismatch: effecting data changed after authorization")]
    SighashMismatch,
}
