//! Shared protocol logic for ZNS minting and wallet operations.

pub mod mtp;
pub mod note;
pub mod otp;
pub mod registry;
pub mod signer;
pub mod treasury;

/// The mint's authoritative position on the Zcash chain.
pub use zcash_client_backend::data_api::BlockMetadata as ChainTip;

// The Name Note type and its codec.
pub use note::{
    decode_name_note, decode_name_note_tuple, decrypt_name_notes, note_commitment_cmx,
    parse_timestamp_canonical, zns_psi_rcm_raw, DecryptedNameNote, Expiry, NameNote,
};
pub use time::Timestamp;

pub use zcash_keys::address::UnifiedAddress;

use zip32::AccountId;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

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

/// A ZcashName
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

// ===========================================================================
// Protocol constants and settlement types
// ===========================================================================

use zcash_client_backend::wallet::NoteId;
use zcash_primitives::transaction::TxId;
use zcash_protocol::value::{Zatoshis, COIN};

/// Claim price and request minimum in zatoshis.
///
/// One ZEC is 100,000,000 zatoshis. Claim payments may exceed this amount;
/// atomic claim settlement returns any excess to the payer.
pub const CLAIM_PRICE: Zatoshis = Zatoshis::const_from_u64(COIN);

/// What kind of transaction was broadcast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// The result of processing a single Treasury note request.
pub struct RequestOutcome {
    pub result: Result<(SubmissionKind, TxId, String, Vec<NoteId>), AssemblyError>,
    pub relay_otp: Option<crate::mint::otp::OtpRequest>,
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
    #[error("name became unavailable before assembly")]
    NameUnavailable,
    #[error("request predecessor commitment does not match Registry tip")]
    PredecessorMismatch,
    #[error("UFVK not found in wallet")]
    UfvkNotFound,
    #[error("sighash mismatch: effecting data changed after authorization")]
    SighashMismatch,
    #[error("upstream wallet transfer failed: {0}")]
    UpstreamTransfer(String),
}
