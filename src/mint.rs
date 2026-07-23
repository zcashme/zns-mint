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
