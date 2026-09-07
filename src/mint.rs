//! Shared protocol logic for ZNS minting and wallet operations.

pub mod mtp;
pub mod note;
pub mod otp;
pub mod pricing;
pub mod registry;

pub mod treasury;

/// The mint's authoritative position on the Zcash chain.
pub use zcash_client_backend::data_api::BlockMetadata as ChainTip;

// The Name Note type and its codec.
pub use note::{decode_name_note, decrypt_name_notes, DecryptedNameNote, Expiry, NameNote};
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
    ///
    /// Per §3 the name field is 1–63 bytes of ASCII `a`–`z` and `0`–`9` —
    /// no hyphens, no separators.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        if bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9')) {
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

use zcash_protocol::value::Zatoshis;

// The claim price is `Oracle::quote_forever(name)`: the USD name schedule
// converted to zats at the oracle's daily rate.

/// Whole-dollar refund fee, settled by [`grid_usd`] at the daily rate,
/// rounded up to the next 100,000-zat step.
pub const REFUND_FEE_USD: u64 = 1;

/// Policy fees settle in steps of 100,000 zats.
const FEE_STEP: u64 = 100_000;

/// Settles a whole-dollar policy amount on the fee lattice: converted at
/// the daily rate, rounded up to the next [`FEE_STEP`].
pub fn grid_usd(oracle: &pricing::Oracle, usd: u64) -> Zatoshis {
    let raw = usd * oracle.current().into_u64();
    Zatoshis::from_u64(raw.next_multiple_of(FEE_STEP))
        .expect("step rounding adds less than one step")
}
