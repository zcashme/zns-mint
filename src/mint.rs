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

use zcash_primitives::transaction::TxId;
use zcash_protocol::value::{Zatoshis, COIN};

/// Claim price and request minimum in zatoshis.
///
/// One ZEC is 100,000,000 zatoshis. Claim payments may exceed this amount;
/// atomic claim settlement returns any excess to the payer.
pub const CLAIM_PRICE: Zatoshis = Zatoshis::const_from_u64(COIN);

/// Flat charge taken from a claim payment whenever the mint processes the
/// request without completing it — either the excess over [`CLAIM_PRICE`]
/// (refunded minus this fee) or the entire payment when the claim is
/// rejected (stale, underpaid, or the name is live). Saturates to "the
/// Treasury retains the payment in full" when the payment is too small to
/// cover it, so every rejected claim is self-funding.
pub const PROCESSING_FEE: Zatoshis = Zatoshis::const_from_u64(10_000);

/// The result of processing a single Treasury note request: the txid of the
/// issued OTP relay payment, or the relay pipeline's error.
pub struct RequestOutcome {
    pub result: Result<
        TxId,
        zcash_client_backend::data_api::wallet::ProposeTransferErrT<
            crate::wallet::Wallet,
            std::convert::Infallible,
            zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector<
                crate::wallet::Wallet,
            >,
            zcash_client_backend::fees::standard::SingleOutputChangeStrategy<crate::wallet::Wallet>,
        >,
    >,
    pub relay_otp: Option<crate::mint::otp::OtpRequest>,
}
