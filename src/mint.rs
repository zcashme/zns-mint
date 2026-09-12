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
pub use note::{decrypt_name_notes, DecryptedNameNote, Expiry, NameNote};
pub use time::Timestamp;

pub use zcash_keys::address::UnifiedAddress;

use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::AccountId;

use otp::OtpCode;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// First block the mint observes; everything before it is pre-birth.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(3_400_000);

#[cfg(feature = "testnet")]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4_338_933);

/// Regtest birth: first block after the harness's NU6.3 activation (height 4).
#[cfg(feature = "regtest")]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4);

/// The liveness interval: one Julian year (365.25 days), in seconds.
pub const LIVENESS_INTERVAL: i64 = 31_557_600;

/// The longest fixed-term registration the mint will accept: 99 years.
pub const MAX_TERM_YEARS: u64 = 99;

/// Minimum Treasury Ironwood balance after boot sync (0.002 ZEC).
pub const MIN_TREASURY_BALANCE: u64 = 200_000;

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

    /// Parses a request-memo verb.
    fn from_verb(verb: &str) -> Option<Self> {
        match verb {
            "claim" => Some(Action::Claim),
            "update" => Some(Action::Update),
            "release" => Some(Action::Release),
            _ => None,
        }
    }

    /// Parses a whole number of years from a request-memo kind field, e.g. `3y`.
    fn parse_years(kind: &str) -> Option<u64> {
        let digits = kind.strip_suffix('y')?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return None;
        }
        let years = digits.parse().ok()?;
        (years > 0 && years <= crate::mint::MAX_TERM_YEARS).then_some(years)
    }
}

/// The registration period of a name.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Term {
    /// No fixed expiration — the name is held while its liveness checks pass.
    Forever,
    /// A fixed term of N years, whole multiples of [`LIVENESS_INTERVAL`],
    /// capped at [`MAX_TERM_YEARS`].
    Years(u64),
}

/// The mint's request memo format, sent to the Treasury to claim, update, or release a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Create a new registration. The `term` is either `forever` or `<N>y`.
    Claim {
        name: Name,
        ua: UnifiedAddress,
        term: Term,
    },
    /// Rebind and/or extend an existing registration.
    Update {
        name: Name,
        ua: UnifiedAddress,
        extend_years: Option<u64>,
    },
    /// Terminate the registration initiated by expiration or voluntary release.
    Release { name: Name, ua: UnifiedAddress },
}

impl Request {
    /// Decodes valid name request memo sent to the Treasury:
    pub fn decode<P: Parameters>(network: &P, raw: &[u8; 512]) -> Option<Self> {
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        if raw[end..].iter().any(|b| *b != 0) {
            return None;
        }
        let text = core::str::from_utf8(&raw[..end]).ok()?;

        let mut fields = text.split(':');
        if fields.next()? != "ZNS" {
            return None;
        }
        let action = Action::from_verb(fields.next()?)?;

        match action {
            Action::Claim => {
                // ZNS:claim:<term>:<name>:<ua>
                let term = match fields.next()? {
                    "forever" => Term::Forever,
                    years => Term::Years(Action::parse_years(years)?),
                };
                let name = Name::parse(fields.next()?)?;
                let ua_str = fields.next()?;
                if ua_str.is_empty() {
                    return None;
                }
                let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
                    zcash_keys::address::Address::Unified(ua) if ua.orchard().is_some() => ua,
                    _ => return None,
                };
                if fields.next().is_some() {
                    return None;
                }
                Some(Request::Claim { name, ua, term })
            }
            Action::Update => {
                // ZNS:update:<years?>:<name>:<ua>
                let years_str = fields.next()?;
                let extend_years = if years_str.is_empty() {
                    None
                } else {
                    Some(Action::parse_years(years_str)?)
                };
                let name = Name::parse(fields.next()?)?;
                let ua_str = fields.next()?;
                if ua_str.is_empty() {
                    return None;
                }
                let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
                    zcash_keys::address::Address::Unified(ua) if ua.orchard().is_some() => ua,
                    _ => return None,
                };
                if fields.next().is_some() {
                    return None;
                }
                Some(Request::Update { name, ua, extend_years })
            }
            Action::Release => {
                // ZNS:release:<name>:<ua>
                let name = Name::parse(fields.next()?)?;
                let ua_str = fields.next()?;
                if ua_str.is_empty() {
                    return None;
                }
                let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
                    zcash_keys::address::Address::Unified(ua) if ua.orchard().is_some() => ua,
                    _ => return None,
                };
                if fields.next().is_some() {
                    return None;
                }
                Some(Request::Release { name, ua })
            }
        }
    }
}

/// A mint-issued challenge to a wallet, proving that the wallet controls a name via shielded-memos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub code: OtpCode,
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
}

impl Challenge {
    /// Encodes the challenge memo.
    pub fn encode<P: Parameters>(&self, network: &P) -> Option<[u8; 512]> {
        if self.action == Action::Claim {
            return None;
        }
        let verb = self.action.as_str();

        let ua_field = self.ua.encode(network);
        let otp_digits = self.code.digits();
        let mut memo = [0u8; 512];
        let mut offset = 0usize;
        for field in [
            b"ZNS:otp:".as_slice(),
            otp_digits.as_slice(),
            b":".as_slice(),
            self.name.as_str().as_bytes(),
            b":".as_slice(),
            verb.as_bytes(),
            b":".as_slice(),
            ua_field.as_bytes(),
        ] {
            let end = offset + field.len();
            memo[offset..end].copy_from_slice(field);
            offset = end;
        }
        Some(memo)
    }

    /// Decodes a relay sentence. The verb is `update` or `release` —
    /// challenges never claim — and the UA must carry an Orchard-family
    /// receiver.
    pub fn decode<P: Parameters>(network: &P, memo: &[u8; 512]) -> Option<Self> {
        let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
        if memo[end..].iter().any(|&b| b != 0) {
            return None;
        }
        let text = std::str::from_utf8(&memo[..end]).ok()?;

        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() != 6 || parts[0] != "ZNS" || parts[1] != "otp" {
            return None;
        }

        let digits = parts[2].as_bytes();
        if digits.len() != 6 || !digits.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let code = OtpCode::from_digits(digits.try_into().ok()?)?;

        let name = Name::parse(parts[3])?;
        let action = match parts[4] {
            "update" => Action::Update,
            "release" => Action::Release,
            _ => return None,
        };

        let ua = match zcash_keys::address::Address::decode(network, parts[5])? {
            zcash_keys::address::Address::Unified(ua) if ua.orchard().is_some() => ua,
            _ => return None,
        };

        Some(Self {
            code,
            name,
            action,
            ua,
        })
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
