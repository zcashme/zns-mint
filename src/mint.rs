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

use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::AccountId;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// First block the mint observes; everything before it is pre-birth.
#[cfg(not(feature = "regtest"))]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(3_400_000);

/// Regtest birth: first block after the harness's NU6.3 activation (height 4).
#[cfg(feature = "regtest")]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4);

/// The liveness interval: one Julian year (365.25 days), in seconds.
///
/// Registration terms are sold in whole multiples of it, and every
/// registration — forever or fixed-term — must pass a liveness check once
/// per interval or the Mint releases it.
pub const LIVENESS_INTERVAL: i64 = 31_557_600;

/// The longest term money can buy: 99 years from the current block.
///
/// Presence, not prepayment, holds a name past a decade — no stack of
/// extensions can push `expires_at` beyond the fence.
pub const MAX_TERM_YEARS: u64 = 99;

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

    /// Parses a whole number of years in canonical `Ny` form: decimal
    /// digits, no sign, no leading zeroes, at least one, at most
    /// [`MAX_TERM_YEARS`].
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

    /// Parses a 512-byte request memo sent to the Treasury:
    ///
    /// - `ZNS:claim:<name>:<ua>:<kind>` — `kind` is `forever` or `<N>y`
    /// - `ZNS:update:<name>:<ua>[:<N>y]` — `<N>y` requests an extension
    /// - `ZNS:release:<name>:<ua>`
    ///
    /// Per-verb arity is enforced here: a release with a term, an update
    /// with `forever`, or a claim without a kind is not a request memo.
    /// The UA must carry an Orchard-family receiver — Ironwood delivery
    /// (refunds, relays) has no other path.
    pub fn parse_request<P: Parameters>(network: &P, raw: &[u8; 512]) -> Option<Request> {
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        if raw[end..].iter().any(|b| *b != 0) {
            return None;
        }
        let text = core::str::from_utf8(&raw[..end]).ok()?;

        let mut fields = text.split(':');
        if fields.next()? != "ZNS" {
            return None;
        }
        let action = Self::from_verb(fields.next()?)?;
        let name = Name::parse(fields.next()?)?;

        let ua_str = fields.next()?;
        if ua_str.is_empty() {
            return None;
        }
        let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
            zcash_keys::address::Address::Unified(ua) if ua.orchard().is_some() => ua,
            _ => return None,
        };

        let kind = fields.next();
        // No verb carries a second term-like field.
        if fields.next().is_some() {
            return None;
        }

        match action {
            Action::Claim => {
                let term = match kind {
                    Some("forever") => Term::Forever,
                    Some(years) => Term::Years(Self::parse_years(years)?),
                    // A claim always states its term.
                    None => return None,
                };
                Some(Request::Claim { name, ua, term })
            }
            Action::Update => {
                let extend_years = match kind {
                    None => None,
                    Some(years) => Some(Self::parse_years(years)?),
                };
                Some(Request::Update { name, ua, extend_years })
            }
            Action::Release => {
                if kind.is_some() {
                    return None;
                }
                Some(Request::Release { name, ua })
            }
        }
    }
}

/// The registration term a claim asks for.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Term {
    /// No fixed expiration — the name is held while its liveness checks pass.
    Forever,
    /// A fixed term of N years, whole multiples of [`LIVENESS_INTERVAL`],
    /// capped at [`MAX_TERM_YEARS`].
    Years(u64),
}

/// A parsed request memo — each verb carries exactly its own fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Register `name` → `ua` on `term`.
    Claim {
        name: Name,
        ua: UnifiedAddress,
        term: Term,
    },
    /// Rebind and/or extend an existing registration. `extend_years` is the
    /// optional `+Ny` extension; a bare update changes nothing but the
    /// liveness clock.
    Update {
        name: Name,
        ua: UnifiedAddress,
        extend_years: Option<u64>,
    },
    /// Terminate the registration.
    Release { name: Name, ua: UnifiedAddress },
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

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    fn padded(s: &str) -> [u8; 512] {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m
    }

    fn test_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    fn parse(s: &str) -> Option<Request> {
        Action::parse_request(&MainNetwork, &padded(s))
    }

    #[test]
    fn claims_parse_their_kinds() {
        let name = Name::parse("alice").unwrap();
        let ua = test_ua();

        assert_eq!(
            parse(&format!("ZNS:claim:alice:{TEST_UA}:forever")).unwrap(),
            Request::Claim {
                name: name.clone(),
                ua: ua.clone(),
                term: Term::Forever
            }
        );
        assert_eq!(
            parse(&format!("ZNS:claim:alice:{TEST_UA}:1y")).unwrap(),
            Request::Claim {
                name: name.clone(),
                ua: ua.clone(),
                term: Term::Years(1)
            }
        );
        assert_eq!(
            parse(&format!("ZNS:claim:alice:{TEST_UA}:99y")).unwrap(),
            Request::Claim {
                name: name.clone(),
                ua: ua.clone(),
                term: Term::Years(99)
            }
        );
        assert_eq!(
            parse(&format!("ZNS:claim:alice:{TEST_UA}:10y")).unwrap(),
            Request::Claim {
                name,
                ua,
                term: Term::Years(10)
            }
        );
    }

    #[test]
    fn update_parses_with_and_without_extension() {
        let name = Name::parse("alice").unwrap();
        let ua = test_ua();

        assert_eq!(
            parse(&format!("ZNS:update:alice:{TEST_UA}")).unwrap(),
            Request::Update {
                name: name.clone(),
                ua: ua.clone(),
                extend_years: None
            }
        );
        assert_eq!(
            parse(&format!("ZNS:update:alice:{TEST_UA}:3y")).unwrap(),
            Request::Update {
                name,
                ua,
                extend_years: Some(3)
            }
        );
    }

    #[test]
    fn release_parses_without_a_term() {
        assert_eq!(
            parse(&format!("ZNS:release:alice:{TEST_UA}")).unwrap(),
            Request::Release {
                name: Name::parse("alice").unwrap(),
                ua: test_ua()
            }
        );
    }

    #[test]
    fn rejects_malformed_kinds() {
        for kind in ["0y", "03y", "100y", "3", "y", "Forever", "forevers", ""] {
            assert!(
                parse(&format!("ZNS:claim:alice:{TEST_UA}:{kind}")).is_none(),
                "claim kind {kind:?} must reject"
            );
            assert!(
                parse(&format!("ZNS:update:alice:{TEST_UA}:{kind}")).is_none(),
                "update kind {kind:?} must reject"
            );
        }
        // A release never carries a term.
        assert!(parse(&format!("ZNS:release:alice:{TEST_UA}:1y")).is_none());
        // A claim never omits its kind.
        assert!(parse(&format!("ZNS:claim:alice:{TEST_UA}")).is_none());
    }

    #[test]
    fn rejects_unknown_verbs_and_non_memos() {
        assert!(parse(&format!("ZNS:otp:alice:{TEST_UA}")).is_none());
        assert!(parse("hello world").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn rejects_invalid_names_and_extra_fields() {
        assert!(parse(&format!("ZNS:claim:INVALID:{TEST_UA}:forever")).is_none());
        assert!(parse(&format!("ZNS:claim:alice:{TEST_UA}:1y:extra")).is_none());
    }

    #[test]
    fn rejects_uas_without_an_orchard_receiver() {
        // Ironwood delivery (refunds, relays) has no other path: a request
        // UA without an Orchard receiver is not a request memo.
        let keys = crate::key::TreasuryKeys::derive(
            &MainNetwork,
            &secrecy::Secret::new(zcash_address::test_vectors::UNIFIED[0].root_seed),
        );
        let ua = keys
            .fvk()
            .address(
                zip32::DiversifierIndex::from(
                    zcash_address::test_vectors::UNIFIED[0].diversifier_index,
                ),
                zcash_keys::keys::UnifiedAddressRequest::unsafe_custom(
                    zcash_keys::keys::ReceiverRequirement::Omit,
                    zcash_keys::keys::ReceiverRequirement::Require,
                    zcash_keys::keys::ReceiverRequirement::Omit,
                ),
            )
            .unwrap();
        let ua_str = ua.encode(&MainNetwork);
        assert!(ua.orchard().is_none());
        assert!(parse(&format!("ZNS:claim:alice:{ua_str}:forever")).is_none());
    }
}
