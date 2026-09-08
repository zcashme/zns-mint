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

impl Request {
    /// Decodes a 512-byte request memo sent to the Treasury:
    ///
    /// - `ZNS:claim:<name>:<ua>:<kind>` — `kind` is `forever` or `<N>y`
    /// - `ZNS:update:<name>:<ua>[:<N>y]` — `<N>y` requests an extension
    /// - `ZNS:release:<name>:<ua>`
    ///
    /// Per-verb arity is enforced here: a release with a term, an update
    /// with `forever`, or a claim without a kind is not a request memo.
    /// The UA must carry an Orchard-family receiver — Ironwood delivery
    /// (relays) has no other path.
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
                    Some(years) => Term::Years(Action::parse_years(years)?),
                    // A claim always states its term.
                    None => return None,
                };
                Some(Request::Claim { name, ua, term })
            }
            Action::Update => {
                let extend_years = match kind {
                    None => None,
                    Some(years) => Some(Action::parse_years(years)?),
                };
                Some(Request::Update {
                    name,
                    ua,
                    extend_years,
                })
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

/// The relay sentence: `ZNS:otp:<code>:<name>:<verb>:<ua>`
///
/// Spoken in both directions — the mint encodes it as a relay challenge to
/// the controller, and the controller echoes it back to the Treasury to
/// prove authority. The verb is `update` or `release` — challenges never
/// claim. The UA is the request's target address and must carry an
/// Orchard-family receiver; Ironwood delivery (relays) has no other path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub code: OtpCode,
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
}

impl Challenge {
    /// Encodes the relay sentence, NUL-padded to 512 bytes.
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

    fn test_name() -> Name {
        Name::parse("alice").unwrap()
    }

    #[test]
    fn claims_parse_their_kinds() {
        let name = test_name();
        let ua = test_ua();

        assert_eq!(
            Request::decode(&MainNetwork, &padded(&format!("ZNS:claim:alice:{TEST_UA}:forever")))
                .unwrap(),
            Request::Claim {
                name: name.clone(),
                ua: ua.clone(),
                term: Term::Forever
            }
        );
        assert_eq!(
            Request::decode(&MainNetwork, &padded(&format!("ZNS:claim:alice:{TEST_UA}:1y")))
                .unwrap(),
            Request::Claim {
                name: name.clone(),
                ua: ua.clone(),
                term: Term::Years(1)
            }
        );
        assert_eq!(
            Request::decode(&MainNetwork, &padded(&format!("ZNS:claim:alice:{TEST_UA}:99y")))
                .unwrap(),
            Request::Claim {
                name: name.clone(),
                ua: ua.clone(),
                term: Term::Years(99)
            }
        );
        assert_eq!(
            Request::decode(&MainNetwork, &padded(&format!("ZNS:claim:alice:{TEST_UA}:10y")))
                .unwrap(),
            Request::Claim {
                name,
                ua,
                term: Term::Years(10)
            }
        );
    }

    #[test]
    fn update_parses_with_and_without_extension() {
        let name = test_name();
        let ua = test_ua();

        assert_eq!(
            Request::decode(&MainNetwork, &padded(&format!("ZNS:update:alice:{TEST_UA}")))
                .unwrap(),
            Request::Update {
                name: name.clone(),
                ua: ua.clone(),
                extend_years: None
            }
        );
        assert_eq!(
            Request::decode(&MainNetwork, &padded(&format!("ZNS:update:alice:{TEST_UA}:3y")))
                .unwrap(),
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
            Request::decode(&MainNetwork, &padded(&format!("ZNS:release:alice:{TEST_UA}")))
                .unwrap(),
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
                Request::decode(&MainNetwork, &padded(&format!("ZNS:claim:alice:{TEST_UA}:{kind}")))
                    .is_none(),
                "claim kind {kind:?} must reject"
            );
            assert!(
                Request::decode(&MainNetwork, &padded(&format!("ZNS:update:alice:{TEST_UA}:{kind}")))
                    .is_none(),
                "update kind {kind:?} must reject"
            );
        }
        // A release never carries a term.
        assert!(Request::decode(
            &MainNetwork,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:1y"))
        )
        .is_none());
        // A claim never omits its kind.
        assert!(Request::decode(
            &MainNetwork,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}"))
        )
        .is_none());
    }

    #[test]
    fn rejects_unknown_verbs_and_non_memos() {
        assert!(Request::decode(
            &MainNetwork,
            &padded(&format!("ZNS:otp:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(Request::decode(&MainNetwork, &padded("hello world")).is_none());
        assert!(Request::decode(&MainNetwork, &padded("")).is_none());
    }

    #[test]
    fn rejects_invalid_names_and_extra_fields() {
        assert!(Request::decode(
            &MainNetwork,
            &padded(&format!("ZNS:claim:INVALID:{TEST_UA}:forever"))
        )
        .is_none());
        assert!(Request::decode(
            &MainNetwork,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}:1y:extra"))
        )
        .is_none());
    }

    #[test]
    fn challenge_round_trips_update_and_release() {
        for action in [Action::Update, Action::Release] {
            let challenge = Challenge {
                code: OtpCode::for_test(*b"004206"),
                name: test_name(),
                action,
                ua: test_ua(),
            };
            let memo = challenge.encode(&MainNetwork).expect("memo fits");
            assert_eq!(Challenge::decode(&MainNetwork, &memo).unwrap(), challenge);
        }
    }

    #[test]
    fn challenge_encodes_the_canonical_format() {
        let challenge = Challenge {
            code: OtpCode::for_test(*b"004206"),
            name: test_name(),
            action: Action::Update,
            ua: test_ua(),
        };
        let memo = challenge.encode(&MainNetwork).expect("memo fits");

        let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
        let text = std::str::from_utf8(&memo[..end]).unwrap();
        assert!(text.starts_with("ZNS:otp:004206:alice:update:"));
        assert!(text.ends_with(&TEST_UA));
    }

    #[test]
    fn challenge_rejects_the_legacy_otp_last_format() {
        let legacy = format!("ZNS:otp:alice:update:{}:004206", TEST_UA);
        assert!(Challenge::decode(&MainNetwork, &padded(&legacy)).is_none());
    }

    #[test]
    fn challenge_rejects_non_zero_bytes_after_nul_padding() {
        let challenge = Challenge {
            code: OtpCode::for_test(*b"004206"),
            name: test_name(),
            action: Action::Update,
            ua: test_ua(),
        };
        let mut memo = challenge.encode(&MainNetwork).expect("memo fits");

        let first_nul = memo.iter().position(|&b| b == 0).unwrap();
        memo[first_nul + 10] = 0x42;

        assert!(Challenge::decode(&MainNetwork, &memo).is_none());
    }

    #[test]
    fn challenges_never_claim() {
        let claim = Challenge {
            code: OtpCode::for_test(*b"004206"),
            name: test_name(),
            action: Action::Claim,
            ua: test_ua(),
        };
        assert!(claim.encode(&MainNetwork).is_none());

        let ua = test_ua();
        let wire = format!("ZNS:otp:004206:alice:claim:{TEST_UA}");
        assert!(Challenge::decode(&MainNetwork, &padded(&wire)).is_none());
    }
}
