//! OTP challenge machinery for ZNS name transitions.
//!
//! Kernel-level state shared by both authorities: `PendingOtps` is a field of
//! [`crate::mint::MintState`], the Registry's `authorize_update`/
//! `authorize_release` consume challenges from it, and the Treasury's OTP
//! relay delivers the codes it generates. Also home to the OTP relay memo
//! codec (`ZNS:otp:<otp>:<name>:<verb>:<ua>`).

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use rand::Rng;
use subtle::ConstantTimeEq;
use zcash_protocol::consensus::BlockHeight;
use zeroize::Zeroize;

use crate::mint::{Action, Name, NameCommitment, UnifiedAddress};
use crate::mint::registry::Registry;

// ---------------------------------------------------------------------------
// OTP challenge state
// ---------------------------------------------------------------------------

/// OTPs are scoped to the exact requested transition.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChallengeKey {
    name: Name,
    action: Action,
    /// The canonical UA encoding (string form: upstream's `UnifiedAddress`
    /// implements neither `Hash` nor `Ord`, which keyed sets require).
    ua: String,
    record_commitment: [u8; 32],
}

impl fmt::Debug for ChallengeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeKey(<redacted>)")
    }
}

impl ChallengeKey {
    pub fn new<P: zcash_protocol::consensus::Parameters>(
        network: &P,
        name: Name,
        action: Action,
        ua: UnifiedAddress,
        record_commitment: NameCommitment,
    ) -> Self {
        Self {
            name,
            action,
            ua: ua.encode(network),
            record_commitment: record_commitment.to_bytes(),
        }
    }

    fn matches_registry(&self, registry: &Registry) -> bool {
        registry
            .record(&self.name)
            .is_some_and(|record| record.commitment.to_bytes() == self.record_commitment)
    }
}

/// A six-digit decimal one-time passcode for update/release authorization.
///
/// Stored as a `u32` in the range `0..=999_999`. The canonical relay form is
/// six ASCII decimal digits, including leading zeroes.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OtpCode(u32);

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpCode(<redacted>)")
    }
}

impl OtpCode {
    /// Generates a new uniformly random six-digit decimal OTP.
    ///
    /// The orchestrator records the code only after the relay transaction has
    /// been assembled and definitively accepted for broadcast.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen_range(0..1_000_000))
    }

    /// Returns the six ASCII decimal digits, including leading zeroes.
    pub fn digits(&self) -> [u8; 6] {
        let mut digits = [0u8; 6];
        let mut n = self.0;
        for i in (0..6).rev() {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        digits
    }

    /// Parses six ASCII decimal digits into an OTP.
    ///
    /// Returns `None` if the input is not exactly six ASCII digits.
    pub fn from_digits(digits: &[u8; 6]) -> Option<Self> {
        let mut value = 0u32;
        for &b in digits {
            if !b.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)? + (b - b'0') as u32;
        }
        Some(Self(value))
    }

    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 6] {
        self.digits()
    }

    /// Constructs a code from raw digits. Test-only: the mint's only
    /// production constructor is [`OtpCode::generate`].
    #[cfg(test)]
    pub fn for_test(digits: [u8; 6]) -> Self {
        Self::from_digits(&digits).expect("test digits are valid")
    }
}

pub struct OtpEntry {
    code: OtpCode,
    expires_at: BlockHeight,
}

pub struct PendingOtps {
    pending: HashMap<ChallengeKey, OtpEntry>,
    /// Challenges currently reserved by an in-flight OTP relay transaction.
    /// The orchestrator owns the lifecycle: reserve when the relay is queued,
    /// release on confirm/fail/rewind. A challenge can be issued (in `pending`)
    /// without being reserved.
    reserved: BTreeSet<ChallengeKey>,
}

impl Default for PendingOtps {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingOtps {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            reserved: BTreeSet::new(),
        }
    }

    /// Reserve a challenge for an in-flight OTP relay transaction.
    ///
    /// Returns `true` if the challenge was free and is now reserved; returns
    /// `false` if another relay is already in flight for it.
    pub fn reserve_challenge(&mut self, key: &ChallengeKey) -> bool {
        self.reserved.insert(key.clone())
    }

    /// Release a previously reserved challenge.
    pub fn release_challenge(&mut self, key: &ChallengeKey) {
        self.reserved.remove(key);
    }

    /// True if the challenge is currently reserved by an in-flight relay.
    pub fn is_challenge_reserved(&self, key: &ChallengeKey) -> bool {
        self.reserved.contains(key)
    }

    /// All currently reserved challenges.
    pub fn reserved_challenges(&self) -> &BTreeSet<ChallengeKey> {
        &self.reserved
    }

    /// Release every challenge in `keys` from the reserved set.
    pub fn release_all(&mut self, keys: &BTreeSet<ChallengeKey>) {
        self.reserved.retain(|key| !keys.contains(key));
    }

    /// Discards every relay reservation and deliverable OTP bound to a name
    /// tip that is no longer canonical after a reorg.
    pub fn invalidate_changed_tips(&mut self, registry: &Registry) {
        self.pending.retain(|key, _| key.matches_registry(registry));
        self.reserved.retain(|key| key.matches_registry(registry));
    }

    /// Issues a new six-digit decimal OTP, valid for the configured number of
    /// blocks from `current_height`.
    pub fn record_issued(
        &mut self,
        key: ChallengeKey,
        otp: &OtpCode,
        current_height: BlockHeight,
    ) {
        self.pending.insert(
            key,
            OtpEntry {
                code: OtpCode(otp.0),
                expires_at: current_height + Self::OTP_VALIDITY_BLOCKS,
            },
        );
    }

    /// Verifies and burns the OTP if it is valid.
    pub fn verify(
        &mut self,
        key: &ChallengeKey,
        provided: &[u8; 6],
        current_height: BlockHeight,
    ) -> bool {
        self.prune(current_height);

        let Some(entry) = self.pending.get(key) else {
            return false;
        };

        let Some(provided_code) = OtpCode::from_digits(provided) else {
            return false;
        };

        if bool::from(entry.code.0.ct_eq(&provided_code.0)) {
            self.pending.remove(key); // Burn it!
            return true;
        }
        false
    }

    /// Removes expired OTPs to prevent memory exhaustion.
    /// Prunes expired OTPs and returns how many were removed.
    pub fn prune(&mut self, current_height: BlockHeight) -> usize {
        let before = self.pending.len();
        self.pending
            .retain(|_, entry| u32::from(entry.expires_at) >= u32::from(current_height));
        before - self.pending.len()
    }

    /// Discards a challenge entirely: its relay reservation and any issued
    /// OTP. Called when the relay transaction carrying the OTP is evicted
    /// from the mempool dead — the controller can never decrypt a code whose
    /// transaction will not confirm.
    pub fn discard(&mut self, key: &ChallengeKey) {
        self.pending.remove(key);
        self.reserved.remove(key);
    }

    /// Whether an unexpired OTP exists for this challenge.
    pub fn contains(&self, key: &ChallengeKey) -> bool {
        self.pending.contains_key(key)
    }

    /// Configured OTP validity window, in blocks.
    ///
    /// 24 blocks ≈ 30 minutes at 75s block time.
    pub const OTP_VALIDITY_BLOCKS: u32 = 24;
}

// ---------------------------------------------------------------------------
// OTP relay memo encoding
// ---------------------------------------------------------------------------

/// Returns the canonical verb string for an action in the OTP relay grammar.
///
/// Only `Update` and `Release` are valid relay actions — claims do not use OTPs.
fn verb_str(action: Action) -> Option<&'static str> {
    match action {
        Action::Update => Some("update"),
        Action::Release => Some("release"),
        Action::Claim => None,
    }
}

/// Whether the fixed-width OTP relay form fits in one Zcash memo.
pub fn otp_relay_memo_fits<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    name: &Name,
    action: Action,
    ua: &UnifiedAddress,
) -> bool {
    let Some(verb) = verb_str(action) else {
        return false;
    };
    8usize
        .checked_add(name.as_str().len())
        .and_then(|length| length.checked_add(1 + verb.len()))
        .and_then(|length| length.checked_add(1 + ua.encode(network).len()))
        .and_then(|length| length.checked_add(1 + 6)) // 6-digit OTP
        .is_some_and(|length| length <= 512)
}

/// Encodes an OTP relay memo: `ZNS:otp:<otp>:<name>:<verb>:<ua>`, zero-padded
/// to 512 bytes.
///
/// This memo is sent from the Treasury to the current controller's address so
/// only they can decrypt it and echo the OTP back. Returns `None` if the action
/// is `Claim` (claims don't use OTPs) or if the encoded text exceeds 512 bytes.
pub fn encode_otp_relay_memo<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    name: &Name,
    action: Action,
    ua: &UnifiedAddress,
    otp: &OtpCode,
) -> Option<[u8; 512]> {
    let verb = verb_str(action)?;
    if !otp_relay_memo_fits(network, name, action, ua) {
        return None;
    }

    let ua_field = ua.encode(network);
    let otp_digits = otp.digits();
    let mut memo = [0u8; 512];
    let mut offset = 0usize;
    for field in [
        b"ZNS:otp:".as_slice(),
        otp_digits.as_slice(),
        b":".as_slice(),
        name.as_str().as_bytes(),
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

/// Parses a 512-byte OTP relay memo and returns its OTP digits if the grammar
/// matches. Returns `None` if the memo is not a valid OTP relay memo.
pub fn decode_otp_relay_memo(memo: &[u8; 512]) -> Option<(Name, Action, String, [u8; 6])> {
    let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
    let text = std::str::from_utf8(&memo[..end]).ok()?;

    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 || parts[0] != "ZNS" || parts[1] != "otp" {
        return None;
    }

    let digits = parts[2].as_bytes();
    if digits.len() != 6 || !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut otp = [0u8; 6];
    otp.copy_from_slice(digits);

    let name = Name::parse(parts[3])?;
    let action = match parts[4] {
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    Some((name, action, parts[5].to_string(), otp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MAIN_NETWORK;

    fn test_ua() -> UnifiedAddress {
        crate::mint::NameNote::parse_ua(
            &MAIN_NETWORK,
            "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        )
        .expect("vector UA")
    }

    fn test_name() -> Name {
        Name::parse("alice").unwrap()
    }

    #[test]
    fn round_trip_otp_relay_memo() {
        let name = test_name();
        let ua = test_ua();
        let otp = OtpCode::for_test(*b"004206");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp)
            .expect("memo fits");

        let (decoded_name, decoded_action, decoded_ua, decoded_otp) =
            decode_otp_relay_memo(&memo).expect("memo decodes");

        assert_eq!(decoded_name, name);
        assert_eq!(decoded_action, Action::Update);
        assert_eq!(decoded_ua, ua.encode(&MAIN_NETWORK));
        assert_eq!(decoded_otp, *b"004206");
    }

    #[test]
    fn otp_relay_memo_is_not_a_request_memo() {
        let name = test_name();
        let ua = test_ua();
        let otp = OtpCode::for_test(*b"123456");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp)
            .expect("memo fits");
        let result = crate::mint::treasury::memo::RequestMemo::parse(&memo);
        assert!(result.is_err(), "relay memo must not parse as a request memo");
    }

    #[test]
    fn generate_otp_is_six_digits() {
        let otp = OtpCode::generate();
        let digits = otp.digits();
        assert_eq!(digits.len(), 6);
        assert!(digits.iter().all(|b| b.is_ascii_digit()));
    }
}
