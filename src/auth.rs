//! In-band OTP authorization policy for update/release requests.
//!
//! OTPs are transported by shielded memos:
//!
//! 1. user -> Treasury: `ZNS:update:<name>:<ua>` or `ZNS:release:<name>:<ua>`
//! 2. Treasury -> current controller: `ZNS:otp:<name>:<verb>:<ua>:<otp>`
//! 3. user -> Treasury: same request with `:<otp>` appended
use std::collections::{BTreeSet, HashMap};
use std::fmt;

use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::mint::{Action, Name, UnifiedAddress};

/// OTPs are scoped to the exact requested transition.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChallengeKey {
    name: Name,
    action: Action,
    ua: UnifiedAddress,
}

impl fmt::Debug for ChallengeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeKey(<redacted>)")
    }
}

impl ChallengeKey {
    pub fn new(name: Name, action: Action, ua: UnifiedAddress) -> Self {
        Self { name, action, ua }
    }
}
use zcash_protocol::consensus::BlockHeight;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OtpSecret([u8; 16]);

/// A newly issued OTP held only long enough to construct its relay memo.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OtpCode([u8; 16]);

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpCode(<redacted>)")
    }
}

impl OtpCode {
    fn lowercase_hex(&self) -> [u8; 32] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0u8; 32];
        for (index, byte) in self.0.iter().copied().enumerate() {
            encoded[index * 2] = HEX[usize::from(byte >> 4)];
            encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        encoded
    }

    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 16] {
        self.0
    }
}

pub struct OtpEntry {
    otp: OtpSecret,
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

    /// Issues a new highly secure 128-bit hex OTP, valid for the configured
    /// number of blocks from `current_height`.
    pub fn issue(&mut self, key: ChallengeKey, current_height: BlockHeight) -> OtpCode {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);

        self.pending.insert(
            key,
            OtpEntry {
                otp: OtpSecret(bytes),
                expires_at: current_height + Self::OTP_VALIDITY_BLOCKS,
            },
        );

        OtpCode(bytes)
    }

    /// Verifies and burns the OTP if it is valid.
    pub fn verify(
        &mut self,
        key: &ChallengeKey,
        provided: &[u8; 16],
        current_height: BlockHeight,
    ) -> bool {
        self.prune(current_height);

        if let Some(entry) = self.pending.get(key) {
            if bool::from(entry.otp.0.ct_eq(provided)) {
                self.pending.remove(key); // Burn it!
                return true;
            }
        }
        false
    }

    /// Removes expired OTPs to prevent memory exhaustion.
    pub fn prune(&mut self, current_height: BlockHeight) {
        self.pending
            .retain(|_, entry| u32::from(entry.expires_at) >= u32::from(current_height));
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
pub fn otp_relay_memo_fits(name: &Name, action: Action, ua: &UnifiedAddress) -> bool {
    let Some(verb) = verb_str(action) else {
        return false;
    };
    8usize
        .checked_add(name.as_str().len())
        .and_then(|length| length.checked_add(1 + verb.len()))
        .and_then(|length| length.checked_add(1 + ua.as_str().len()))
        .and_then(|length| length.checked_add(1 + 32))
        .is_some_and(|length| length <= 512)
}

/// Encodes an OTP relay memo: `ZNS:otp:<name>:<verb>:<ua>:<otp>`, zero-padded
/// to 512 bytes.
///
/// This memo is sent from the Treasury to the current controller's address so
/// only they can decrypt it and echo the OTP back. Returns `None` if the action
/// is `Claim` (claims don't use OTPs) or if the encoded text exceeds 512 bytes.
pub fn encode_otp_relay_memo(
    name: &Name,
    action: Action,
    ua: &UnifiedAddress,
    otp: &OtpCode,
) -> Option<[u8; 512]> {
    let verb = verb_str(action)?;
    if !otp_relay_memo_fits(name, action, ua) {
        return None;
    }

    let mut memo = [0u8; 512];
    let mut otp_hex = otp.lowercase_hex();
    let mut offset = 0usize;
    for field in [
        b"ZNS:otp:".as_slice(),
        name.as_str().as_bytes(),
        b":".as_slice(),
        verb.as_bytes(),
        b":".as_slice(),
        ua.as_str().as_bytes(),
        b":".as_slice(),
        otp_hex.as_slice(),
    ] {
        let end = offset + field.len();
        memo[offset..end].copy_from_slice(field);
        offset = end;
    }
    otp_hex.zeroize();
    Some(memo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_memo_encodes_update() {
        let name = Name::parse("alice").unwrap();
        let ua = UnifiedAddress::from_string("u1test".into());
        let otp = OtpCode([0xabu8; 16]);

        let memo = encode_otp_relay_memo(&name, Action::Update, &ua, &otp).unwrap();

        let expected = "ZNS:otp:alice:update:u1test:abababababababababababababababab";
        let end = memo.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
        let text = core::str::from_utf8(&memo[..end]).unwrap();
        assert_eq!(text, expected);
    }

    #[test]
    fn relay_memo_encodes_release() {
        let name = Name::parse("bob").unwrap();
        let ua = UnifiedAddress::from_string("u1current".into());
        let otp = OtpCode([0xcdu8; 16]);

        let memo = encode_otp_relay_memo(&name, Action::Release, &ua, &otp).unwrap();

        let end = memo.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
        let text = core::str::from_utf8(&memo[..end]).unwrap();
        assert_eq!(
            text,
            "ZNS:otp:bob:release:u1current:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        );
    }

    #[test]
    fn relay_memo_rejects_claim() {
        let name = Name::parse("alice").unwrap();
        let ua = UnifiedAddress::from_string("u1test".into());
        let otp = OtpCode([0u8; 16]);
        assert!(encode_otp_relay_memo(&name, Action::Claim, &ua, &otp).is_none());
    }

    #[test]
    fn relay_memo_is_not_a_request_memo() {
        // OTP relay memos use verb "otp", which is not a valid request verb.
        // treasury::memo::RequestMemo::parse must reject them.
        let name = Name::parse("alice").unwrap();
        let ua = UnifiedAddress::from_string("u1test".into());
        let otp = OtpCode([0xdeu8; 16]);

        let memo = encode_otp_relay_memo(&name, Action::Update, &ua, &otp).unwrap();
        let result = crate::treasury::memo::RequestMemo::parse(&memo);
        assert!(
            result.is_err(),
            "relay memo must not parse as a request memo"
        );
    }

    #[test]
    fn relay_memo_is_exactly_512_bytes() {
        let name = Name::parse("a").unwrap();
        let ua = UnifiedAddress::from_string("u1".into());
        let otp = OtpCode([0xffu8; 16]);
        let memo = encode_otp_relay_memo(&name, Action::Update, &ua, &otp).unwrap();
        assert_eq!(memo.len(), 512);
    }
}
