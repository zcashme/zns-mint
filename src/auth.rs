//! In-band OTP authorization policy for update/release requests.
//!
//! OTPs are transported by shielded memos:
//!
//! 1. user -> Treasury: `ZNS:update:<name>:<ua>` or `ZNS:release:<name>:<ua>`
//! 2. Treasury -> current controller: `ZNS:otp:<name>:<verb>:<ua>:<otp>`
//! 3. user -> Treasury: same request with `:<otp>` appended
use std::collections::HashMap;

use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::mint::{Action, Name, UnifiedAddress};

/// OTPs are scoped to the exact requested transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChallengeKey {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
}

impl ChallengeKey {
    pub fn new(name: Name, action: Action, ua: UnifiedAddress) -> Self {
        Self { name, action, ua }
    }
}
use zcash_protocol::consensus::BlockHeight;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OtpSecret(pub [u8; 16]);

pub struct OtpEntry {
    pub otp: OtpSecret,
    pub expires_at: BlockHeight,
}

pub struct PendingOtps {
    pending: HashMap<ChallengeKey, OtpEntry>,
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
        }
    }

    /// Issues a new highly secure 128-bit hex OTP, valid for 50 blocks.
    pub fn issue(&mut self, key: ChallengeKey, current_height: BlockHeight) -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let otp_hex = hex::encode(bytes);

        self.pending.insert(
            key,
            OtpEntry {
                otp: OtpSecret(bytes),
                expires_at: current_height + 50,
            },
        );

        otp_hex
    }

    /// Verifies and burns the OTP if it is valid.
    pub fn verify(&mut self, key: &ChallengeKey, provided: &[u8; 16], current_height: BlockHeight) -> bool {
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
    otp: &str,
) -> Option<[u8; 512]> {
    let verb = verb_str(action)?;
    let text = format!("ZNS:otp:{}:{}:{}:{}", name.as_str(), verb, ua.as_str(), otp);

    if text.len() > 512 {
        return None;
    }

    let mut memo = [0u8; 512];
    memo[..text.len()].copy_from_slice(text.as_bytes());
    Some(memo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_memo_encodes_update() {
        let name = Name::parse("alice").unwrap();
        let ua = UnifiedAddress::from_string("u1test".into());
        let otp = "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";

        let memo = encode_otp_relay_memo(&name, Action::Update, &ua, otp).unwrap();

        let expected = format!("ZNS:otp:alice:update:u1test:{otp}");
        let end = memo.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
        let text = core::str::from_utf8(&memo[..end]).unwrap();
        assert_eq!(text, expected);
    }

    #[test]
    fn relay_memo_encodes_release() {
        let name = Name::parse("bob").unwrap();
        let ua = UnifiedAddress::from_string("u1current".into());
        let otp = "aabbccdd";

        let memo = encode_otp_relay_memo(&name, Action::Release, &ua, otp).unwrap();

        let end = memo.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
        let text = core::str::from_utf8(&memo[..end]).unwrap();
        assert_eq!(text, "ZNS:otp:bob:release:u1current:aabbccdd");
    }

    #[test]
    fn relay_memo_rejects_claim() {
        let name = Name::parse("alice").unwrap();
        let ua = UnifiedAddress::from_string("u1test".into());
        assert!(encode_otp_relay_memo(&name, Action::Claim, &ua, "otp").is_none());
    }

    #[test]
    fn relay_memo_is_not_a_request_memo() {
        // OTP relay memos use verb "otp", which is not a valid request verb.
        // treasury::memo::RequestMemo::parse must reject them.
        let name = Name::parse("alice").unwrap();
        let ua = UnifiedAddress::from_string("u1test".into());
        let otp = "deadbeefdeadbeefdeadbeefdeadbeef";

        let memo = encode_otp_relay_memo(&name, Action::Update, &ua, otp).unwrap();
        let result = crate::treasury::memo::RequestMemo::parse(&memo);
        assert!(result.is_err(), "relay memo must not parse as a request memo");
    }

    #[test]
    fn relay_memo_is_exactly_512_bytes() {
        let name = Name::parse("a").unwrap();
        let ua = UnifiedAddress::from_string("u1".into());
        let memo = encode_otp_relay_memo(&name, Action::Update, &ua, "ff").unwrap();
        assert_eq!(memo.len(), 512);
    }
}
