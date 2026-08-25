//! OTP challenge machinery for ZNS name transitions.
//!
//! The OTP queue is a single-use TTL cache: each entry binds a 6-digit
//! passcode to a specific (name, action, target UA) and expires after
//! 30 minutes of chain MTP. Entries are pushed when a relay transaction
//! is accepted and burned on first successful verification — one-shot,
//! never reusable.
//!
//! Also home to the OTP relay memo codec
//! (`ZNS:otp:<name>:<verb>:<ua>:<otp>`).

use std::fmt;

use rand::Rng;
use subtle::ConstantTimeEq;
use time::Timestamp;
use zeroize::Zeroize;

use crate::mint::{Action, Name, UnifiedAddress};

/// OTP validity window (whitepaper §5.3: D_OTP). 30 minutes in seconds.
pub const D_OTP: i64 = 1800;

// ---------------------------------------------------------------------------
// OtpCode
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// OtpRequest — one pending OTP bound to a specific transition
// ---------------------------------------------------------------------------

/// A pending OTP bound to a specific (name, action, target UA).
///
/// Pushed onto the [`OtpQueue`] after the relay transaction is accepted.
/// Burned on first successful verification — one-shot, never reusable.
/// Expires after `D_OTP` seconds of chain MTP.
pub struct OtpRequest {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    pub code: OtpCode,
    pub expires_at: Timestamp,
}

// ---------------------------------------------------------------------------
// OtpQueue — single-use TTL cache of pending OTPs
// ---------------------------------------------------------------------------

/// A bag of pending OTP requests. Push appends with no checks; every
/// accepted relay gets an entry. Verification scans for a match on
/// (name, action, ua, code) plus the expiry check, and removes the
/// first match — burning it permanently.
pub struct OtpQueue(Vec<OtpRequest>);

impl Default for OtpQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpQueue {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a pending OTP request. No checks — every accepted relay
    /// gets an entry. Multiple entries per name are allowed.
    pub fn push(&mut self, req: OtpRequest) {
        self.0.push(req);
    }

    /// Scans for an entry matching (name, action, ua) with an unexpired
    /// timestamp and a code that equals `provided` under constant-time
    /// comparison. Removes and returns `true` on first match — the OTP
    /// is burned. Failed verification leaves the entry intact.
    pub fn verify_and_burn(
        &mut self,
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
        provided: &[u8; 6],
        mtp: Timestamp,
    ) -> bool {
        let Some(provided_code) = OtpCode::from_digits(provided) else {
            return false;
        };
        for i in 0..self.0.len() {
            let req = &self.0[i];
            if req.name == *name
                && req.action == action
                && &req.ua == ua
                && mtp < req.expires_at
                && bool::from(req.code.0.ct_eq(&provided_code.0))
            {
                self.0.remove(i);
                return true;
            }
        }
        false
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
    8usize // "ZNS:otp:"
        .checked_add(name.as_str().len())
        .and_then(|l| l.checked_add(1 + verb.len()))
        .and_then(|l| l.checked_add(1 + ua.encode(network).len()))
        .and_then(|l| l.checked_add(1 + 6)) // ":<otp>" — 6-digit OTP
        .is_some_and(|l| l <= 512)
}

/// Encodes an OTP relay memo: `ZNS:otp:<name>:<verb>:<ua>:<otp>`, zero-padded
/// to 512 bytes.
///
/// This memo is sent from the Treasury to the current controller's address so
/// only they can decrypt it and forward it back. Returns `None` if the action
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
        name.as_str().as_bytes(),
        b":".as_slice(),
        verb.as_bytes(),
        b":".as_slice(),
        ua_field.as_bytes(),
        b":".as_slice(),
        otp_digits.as_slice(),
    ] {
        let end = offset + field.len();
        memo[offset..end].copy_from_slice(field);
        offset = end;
    }
    Some(memo)
}

/// Parses a 512-byte OTP relay memo and returns its fields if the grammar
/// matches `ZNS:otp:<name>:<verb>:<ua>:<otp>`. Returns `None` otherwise.
pub fn decode_otp_relay_memo(memo: &[u8; 512]) -> Option<(Name, Action, String, [u8; 6])> {
    let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
    let text = std::str::from_utf8(&memo[..end]).ok()?;

    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 || parts[0] != "ZNS" || parts[1] != "otp" {
        return None;
    }

    let name = Name::parse(parts[2])?;
    let action = match parts[3] {
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    let ua = parts[4].to_string();
    if ua.is_empty() {
        return None;
    }

    let digits = parts[5].as_bytes();
    if digits.len() != 6 || !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut otp = [0u8; 6];
    otp.copy_from_slice(digits);

    Some((name, action, ua, otp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;
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
    fn otp_relay_memo_format_is_name_verb_ua_otp() {
        let name = test_name();
        let ua = test_ua();
        let otp = OtpCode::for_test(*b"004206");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp)
            .expect("memo fits");

        let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
        let text = std::str::from_utf8(&memo[..end]).unwrap();
        // OTP must be at the END: ZNS:otp:alice:update:<ua>:004206
        assert!(text.ends_with(":004206"), "memo must end with OTP digits");
        assert!(text.starts_with("ZNS:otp:alice:update:"), "memo must start with ZNS:otp:name:verb:");
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

    #[test]
    fn otp_queue_verify_and_burn() {
        let name = test_name();
        let ua = test_ua();
        // code is set in the OtpRequest below
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Correct code burns the entry
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
        // Second attempt fails — entry is gone
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_wrong_code_does_not_burn() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Wrong code — entry stays
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"999999", now));
        // Correct code still works
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_wrong_action_does_not_burn() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Wrong action — entry stays
        assert!(!queue.verify_and_burn(&name, Action::Release, &ua, b"004206", now));
        // Correct action still works
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_expired_does_not_burn() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now; // already expired

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Expired — entry stays (just not consumed)
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_multiple_entries_per_name() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"111111"),
            expires_at: expires,
        });
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"222222"),
            expires_at: expires,
        });

        // First code burns one entry, the other stays
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"111111", now));
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"222222", now));
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"111111", now));
    }
}