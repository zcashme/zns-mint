//! In-band OTP authorization policy for update/release requests.
//!
//! OTPs are transported by shielded memos, never by logs. The flow is:
//!
//! 1. user -> Treasury: `ZNS:update:<name>:<ua>` or `ZNS:release:<name>:<ua>`
//! 2. Treasury -> current controller: `ZNS:otp:<name>:<verb>:<ua>:<otp>`
//! 3. user -> Treasury: same request with `:<otp>` appended
//!
//! This module owns OTP credential state and memo construction only. It is the
//! sole OTP authority: issuance, verification, expiry, and one-time
//! consumption. It does **not** sign or broadcast the OTP relay transaction;
//! that is the job of the transaction-assembly path, which funds the relay
//! from the Treasury account and signs it with the Treasury spending key. The
//! Treasury module (`treasury.rs`) owns Treasury wallet state and policy
//! (auto-sweep, funding the Registry account) and does not sign OTP relays
//! either.
//!
//! This module is currently not wired into `main.rs` (`mod auth;` is commented
//! out) and depends on `crate::payload`, which does not exist in the current
//! tree. It is aspirational: it documents the OTP credential policy shape and
//! will be re-enabled when the request-processing layer and payload kernel are
//! restored.

use std::collections::HashMap;

use rand::{rngs::OsRng, RngCore};

use crate::payload::{self, Action, OtpCode};

/// OTPs are scoped to the exact requested transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OtpKey {
    name: String,
    action: Action,
    ua: String,
}

impl OtpKey {
    fn new(name: &str, action: Action, ua: &str) -> Self {
        Self {
            name: name.to_string(),
            action,
            ua: ua.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedOtp {
    pub name: String,
    pub action: Action,
    pub ua: String,
    /// The 512-byte OTP relay memo. The Treasury account is the shielded origin
    /// of this memo; the transaction-assembly path funds and signs the relay
    /// transaction, not this module.
    pub memo: [u8; payload::MEMO_SIZE],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("OTP is not valid for claim")]
    ClaimDoesNotUseOtp,
    #[error("OTP memo encode failed: {0:?}")]
    Encode(payload::MemoError),
    #[error("no pending OTP for request")]
    Missing,
    #[error("OTP mismatch")]
    Mismatch,
}

#[derive(Default)]
pub struct OtpStore {
    pending: HashMap<OtpKey, OtpCode>,
}

impl OtpStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue or replace the pending OTP for `(name, action, ua)`.
    pub fn issue(&mut self, name: &str, action: Action, ua: &str) -> Result<IssuedOtp, AuthError> {
        if action == Action::Claim {
            return Err(AuthError::ClaimDoesNotUseOtp);
        }

        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let otp = OtpCode::from_bytes(bytes);
        let memo = payload::encode_otp_memo(action, name, ua, otp).map_err(AuthError::Encode)?;
        self.pending.insert(OtpKey::new(name, action, ua), otp);

        Ok(IssuedOtp {
            name: name.to_string(),
            action,
            ua: ua.to_string(),
            memo,
        })
    }

    /// Verify and consume the OTP. A successful OTP cannot be replayed.
    pub fn verify_consume(
        &mut self,
        name: &str,
        action: Action,
        ua: &str,
        provided: OtpCode,
    ) -> Result<(), AuthError> {
        if action == Action::Claim {
            return Err(AuthError::ClaimDoesNotUseOtp);
        }
        let key = OtpKey::new(name, action, ua);
        let expected = self.pending.get(&key).copied().ok_or(AuthError::Missing)?;
        if expected != provided {
            return Err(AuthError::Mismatch);
        }
        self.pending.remove(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memo_text(memo: &[u8; payload::MEMO_SIZE]) -> &str {
        let end = memo.iter().rposition(|b| *b != 0).unwrap() + 1;
        std::str::from_utf8(&memo[..end]).unwrap()
    }

    #[test]
    fn issue_returns_in_band_otp_memo() {
        let mut store = OtpStore::new();
        let issued = store.issue("alice", Action::Update, "u1new").unwrap();
        let text = memo_text(&issued.memo);
        assert!(text.starts_with("ZNS:otp:alice:update:u1new:"));
        assert_eq!(text.rsplit(':').next().unwrap().len(), OtpCode::LEN_HEX);
    }

    #[test]
    fn verify_consumes_exact_match_once() {
        let mut store = OtpStore::new();
        let issued = store.issue("alice", Action::Release, "u1old").unwrap();
        let otp = OtpCode::parse(memo_text(&issued.memo).rsplit(':').next().unwrap()).unwrap();

        store
            .verify_consume("alice", Action::Release, "u1old", otp)
            .unwrap();
        assert_eq!(
            store.verify_consume("alice", Action::Release, "u1old", otp),
            Err(AuthError::Missing)
        );
    }

    #[test]
    fn otp_is_bound_to_name_action_and_ua() {
        let mut store = OtpStore::new();
        let issued = store.issue("alice", Action::Update, "u1new").unwrap();
        let otp = OtpCode::parse(memo_text(&issued.memo).rsplit(':').next().unwrap()).unwrap();

        assert_eq!(
            store.verify_consume("alice", Action::Update, "u1other", otp),
            Err(AuthError::Missing)
        );
        assert_eq!(
            store.verify_consume("alice", Action::Release, "u1new", otp),
            Err(AuthError::Missing)
        );
        assert_eq!(
            store.verify_consume("bob", Action::Update, "u1new", otp),
            Err(AuthError::Missing)
        );
    }
}
