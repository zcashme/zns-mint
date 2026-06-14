//! `zns-auth` — pure OTP challenge-response logic for ZNS UPDATE / RELEASE.
//!
//! # Flow
//! 1. Registry receives `ZNS:update:alice:ua_new` from any sender.
//! 2. Registry calls [`new_challenge`] → a [`PendingChallenge`] it persists
//!    (durably — a daemon restart must not void pending mutations) and whose
//!    nonce it relays to the current owner's UA.
//! 3. Current owner echoes back `ZNS:confirm:alice:<nonce>`.
//! 4. Registry loads the stored challenge, calls [`verify`], and on success
//!    proceeds to mint — deleting the challenge **in the same transaction**
//!    that records the mint, so neither a transient mint failure (challenge
//!    must survive for the retry) nor a duplicate confirm (must not re-mint)
//!    can wedge the flow.
//!
//! This crate is **pure logic**: no storage, no network I/O, no clocks.
//! Expiry is by *block height* — an OTP round trip is two mined transactions
//! plus a human noticing a memo, which a wall-clock TTL measured in minutes
//! cannot accommodate; chain height is also replayable, so anyone auditing
//! the flow on-chain applies the same expiry rule.

pub mod error;

pub use error::AuthError;

use uuid::Uuid;
use zns_core::Action;

/// How many blocks a challenge stays confirmable. ~2.5 h on mainnet (75 s
/// blocks) — enough for a human round trip; a few minutes on a fast regtest.
pub const CHALLENGE_TTL_BLOCKS: u32 = 120;

/// A pending OTP challenge, persisted by the registry while waiting for the
/// owner's `ZNS:confirm` memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChallenge {
    /// The ZNS name being acted upon (e.g. "alice").
    pub name: String,
    /// The mutation being confirmed (UPDATE or RELEASE; never CLAIM).
    pub action: Action,
    /// The new unified address supplied in the original `ZNS:update` memo.
    /// Empty string for RELEASE (no new UA needed).
    pub ua_new: String,
    /// The one-time nonce relayed to the current owner's UA.
    pub nonce: String,
    /// Block height after which the challenge is no longer confirmable.
    pub expires_height: u32,
}

/// Create a challenge for a mutation observed at `current_height`.
///
/// Returns [`AuthError::NotRequired`] for CLAIM (which is fee-gated, not
/// auth-gated). The caller persists the result and relays `nonce`.
pub fn new_challenge(
    name: impl Into<String>,
    action: Action,
    ua_new: impl Into<String>,
    current_height: u32,
) -> Result<PendingChallenge, AuthError> {
    if action == Action::Claim {
        return Err(AuthError::NotRequired);
    }
    Ok(PendingChallenge {
        name: name.into(),
        action,
        ua_new: ua_new.into(),
        nonce: Uuid::new_v4().simple().to_string(),
        expires_height: current_height.saturating_add(CHALLENGE_TTL_BLOCKS),
    })
}

/// Verify an echoed nonce against a stored challenge at `current_height`.
///
/// Pure check — the caller decides when to delete the stored row (on
/// successful mint, in the same transaction as the record update). The nonce
/// is checked before expiry so a confirmer always learns the most useful
/// error; the comparison is ordinary equality — the nonce is on-chain data,
/// not a secret needing constant-time handling.
pub fn verify(
    challenge: &PendingChallenge,
    nonce: &str,
    current_height: u32,
) -> Result<(), AuthError> {
    if challenge.nonce != nonce {
        return Err(AuthError::WrongNonce(challenge.name.clone()));
    }
    if current_height > challenge.expires_height {
        return Err(AuthError::Expired(challenge.name.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_needs_no_challenge() {
        assert_eq!(
            new_challenge("alice", Action::Claim, "u1x", 100).unwrap_err(),
            AuthError::NotRequired
        );
    }

    #[test]
    fn round_trip_verifies_until_expiry() {
        let c = new_challenge("alice", Action::Update, "u1new", 100).unwrap();
        assert_eq!(c.expires_height, 100 + CHALLENGE_TTL_BLOCKS);
        assert_eq!(c.nonce.len(), 32); // uuid simple form

        assert!(verify(&c, &c.nonce, 100).is_ok());
        assert!(verify(&c, &c.nonce, c.expires_height).is_ok()); // inclusive
        assert_eq!(
            verify(&c, &c.nonce, c.expires_height + 1).unwrap_err(),
            AuthError::Expired("alice".into())
        );
        assert_eq!(
            verify(&c, "deadbeef", 100).unwrap_err(),
            AuthError::WrongNonce("alice".into())
        );
    }

    #[test]
    fn nonces_are_unique() {
        let a = new_challenge("alice", Action::Update, "u1x", 1).unwrap();
        let b = new_challenge("alice", Action::Update, "u1x", 1).unwrap();
        assert_ne!(a.nonce, b.nonce);
    }
}
