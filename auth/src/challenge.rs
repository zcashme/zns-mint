use std::time::{Duration, Instant};

use crate::Action;

/// How long a pending challenge remains valid.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// A pending OTP challenge stored in memory while waiting for the user's
/// ZNS:confirm memo.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    /// The ZNS name being acted upon (e.g. "alice").
    pub name: String,

    /// The registry action being confirmed.
    pub action: Action,

    /// The new unified address supplied in the original ZNS:update memo.
    /// Empty string for Release (no new UA needed).
    pub ua_new: String,

    /// The one-time nonce that was sent to the current owner's UA.
    pub nonce: String,

    /// Wall-clock deadline after which the challenge is considered expired.
    pub expires_at: Instant,
}

impl PendingChallenge {
    /// Returns `true` if this challenge has passed its deadline.
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}
