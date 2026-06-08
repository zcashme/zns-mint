//! `zns-auth` — OTP challenge-response auth for ZNS UPDATE and RELEASE actions.
//!
//! # Flow
//! 1. Registry receives `ZNS:update:alice:ua_new` from any sender.
//! 2. Registry calls [`AuthModule::new_challenge`] → gets `(nonce, send_to_ua)`.
//! 3. Registry sends a ZEC memo containing `nonce` to `send_to_ua` (the current owner).
//! 4. Current owner echoes back `ZNS:confirm:alice:<nonce>`.
//! 5. Registry calls [`AuthModule::verify_confirm`] → on success receives the
//!    original [`PendingChallenge`] and proceeds to mint the Name Note.
//!
//! This crate is **pure logic**: no Zcash dependencies, no network I/O.

pub mod challenge;
pub mod error;

pub use challenge::{PendingChallenge, CHALLENGE_TTL};
pub use error::AuthError;

use std::{collections::HashMap, sync::Arc, time::Instant};

use tokio::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// Registry actions that may need an OTP challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// First-time name registration. No challenge required; the registry only
    /// checks that the correct fee was paid.
    Claim,

    /// Change the unified address bound to an existing name.
    Update,

    /// Release an existing name back to the pool.
    Release,
}

// ---------------------------------------------------------------------------
// AuthModule
// ---------------------------------------------------------------------------

/// Inner state hidden behind the mutex.
#[derive(Debug, Default)]
struct Inner {
    pending: HashMap<String, PendingChallenge>,
}

/// Thread-safe auth module.  Cheap to clone — the `Arc` is cloned, not the map.
#[derive(Debug, Clone)]
pub struct AuthModule {
    inner: Arc<Mutex<Inner>>,
}

impl Default for AuthModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthModule {
    /// Create a new, empty auth module.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Returns `true` when the action does **not** require an OTP challenge.
    ///
    /// Currently only [`Action::Claim`] is challenge-free.
    pub fn is_claim(action: &Action) -> bool {
        matches!(action, Action::Claim)
    }

    /// Create a new OTP challenge for `name`.
    ///
    /// # Parameters
    /// - `name` — the ZNS name being acted upon (e.g. `"alice"`).
    /// - `action` — must be [`Action::Update`] or [`Action::Release`]; returns
    ///   [`AuthError::NotRequired`] for [`Action::Claim`].
    /// - `ua_new` — the new unified address from the original memo (pass an
    ///   empty string for [`Action::Release`]).
    /// - `current_owner_ua` — the UA currently registered for `name`; the
    ///   caller must look this up from the registry state before calling here.
    ///   The nonce memo should be sent to this address.
    ///
    /// # Returns
    /// `Ok((nonce, send_to_ua))` where `send_to_ua` is `current_owner_ua`
    /// (returned for ergonomics so the caller doesn't have to keep a copy).
    ///
    /// Any pre-existing pending challenge for `name` is silently overwritten
    /// (the user may retry).
    pub async fn new_challenge(
        &self,
        name: impl Into<String>,
        action: Action,
        ua_new: impl Into<String>,
        current_owner_ua: impl Into<String>,
    ) -> Result<(String, String), AuthError> {
        if Self::is_claim(&action) {
            return Err(AuthError::NotRequired);
        }

        let name = name.into();
        let ua_new = ua_new.into();
        let send_to_ua = current_owner_ua.into();

        let nonce = generate_nonce();
        let expires_at = Instant::now() + CHALLENGE_TTL;

        let challenge = PendingChallenge {
            name: name.clone(),
            action,
            ua_new,
            nonce: nonce.clone(),
            expires_at,
        };

        let mut guard = self.inner.lock().await;
        guard.pending.insert(name, challenge);

        Ok((nonce, send_to_ua))
    }

    /// Verify an echo-back nonce from a `ZNS:confirm:<name>:<nonce>` memo.
    ///
    /// On success the [`PendingChallenge`] is removed from the pending map and
    /// returned to the caller, which can then proceed with the registry action.
    ///
    /// # Errors
    /// - [`AuthError::NoPendingChallenge`] — no challenge was ever issued for `name`.
    /// - [`AuthError::WrongNonce`] — challenge exists but nonce doesn't match.
    /// - [`AuthError::Expired`] — challenge existed but the 5-minute window has passed.
    pub async fn verify_confirm(
        &self,
        name: &str,
        nonce: &str,
    ) -> Result<PendingChallenge, AuthError> {
        let mut guard = self.inner.lock().await;

        let challenge = guard
            .pending
            .get(name)
            .ok_or_else(|| AuthError::NoPendingChallenge(name.to_owned()))?;

        // Check nonce before expiry so we don't reveal timing information
        // about whether the challenge exists vs. the nonce is wrong.
        if challenge.nonce != nonce {
            return Err(AuthError::WrongNonce(name.to_owned()));
        }

        if challenge.is_expired() {
            // Remove stale entry and report expiry.
            guard.pending.remove(name);
            return Err(AuthError::Expired(name.to_owned()));
        }

        // Valid — consume and return.
        let challenge = guard.pending.remove(name).expect("just confirmed present");
        Ok(challenge)
    }

    /// Remove any pending challenge for `name` without verification.
    ///
    /// Useful if the registry detects a conflicting state change (e.g. the
    /// name was released before the challenge was confirmed).
    pub async fn cancel(&self, name: &str) {
        let mut guard = self.inner.lock().await;
        guard.pending.remove(name);
    }

    /// Returns `true` if there is an unexpired pending challenge for `name`.
    pub async fn has_pending(&self, name: &str) -> bool {
        let guard = self.inner.lock().await;
        guard
            .pending
            .get(name)
            .map(|c: &PendingChallenge| !c.is_expired())
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Nonce generation
// ---------------------------------------------------------------------------

/// Generate a cryptographically random nonce as a lowercase hex string.
///
/// Uses [`Uuid::new_v4`] (which is backed by `getrandom`) to produce 128 bits
/// of randomness, then formats it without hyphens for a compact 32-character
/// string.
fn generate_nonce() -> String {
    let id = Uuid::new_v4();
    id.simple().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn claim_returns_not_required() {
        let auth = AuthModule::new();
        let err = auth
            .new_challenge("alice", Action::Claim, "", "ua_old")
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::NotRequired);
    }

    #[tokio::test]
    async fn update_round_trip() {
        let auth = AuthModule::new();

        let (nonce, send_to) = auth
            .new_challenge("alice", Action::Update, "ua_new_addr", "ua_old_addr")
            .await
            .expect("challenge should be created");

        assert_eq!(send_to, "ua_old_addr");
        assert!(!nonce.is_empty());

        let challenge = auth
            .verify_confirm("alice", &nonce)
            .await
            .expect("confirm should succeed");

        assert_eq!(challenge.name, "alice");
        assert_eq!(challenge.action, Action::Update);
        assert_eq!(challenge.ua_new, "ua_new_addr");
        assert_eq!(challenge.nonce, nonce);
    }

    #[tokio::test]
    async fn release_round_trip() {
        let auth = AuthModule::new();
        let (nonce, _) = auth
            .new_challenge("bob", Action::Release, "", "ua_bob")
            .await
            .unwrap();

        let challenge = auth.verify_confirm("bob", &nonce).await.unwrap();
        assert_eq!(challenge.action, Action::Release);
        assert!(challenge.ua_new.is_empty());
    }

    #[tokio::test]
    async fn wrong_nonce_returns_error() {
        let auth = AuthModule::new();
        auth.new_challenge("alice", Action::Update, "ua_new", "ua_old")
            .await
            .unwrap();

        let err = auth
            .verify_confirm("alice", "definitely-not-the-nonce")
            .await
            .unwrap_err();

        assert_eq!(err, AuthError::WrongNonce("alice".to_owned()));
    }

    #[tokio::test]
    async fn no_pending_challenge() {
        let auth = AuthModule::new();
        let err = auth.verify_confirm("nobody", "any-nonce").await.unwrap_err();
        assert_eq!(err, AuthError::NoPendingChallenge("nobody".to_owned()));
    }

    #[tokio::test]
    async fn confirm_consumes_challenge() {
        let auth = AuthModule::new();
        let (nonce, _) = auth
            .new_challenge("alice", Action::Update, "new", "old")
            .await
            .unwrap();

        // First confirm succeeds.
        auth.verify_confirm("alice", &nonce).await.unwrap();

        // Second confirm finds nothing.
        let err = auth.verify_confirm("alice", &nonce).await.unwrap_err();
        assert_eq!(err, AuthError::NoPendingChallenge("alice".to_owned()));
    }

    #[tokio::test]
    async fn overwrite_pending_challenge() {
        let auth = AuthModule::new();
        let (nonce1, _) = auth
            .new_challenge("alice", Action::Update, "ua_v2", "ua_old")
            .await
            .unwrap();

        // Issue a second challenge — overwrites the first.
        let (nonce2, _) = auth
            .new_challenge("alice", Action::Update, "ua_v3", "ua_old")
            .await
            .unwrap();

        // Old nonce should no longer be valid.
        let err = auth.verify_confirm("alice", &nonce1).await.unwrap_err();
        assert_eq!(err, AuthError::WrongNonce("alice".to_owned()));

        // New nonce works.
        auth.verify_confirm("alice", &nonce2).await.unwrap();
    }

    #[tokio::test]
    async fn cancel_removes_pending() {
        let auth = AuthModule::new();
        let (nonce, _) = auth
            .new_challenge("alice", Action::Update, "new", "old")
            .await
            .unwrap();

        auth.cancel("alice").await;

        let err = auth.verify_confirm("alice", &nonce).await.unwrap_err();
        assert_eq!(err, AuthError::NoPendingChallenge("alice".to_owned()));
    }

    #[tokio::test]
    async fn is_claim_logic() {
        assert!(AuthModule::is_claim(&Action::Claim));
        assert!(!AuthModule::is_claim(&Action::Update));
        assert!(!AuthModule::is_claim(&Action::Release));
    }

    /// Simulate expiry by injecting a challenge whose deadline is in the past.
    #[tokio::test]
    async fn expired_challenge() {
        let auth = AuthModule::new();

        // Inject an already-expired challenge directly.
        {
            let mut guard = auth.inner.lock().await;
            guard.pending.insert(
                "alice".to_owned(),
                PendingChallenge {
                    name: "alice".to_owned(),
                    action: Action::Update,
                    ua_new: "new".to_owned(),
                    nonce: "abc123".to_owned(),
                    // Expired 1 second ago.
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }

        let err = auth.verify_confirm("alice", "abc123").await.unwrap_err();
        assert_eq!(err, AuthError::Expired("alice".to_owned()));

        // Entry must have been cleaned up.
        assert!(!auth.has_pending("alice").await);
    }
}
