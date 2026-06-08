use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    /// No pending challenge exists for the given name.
    #[error("no pending challenge for name '{0}'")]
    NoPendingChallenge(String),

    /// The supplied nonce does not match the stored one.
    #[error("wrong nonce for name '{0}'")]
    WrongNonce(String),

    /// The challenge existed but the 5-minute window has elapsed.
    #[error("challenge expired for name '{0}'")]
    Expired(String),

    /// The action does not require an OTP challenge (e.g. CLAIM).
    #[error("action does not require auth")]
    NotRequired,
}
