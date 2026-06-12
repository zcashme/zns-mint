use thiserror::Error;

/// Errors produced by the ZNS memo parser and name validator.
#[derive(Debug, Error)]
pub enum MemoError {
    /// A memo field did not conform to the ZNS grammar.
    #[error("invalid ZNS memo: {0}")]
    InvalidMemo(String),

    /// A name string failed validation (empty, too long, bad chars, …).
    #[error("invalid name '{0}': {1}")]
    InvalidName(String, String),
}
