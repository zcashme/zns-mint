//! Typed errors for the signer crate.

use std::fmt;

use thiserror::Error;

use crate::policy::PolicyError;

/// Why the signer refused (policy) or failed (build/initialisation).
#[derive(Debug)]
pub enum SignError {
    /// The proposal violated policy — the signer refused before building.
    Policy(PolicyError),
    /// Policy passed but bundle construction / proving failed.
    Build(BuildError),
    /// The registry spend seed was invalid.
    InvalidSeed(String),
}

impl From<PolicyError> for SignError {
    fn from(e: PolicyError) -> Self {
        SignError::Policy(e)
    }
}

impl From<BuildError> for SignError {
    fn from(e: BuildError) -> Self {
        SignError::Build(e)
    }
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::Policy(e) => write!(f, "policy refused: {e:?}"),
            SignError::Build(e) => write!(f, "build failed: {e}"),
            SignError::InvalidSeed(e) => write!(f, "invalid seed: {e}"),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignError::Build(e) => Some(e),
            _ => None,
        }
    }
}

/// Why an Orchard bundle could not be constructed, proven, signed, or
/// serialized.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The canonical Name Note memo could not be encoded.
    #[error("invalid memo: {0}")]
    Memo(#[from] zns_core::MemoError),

    /// Adding a spend or output to the Orchard builder failed.
    #[error("Orchard bundle error: {0}")]
    Bundle(String),

    /// The Orchard bundle was empty after construction.
    #[error("builder produced an empty bundle")]
    EmptyBundle,

    /// The Name Note output was missing from the constructed bundle.
    #[error("Name Note output missing from bundle")]
    MissingNameNote,

    /// Creating the halo2 proof failed.
    #[error("failed to create proof: {0}")]
    Proof(String),

    /// Applying spend authorizing signatures failed.
    #[error("failed to apply signatures: {0}")]
    Signature(String),

    /// The constructed proof failed self-verification.
    #[error("self-verification failed: {0}")]
    Verify(String),

    /// Serializing or re-parsing the transaction failed.
    #[error("transaction serialization failed: {0}")]
    Serialize(#[from] std::io::Error),

    /// The computed ZIP-244 sighash did not match the serialized txid.
    #[error("sighash/txid mismatch")]
    SighashMismatch,

    /// The transaction value balance could not be represented.
    #[error("value balance out of range: {0}")]
    ValueBalance(String),
}

impl BuildError {
    /// Wrap an opaque orchard/zcash builder error in a [`BuildError::Bundle`].
    pub fn bundle<E: fmt::Debug>(e: E) -> Self {
        BuildError::Bundle(format!("{e:?}"))
    }

    /// Wrap an opaque proof error in a [`BuildError::Proof`].
    pub fn proof<E: fmt::Debug>(e: E) -> Self {
        BuildError::Proof(format!("{e:?}"))
    }

    /// Wrap an opaque signature error in a [`BuildError::Signature`].
    pub fn signature<E: fmt::Debug>(e: E) -> Self {
        BuildError::Signature(format!("{e:?}"))
    }

    /// Wrap an opaque verify error in a [`BuildError::Verify`].
    pub fn verify<E: fmt::Debug>(e: E) -> Self {
        BuildError::Verify(format!("{e:?}"))
    }

    /// Wrap an opaque value-balance error in a [`BuildError::ValueBalance`].
    pub fn value_balance<E: fmt::Debug>(e: E) -> Self {
        BuildError::ValueBalance(format!("{e:?}"))
    }
}
