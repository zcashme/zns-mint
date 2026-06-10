use thiserror::Error;

/// All errors that can be produced by the registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// A memo field did not conform to the ZNS grammar.
    #[error("invalid ZNS memo: {0}")]
    InvalidMemo(String),

    /// A name string failed validation (empty, too long, bad chars, …).
    #[error("invalid name '{0}': {1}")]
    InvalidName(String, String),

    /// The fee attached to a CLAIM was below the minimum.
    #[error("insufficient fee: got {got} zatoshis, need {need}")]
    InsufficientFee { got: u64, need: u64 },

    /// The name is already claimed (and no prior tip was found to chain from).
    #[error("name '{0}' is already registered")]
    AlreadyClaimed(String),

    /// The name has no existing record (UPDATE/RELEASE with unknown name).
    #[error("name '{0}' is not registered")]
    NotFound(String),

    /// OTP/confirm auth failed (the stringified `zns_auth::AuthError` — kept
    /// as a string so the domain core does not depend on the auth crate;
    /// layering runs auth → core, not the reverse).
    #[error("auth error: {0}")]
    Auth(String),

    /// The signer's policy gate refused. `permanent` carries the gate's
    /// verdict class across the crate boundary: a bad name or a replay can
    /// never succeed; a velocity cap or low-watermark pause clears on its
    /// own, so the intake retries it.
    #[error("policy refused: {reason}")]
    Policy {
        /// The gate's rejection, stringified.
        reason: String,
        /// Whether retrying the same request can ever succeed.
        permanent: bool,
    },

    /// An Orchard builder error occurred during note construction.
    #[error("note build error: {0}")]
    Build(String),

    /// SQLite persistence error.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    /// gRPC broadcast error.
    #[error("broadcast error: {0}")]
    Broadcast(String),

    /// General I/O or internal error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl RegistryError {
    /// Whether retrying the same input can ever succeed. Permanent failures
    /// (the note's memo, value, or auth state can never change) settle the
    /// note in the intake ledger; transient ones (infrastructure) leave it
    /// for the next rescan.
    pub fn is_permanent(&self) -> bool {
        match self {
            RegistryError::InvalidMemo(_)
            | RegistryError::InvalidName(_, _)
            | RegistryError::InsufficientFee { .. }
            | RegistryError::AlreadyClaimed(_)
            | RegistryError::NotFound(_)
            | RegistryError::Auth(_) => true,
            RegistryError::Policy { permanent, .. } => *permanent,
            RegistryError::Build(_)
            | RegistryError::Db(_)
            | RegistryError::Broadcast(_)
            | RegistryError::Other(_) => false,
        }
    }
}
