//! Cross-cutting error type for the registry orchestration layer.
//!
//! This lives in the orchestration crate because it needs to classify errors
//! from every downstream layer (state, core memo, chain/grpc, signer, build)
//! into permanent vs. transient for the intake ledger settlement decision.

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("insufficient fee: got {got} zat, need {need} zat")]
    InsufficientFee { got: u64, need: u64 },
    #[error("name already claimed: {0}")]
    AlreadyClaimed(String),
    #[error("name not found: {0}")]
    NotFound(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("broadcast: {0}")]
    Broadcast(String),
    #[error("policy: {reason}")]
    Policy { reason: String, permanent: bool },
    #[error("invalid memo: {0}")]
    InvalidMemo(String),
    #[error(transparent)]
    Db(#[from] zns_state::StateError),
    #[error(transparent)]
    Memo(#[from] zns_core::MemoError),
    #[error(transparent)]
    Grpc(#[from] zns_chain::GrpcError),
    #[error(transparent)]
    Sign(#[from] zns_mint::SignError),
    #[error(transparent)]
    Build(#[from] zns_mint::BuildError),
    #[error("config: {0}")]
    Config(String),
    #[error("rpc: {0}")]
    Rpc(String),
}

impl From<rusqlite::Error> for RegistryError {
    fn from(e: rusqlite::Error) -> Self {
        RegistryError::Db(zns_state::StateError::Db(e))
    }
}

impl RegistryError {
    /// Whether this error means the triggering intake note can be marked
    /// settled forever (will never produce a different outcome on retry).
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::InsufficientFee { .. }
            | Self::AlreadyClaimed(_)
            | Self::NotFound(_)
            | Self::Auth(_)
            | Self::InvalidMemo(_)
            | Self::Config(_)
            | Self::Rpc(_) => true,
            Self::Policy { permanent, .. } => *permanent,
            Self::Broadcast(_)
            | Self::Db(_)
            | Self::Memo(_)
            | Self::Grpc(_)
            | Self::Sign(_)
            | Self::Build(_) => false,
        }
    }
}
