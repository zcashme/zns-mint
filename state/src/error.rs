use thiserror::Error;

/// Errors produced by the ZNS state layer (SQLite persistence).
#[derive(Debug, Error)]
pub enum StateError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
