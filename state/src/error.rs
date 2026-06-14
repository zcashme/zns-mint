use thiserror::Error;

/// Errors produced by the ZNS state layer (SQLite persistence).
#[derive(Debug, Error)]
pub enum StateError {
    /// An underlying SQLite error.
    #[error(transparent)]
    Db(#[from] rusqlite::Error),

    /// A row read from the database violates an invariant (wrong blob length,
    /// unrecognized enum value, etc.).
    #[error("corrupt {table}.{field}: {detail}")]
    CorruptRow {
        /// Table the corrupt value came from.
        table: &'static str,
        /// Column the corrupt value came from.
        field: &'static str,
        /// Human-readable detail about the corruption.
        detail: String,
    },

    /// An internal invariant was violated (e.g. attempting to persist a
    /// challenge for an action that can never have one).
    #[error("database invariant violated: {0}")]
    Invariant(String),
}
