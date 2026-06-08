//! Re-exports from [`crate::db`] for backward compatibility.
//!
//! The canonical implementation lives in `db.rs`; this module is a thin
//! façade so any existing code that imports `zns_registry::store` still
//! resolves.

pub use crate::db::{delete_record, get_record, init_schema, upsert_record, NameRecord};
