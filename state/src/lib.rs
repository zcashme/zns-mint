//! `zns-state` — ZNS registry persistence.
//!
//! Owns the SQLite store: [`db`] holds `name_records` (current tip per name) and
//! [`actions`] holds the append-only minted-action log. Split out of `zns-core`
//! so the storage layer is its own crate (cf. `zebra-state`) and pure consumers
//! of the domain types never link rusqlite.

pub mod actions;
pub mod db;
pub mod error;

pub use actions::{actions_for, append_action, latest_action, MintedAction};
pub use db::{delete_record, get_record, upsert_record, NameRecord};
pub use error::StateError;

use rusqlite::Connection;

/// Initialise the full registry schema (idempotent): the name-record tip table
/// and the append-only minted-action log.
pub fn init_schema(conn: &Connection) -> Result<(), StateError> {
    db::init_schema(conn)?;
    actions::init_actions_schema(conn)?;
    Ok(())
}
