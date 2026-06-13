//! `zns-state` — ZNS registry persistence.
//!
//! Owns the SQLite stores: [`db`] holds `name_records` (current tip per name)
//! and [`actions`] holds the append-only minted-action log. Split out of
//! `zns-core` so the storage layer is its own crate (cf. `zebra-state`) and
//! pure consumers of the domain types never link rusqlite.
//!
//! [`treasury`] is the registry's *other* SQLite store — a `zcash_client_sqlite`
//! `WalletDb` tracking the registry's own spendable notes (the treasury float)
//! for self-funding mint fees. A separate database from `db`/`actions`, but the
//! same kind of thing: persisted state this crate owns, not chain I/O.

pub mod actions;
pub mod db;
pub mod error;
pub mod treasury;

pub use actions::{
    actions_for, affected_names, append_action, delete_actions_above, latest_action, MintedAction,
};
pub use db::{
    delete_intents_above, delete_processed_above, delete_record, get_record, last_processed_height,
    mark_processed, processed_hash_at_height, rebuild_records_after_reorg, upsert_record,
    NameRecord,
};
pub use error::StateError;
pub use treasury::{FundingSelection, NoteState, SpendableNote, TreasuryConfig, TreasuryError};

use rusqlite::Connection;

/// Initialise the full registry schema (idempotent): the name-record tip table
/// and the append-only minted-action log.
pub fn init_schema(conn: &Connection) -> Result<(), StateError> {
    db::init_schema(conn)?;
    actions::init_actions_schema(conn)?;
    Ok(())
}
