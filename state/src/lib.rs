//! `zns-state` — ZNS registry persistence.
//!
//! Owns the SQLite stores:
//! - [`db`] holds the live `names` table (current tip binding per active name,
//!   one row, O(1) by name) plus ancillary tables (processed_notes, challenges,
//!   intents).
//! - [`actions`] holds the append-only `name_events` history log (one row per
//!   CLAIM/UPDATE/RELEASE). This is the source of truth for the `(ψ, rcm)`
//!   chain and for reorg reconstruction.
//!
//! The split (live `names` + history `name_events`) keeps the hot path tiny
//! while allowing the history to be pruned or archived independently if ever
//! needed. Both are updated atomically with the other registry tables in the
//! same transaction on mint or reorg.
//!
//! Split out of `zns-core` so the storage layer is its own crate (cf.
//! `zebra-state`) and pure consumers of the domain types never link rusqlite.
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
    upsert_record_from_action, NameRecord,
};
pub use error::StateError;
pub use treasury::{FundingSelection, NoteState, SpendableNote, TreasuryConfig, TreasuryError};

use rusqlite::Connection;

pub struct State {
    conn: Connection,
}

impl State {
    pub fn open(path: &str) -> Result<Self, StateError> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(State { conn })
    }

    pub fn open_in_memory() -> Result<Self, StateError> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(State { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn apply_mint(&self, minted: &MintedAction) -> Result<(), StateError> {
        let tx = self.conn.unchecked_transaction()?;
        append_action(&tx, minted)?;
        if minted.action == zns_core::Action::Release {
            delete_record(&tx, &minted.name)?;
        } else {
            upsert_record_from_action(&tx, minted)?;
        }
        db::delete_challenge(&tx, &minted.name)?;
        db::delete_intent(&tx, &minted.name)?;
        tx.commit()?;
        Ok(())
    }

    pub fn apply_reorg<F>(&self, height: u32, mut releaser: F) -> Result<usize, StateError>
    where
        F: FnMut(([u8; 32], u32)),
    {
        let tx = self.conn.unchecked_transaction()?;
        let names = affected_names(&tx, height)?;
        let intents = db::list_intents(&tx)?;
        for intent in &intents {
            if intent.minted.height >= height {
                releaser((intent.request.0, intent.request.1));
            }
        }
        db::delete_intents_above(&tx, height)?;
        db::delete_processed_above(&tx, height)?;
        delete_actions_above(&tx, height)?;
        rebuild_records_after_reorg(&tx, &names)?;
        tx.commit()?;
        Ok(names.len())
    }

    pub fn delete_intent(&self, name: &str) -> Result<(), StateError> {
        db::delete_intent(&self.conn, name)
    }
}

/// Initialise the full registry schema (idempotent): the live `names` tip table,
/// the append-only `name_events` history, and ancillary tables.
pub fn init_schema(conn: &Connection) -> Result<(), StateError> {
    db::init_schema(conn)?;
    actions::init_actions_schema(conn)?;
    Ok(())
}
