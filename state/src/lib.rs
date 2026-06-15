//! `zns-state` — ZNS registry persistence.
//!
//! Owns the SQLite stores:
//! - [`db`] owns the live `names` table (fast current binding per active name,
//!   plus the chain-head `rcm` for the next mutation) and ancillary tables
//!   (processed_notes, challenges).
//! - [`actions`] owns the append-only `name_events` history log (one row per
//!   CLAIM/UPDATE/RELEASE). This is the source of truth for the `(ψ, rcm)`
//!   chain and for reorg reconstruction.
//!
//! The public API exposes a thin [`Name`] (just the name → UA binding) via
//! `get_record` / `lookup`. Verification / chain data is available separately
//! via `get_current_rcm`, `latest_action`, or `MintedAction`.
//!
//! The split (live `names` tip + history `name_events`) keeps the hot path
//! tiny while allowing the history to be pruned or archived independently if
//! ever needed. Both are updated atomically with the other registry tables in
//! the same transaction on mint or reorg.
//!
//! Split out of `zns-core` so the storage layer is its own crate and pure
//! consumers of the domain types never link rusqlite.
//!
//! [`treasury`] is the registry's *other* SQLite store — a `zcash_client_sqlite`
//! `WalletDb` tracking the registry's own spendable notes (the treasury float)
//! for self-funding mint fees. A separate database from `db`/`actions`.
//!
//! IMPORTANT: this module is *passive persistence only*. It opens the WalletDb,
//! performs note selection + witness extraction, and provides an explicit seam
//! (`NoteState::wallet_db_mut`) for an external driver. It does **not** own
//! lightwalletd clients, perform sync, implement BlockCache, or contain any
//! transport URLs. The main orchestrator (or a thin coordinator in `chain`)
//! drives `sync::run` / `scan_cached_blocks` and bootstrap.

pub mod actions;
pub mod block_cache;
pub mod db;
pub mod error;
pub mod orchestrator;
pub mod treasury;

pub use treasury::{FundingSelection, SpendableNote, Treasury, TreasuryConfig, TreasuryError};

/// Compatibility alias.
///
/// Most of the "NoteState owns the seam and the orchestrator drives sync"
/// story is aspirational. In the current mint binary this is a dummy
/// uninitialized value and the real sync path is disabled.
pub type NoteState = treasury::Treasury;

pub use actions::{
    actions_for, affected_names, append_action, delete_actions_above, latest_action, MintedAction,
};
pub use db::{
    delete_processed_above, delete_record, get_current_rcm, get_record, last_processed_height,
    mark_processed, processed_hash_at_height, rebuild_records_after_reorg, upsert_record_from_action,
    Name,
};
pub use error::StateError;
pub use orchestrator::{InFlightSpend, ScanTip, SweepCursor};

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

    pub fn apply_mint(&self, minted: &MintedAction) -> Result<(), StateError> {
        let tx = self.conn.unchecked_transaction()?;
        append_action(&tx, minted)?;
        if minted.action == zns_core::Action::Release {
            delete_record(&tx, &minted.name)?;
        } else {
            upsert_record_from_action(&tx, minted)?;
        }
        db::delete_challenge(&tx, &minted.name)?;
        tx.commit()?;
        Ok(())
    }

    pub fn apply_reorg<F>(&self, height: u32, mut releaser: F) -> Result<usize, StateError>
    where
        F: FnMut(([u8; 32], u32)),
    {
        let tx = self.conn.unchecked_transaction()?;
        let names = affected_names(&tx, height)?;
        if let Some(flight) = orchestrator::get_in_flight(&tx)? {
            releaser((flight.request_txid, flight.request_index));
        }
        db::delete_processed_above(&tx, height)?;
        orchestrator::rewind_scan_tip(&tx, height)?;
        orchestrator::clear_in_flight(&tx)?;
        delete_actions_above(&tx, height)?;
        rebuild_records_after_reorg(&tx, &names)?;
        tx.commit()?;
        Ok(names.len())
    }

    /// Return the current public binding for a name (name + UA).
    ///
    /// This is the thin resolution record. Chain-head verification data
    /// (the `rcm` needed as `prev_rcm` for the next mutation) is returned
    /// separately by [`Self::get_current_rcm`].
    pub fn get_record(&self, name: &str) -> Result<Option<Name>, StateError> {
        db::get_record(&self.conn, name)
    }

    /// Return the current chain-head `rcm` for a name (if registered).
    ///
    /// This is the value that must be used as `prev_rcm` when minting the
    /// next UPDATE or RELEASE for the name.
    pub fn get_current_rcm(&self, name: &str) -> Result<Option<[u8; 32]>, StateError> {
        db::get_current_rcm(&self.conn, name)
    }

    pub fn table_counts(&self) -> Result<(u64, u64), StateError> {
        db::table_counts(&self.conn)
    }

    pub fn is_processed(&self, txid: &[u8; 32], pool: u8, output_index: u32) -> Result<bool, StateError> {
        db::is_processed(&self.conn, txid, pool, output_index)
    }

    pub fn mark_processed(&self, txid: &[u8; 32], pool: u8, output_index: u32, block_height: u32, block_hash: &[u8; 32]) -> Result<(), StateError> {
        db::mark_processed(&self.conn, txid, pool, output_index, block_height, block_hash)
    }

    pub fn get_challenge(&self, name: &str) -> Result<Option<zns_auth::PendingChallenge>, StateError> {
        db::get_challenge(&self.conn, name)
    }

    pub fn put_challenge(&self, c: &zns_auth::PendingChallenge) -> Result<(), StateError> {
        db::put_challenge(&self.conn, c)
    }

    pub fn purge_expired_challenges(&self, current_height: u32) -> Result<(), StateError> {
        db::purge_expired_challenges(&self.conn, current_height)
    }

    pub fn last_processed_height(&self) -> Result<Option<u32>, StateError> {
        db::last_processed_height(&self.conn)
    }

    pub fn processed_hash_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        db::processed_hash_at_height(&self.conn, height)
    }

    pub fn delete_processed_above(&self, height: u32) -> Result<(), StateError> {
        db::delete_processed_above(&self.conn, height)
    }

    pub fn delete_challenge(&self, name: &str) -> Result<(), StateError> {
        db::delete_challenge(&self.conn, name)
    }

    pub fn get_scan_tip(&self) -> Result<Option<ScanTip>, StateError> {
        orchestrator::get_scan_tip(&self.conn)
    }

    pub fn set_scan_tip(&self, tip: &ScanTip) -> Result<(), StateError> {
        orchestrator::set_scan_tip(&self.conn, tip)
    }

    pub fn get_in_flight(&self) -> Result<Option<InFlightSpend>, StateError> {
        orchestrator::get_in_flight(&self.conn)
    }

    pub fn set_in_flight(&self, flight: &InFlightSpend) -> Result<(), StateError> {
        orchestrator::set_in_flight(&self.conn, flight)
    }

    pub fn clear_in_flight(&self) -> Result<(), StateError> {
        orchestrator::clear_in_flight(&self.conn)
    }

    pub fn get_sweep_cursor(&self) -> Result<SweepCursor, StateError> {
        orchestrator::get_sweep_cursor(&self.conn)
    }

    pub fn set_sweep_cursor(&self, cursor: &SweepCursor) -> Result<(), StateError> {
        orchestrator::set_sweep_cursor(&self.conn, cursor)
    }
}

/// Initialise the full registry schema (idempotent): the live `names` tip table,
/// the append-only `name_events` history, and ancillary tables.
pub fn init_schema(conn: &Connection) -> Result<(), StateError> {
    db::init_schema(conn)?;
    actions::init_actions_schema(conn)?;
    orchestrator::init_orchestrator_schema(conn)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_cursor_round_trip() {
        let state = State::open_in_memory().unwrap();
        assert_eq!(
            state.get_sweep_cursor().unwrap(),
            SweepCursor {
                height: 0,
                txid: None,
            }
        );

        let cursor = SweepCursor {
            height: 2_000_500,
            txid: Some([0xab; 32]),
        };
        state.set_sweep_cursor(&cursor).unwrap();
        assert_eq!(state.get_sweep_cursor().unwrap(), cursor);
    }

    #[test]
    fn apply_reorg_releases_in_flight_request() {
        let state = State::open_in_memory().unwrap();
        state
            .set_in_flight(&InFlightSpend {
                txid: [9u8; 32],
                request_txid: [7u8; 32],
                request_index: 2,
                expiry_height: 300,
                relay: false,
                name: "alice".into(),
            })
            .unwrap();

        let mut released = None;
        state
            .apply_reorg(100, |(txid, idx)| released = Some((txid, idx)))
            .unwrap();

        assert_eq!(released, Some(([7u8; 32], 2)));
        assert!(state.get_in_flight().unwrap().is_none());
    }

}
