//! Append-only log of minted Name Note actions (`name_events`).
//!
//! `names` holds only the *current* tip per name (one row, the latest event's
//! full data). `name_events` is the canonical history — one row per minted
//! Orchard action (CLAIM / UPDATE / RELEASE). It is the source of truth for
//! `(ψ, rcm)` chain reconstruction, reorg handling, and audit. The row in
//! `names` is a materialized copy of the highest-height event for that name,
//! for O(1) live lookup by name.
//!
//! Reorg: DELETE FROM name_events WHERE height >= ?; then DELETE or re-upsert
//! into `names` by selecting the new max-height remaining event per affected
//! name (or delete the names row if the new tip is a RELEASE or none remain).

use crate::error::StateError;
use rusqlite::{params, Connection};
use zns_core::Action;

/// One minted Orchard action in a name's `(ψ, rcm)` chain.
///
/// Carries the `prev_rcm` that was the input to the `(ψ, rcm)` derivation for
/// this note (ZERO_PREV_RCM for the initial CLAIM). This is the chain-link
/// witness that appears in the registry's canonical Name Note memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedAction {
    /// The name this action applies to.
    pub name: String,
    /// The lifecycle event.
    pub action: Action,
    /// The Unified Address bound by this action (empty for RELEASE).
    pub ua: String,
    /// ZIP-244 txid of the transaction that carried this action.
    pub txid: [u8; 32],
    /// The Name Note's extracted note commitment.
    pub cmx: [u8; 32],
    /// The `rcm` of the Name Note minted by this action (the chain tip after it).
    pub rcm: [u8; 32],
    /// The `psi` of the Name Note minted by this action.
    pub psi: [u8; 32],
    /// The `prev_rcm` input used to derive `(ψ, rcm)` for this action.
    /// For CLAIM this is the all-zero sentinel; for UPDATE/RELEASE it is the
    /// prior action's `rcm`.
    pub prev_rcm: [u8; 32],
    /// Block height at which the action was minted/broadcast.
    pub height: u32,
}

/// Initialise the minted-action log schema (idempotent).
/// Table name: `name_events` (history). Paired with `names` (live tip) in db.rs.
pub fn init_actions_schema(conn: &Connection) -> Result<(), StateError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS name_events (
              name     TEXT    NOT NULL,
              height   INTEGER NOT NULL,
              action   TEXT    NOT NULL,
              ua       TEXT    NOT NULL,
              prev_rcm BLOB    NOT NULL,
              rcm      BLOB    NOT NULL,
              psi      BLOB    NOT NULL,
              cmx      BLOB    NOT NULL,
              txid     BLOB    NOT NULL,
              PRIMARY KEY (name, height)
          );
          CREATE INDEX IF NOT EXISTS idx_name_events_height ON name_events(height);",
    )?;
    // No legacy migration for the rename/split (dev schema). Old tables
    // (name_actions, name_records) are orphaned if present; a fresh DB or
    // manual drop is used during the transition to names+name_events.
    Ok(())
}

/// Append a minted action (event) to the history log.
///
/// The caller must ensure no prior event exists for (name, height) —
/// protocol guarantees one action per name per height.
pub fn append_action(conn: &Connection, a: &MintedAction) -> Result<(), StateError> {
    conn.execute(
        "INSERT INTO name_events (name, height, action, ua, prev_rcm, rcm, psi, cmx, txid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            a.name,
            a.height,
            std::str::from_utf8(a.action.as_bytes()).expect("action bytes are ASCII"),
            a.ua,
            a.prev_rcm.as_slice(),
            a.rcm.as_slice(),
            a.psi.as_slice(),
            a.cmx.as_slice(),
            a.txid.as_slice(),
        ],
    )?;
    Ok(())
}

/// Return every action recorded for `name`, oldest first (i.e. CLAIM → … → tip).
pub fn actions_for(conn: &Connection, name: &str) -> Result<Vec<MintedAction>, StateError> {
    let mut stmt = conn.prepare(
        "SELECT name, action, ua, txid, cmx, rcm, psi, prev_rcm, height
         FROM name_events WHERE name = ?1 ORDER BY height ASC",
    )?;
    let rows = stmt.query_map(params![name], row_to_action)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r??);
    }
    Ok(out)
}

/// Return the most recently minted action for `name`, or `None` if untracked.
pub fn latest_action(conn: &Connection, name: &str) -> Result<Option<MintedAction>, StateError> {
    let mut stmt = conn.prepare(
        "SELECT name, action, ua, txid, cmx, rcm, psi, prev_rcm, height
         FROM name_events WHERE name = ?1 ORDER BY height DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![name], row_to_action)?;
    match rows.next() {
        Some(r) => Ok(Some(r??)),
        None => Ok(None),
    }
}

/// Delete every minted action (event) at or above `height` — used during reorg rewind.
/// After this, callers typically invoke rebuild logic on `names` for the affected names.
pub fn delete_actions_above(conn: &Connection, height: u32) -> Result<(), StateError> {
    conn.execute(
        "DELETE FROM name_events WHERE height >= ?1",
        params![height],
    )?;
    Ok(())
}

/// All distinct names that have any action (event) at or above `height`.
pub fn affected_names(conn: &Connection, min_height: u32) -> Result<Vec<String>, StateError> {
    let mut stmt = conn.prepare("SELECT DISTINCT name FROM name_events WHERE height >= ?1")?;
    let rows = stmt.query_map(params![min_height], |row| row.get::<_, String>(0))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Decode one `name_events` row. The outer `Result` is rusqlite's column
/// access; the inner one is our own validation (action verb, blob lengths).
fn row_to_action(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<MintedAction, StateError>> {
    let name: String = row.get(0)?;
    let action_str: String = row.get(1)?;
    let ua: String = row.get(2)?;
    let txid: Vec<u8> = row.get(3)?;
    let cmx: Vec<u8> = row.get(4)?;
    let rcm: Vec<u8> = row.get(5)?;
    let psi: Vec<u8> = row.get(6)?;
    let prev_rcm: Vec<u8> = row.get(7)?;
    let height: u32 = row.get(8)?;

    Ok((|| {
        let action =
            Action::from_bytes(action_str.as_bytes()).ok_or_else(|| StateError::CorruptRow {
                table: "name_events",
                field: "action",
                detail: format!("unrecognized verb '{action_str}'"),
            })?;
        Ok(MintedAction {
            name,
            action,
            ua,
            txid: blob32(&txid, "txid")?,
            cmx: blob32(&cmx, "cmx")?,
            rcm: blob32(&rcm, "rcm")?,
            psi: blob32(&psi, "psi")?,
            prev_rcm: blob32(&prev_rcm, "prev_rcm")?,
            height,
        })
    })())
}

fn blob32(b: &[u8], field: &'static str) -> Result<[u8; 32], StateError> {
    b.try_into().map_err(|_| StateError::CorruptRow {
        table: "name_events",
        field,
        detail: format!("expected 32 bytes, got {}", b.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_actions_schema(&conn).unwrap();
        conn
    }

    fn sample(name: &str, action: Action, tag: u8) -> MintedAction {
        // For test data, use a distinct prev_rcm per sample (tag-derived).
        // Real usage chains: a later action's prev_rcm == prior action's rcm.
        MintedAction {
            name: name.to_owned(),
            action,
            ua: if action == Action::Release {
                String::new()
            } else {
                format!("u1{tag:02x}")
            },
            txid: [tag; 32],
            cmx: [tag.wrapping_add(1); 32],
            rcm: [tag.wrapping_add(2); 32],
            psi: [tag.wrapping_add(3); 32],
            prev_rcm: [tag.wrapping_add(4); 32],
            height: 2_000_000 + tag as u32,
        }
    }

    #[test]
    fn append_and_read_back_in_order() {
        let conn = open();
        append_action(&conn, &sample("alice", Action::Claim, 1)).unwrap();
        append_action(&conn, &sample("alice", Action::Update, 2)).unwrap();

        let log = actions_for(&conn, "alice").unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].action, Action::Claim);
        assert_eq!(log[1].action, Action::Update);
        assert_eq!(log[1].txid, [2; 32]);
    }

    #[test]
    fn latest_is_the_tip() {
        let conn = open();
        append_action(&conn, &sample("bob", Action::Claim, 5)).unwrap();
        append_action(&conn, &sample("bob", Action::Update, 9)).unwrap();

        let tip = latest_action(&conn, "bob").unwrap().unwrap();
        assert_eq!(tip.action, Action::Update);
        assert_eq!(tip.rcm, [11; 32]); // 9 + 2
    }

    #[test]
    fn untracked_name_has_no_actions() {
        let conn = open();
        assert!(actions_for(&conn, "nobody").unwrap().is_empty());
        assert!(latest_action(&conn, "nobody").unwrap().is_none());
    }

    #[test]
    fn actions_carry_ua_for_reorg_reconstruction() {
        let conn = open();
        let claim = sample("alice", Action::Claim, 1);
        let update = sample("alice", Action::Update, 2);
        append_action(&conn, &claim).unwrap();
        append_action(&conn, &update).unwrap();

        let log = actions_for(&conn, "alice").unwrap();
        assert_eq!(log[0].ua, "u101");
        assert_eq!(log[1].ua, "u102");

        let tip = latest_action(&conn, "alice").unwrap().unwrap();
        assert_eq!(tip.ua, "u102");
    }

    #[test]
    fn release_action_has_empty_ua() {
        let conn = open();
        let release = sample("alice", Action::Release, 3);
        append_action(&conn, &release).unwrap();
        let tip = latest_action(&conn, "alice").unwrap().unwrap();
        assert_eq!(tip.action, Action::Release);
        assert!(tip.ua.is_empty());
    }
}
