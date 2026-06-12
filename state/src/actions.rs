//! Append-only log of minted Name Note actions.
//!
//! `name_records` holds only the *current* tip per name; this table is the
//! canonical history — one row per minted Orchard action (CLAIM / UPDATE /
//! RELEASE). It is the source of truth for witness reconstruction, reorg
//! handling, and audit. The tip in `name_records` is just the latest row here,
//! cached for O(1) lookup.

use rusqlite::{params, Connection};
use zns_core::Action;
use crate::error::StateError;

/// One minted Orchard action in a name's `(ψ, rcm)` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedAction {
    /// The name this action applies to.
    pub name: String,
    /// The lifecycle event.
    pub action: Action,
    /// ZIP-244 txid of the transaction that carried this action.
    pub txid: [u8; 32],
    /// The Name Note's extracted note commitment.
    pub cmx: [u8; 32],
    /// The `rcm` of the Name Note minted by this action (the chain tip after it).
    pub rcm: [u8; 32],
    /// The `psi` of the Name Note minted by this action.
    pub psi: [u8; 32],
    /// Block height at which the action was minted/broadcast.
    pub height: u32,
}

/// Initialise the minted-action log schema (idempotent).
pub fn init_actions_schema(conn: &Connection) -> Result<(), StateError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS name_actions (
             id         INTEGER PRIMARY KEY AUTOINCREMENT,
             name       TEXT    NOT NULL,
             action     TEXT    NOT NULL,
             txid       BLOB    NOT NULL,
             cmx        BLOB    NOT NULL,
             rcm        BLOB    NOT NULL,
             psi        BLOB    NOT NULL,
             height     INTEGER NOT NULL,
             created_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_name_actions_name ON name_actions(name, id);",
    )?;
    Ok(())
}

/// Append a minted action to the log, returning its rowid.
pub fn append_action(conn: &Connection, a: &MintedAction) -> Result<i64, StateError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO name_actions (name, action, txid, cmx, rcm, psi, height, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            a.name,
            std::str::from_utf8(a.action.as_bytes()).expect("action bytes are ASCII"),
            a.txid.as_slice(),
            a.cmx.as_slice(),
            a.rcm.as_slice(),
            a.psi.as_slice(),
            a.height,
            now,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Return every action recorded for `name`, oldest first (i.e. CLAIM → … → tip).
pub fn actions_for(conn: &Connection, name: &str) -> Result<Vec<MintedAction>, StateError> {
    let mut stmt = conn.prepare(
        "SELECT name, action, txid, cmx, rcm, psi, height
         FROM name_actions WHERE name = ?1 ORDER BY id ASC",
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
        "SELECT name, action, txid, cmx, rcm, psi, height
         FROM name_actions WHERE name = ?1 ORDER BY id DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![name], row_to_action)?;
    match rows.next() {
        Some(r) => Ok(Some(r??)),
        None => Ok(None),
    }
}

/// Decode one `name_actions` row. The outer `Result` is rusqlite's column
/// access; the inner one is our own validation (action verb, blob lengths).
fn row_to_action(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<MintedAction, StateError>> {
    let name: String = row.get(0)?;
    let action_str: String = row.get(1)?;
    let txid: Vec<u8> = row.get(2)?;
    let cmx: Vec<u8> = row.get(3)?;
    let rcm: Vec<u8> = row.get(4)?;
    let psi: Vec<u8> = row.get(5)?;
    let height: u32 = row.get(6)?;

    Ok((|| {
        let action = Action::from_bytes(action_str.as_bytes()).ok_or_else(|| {
            StateError::Other(anyhow::anyhow!("corrupt action verb '{action_str}' in db"))
        })?;
        Ok(MintedAction {
            name,
            action,
            txid: blob32(&txid, "txid")?,
            cmx: blob32(&cmx, "cmx")?,
            rcm: blob32(&rcm, "rcm")?,
            psi: blob32(&psi, "psi")?,
            height,
        })
    })())
}

fn blob32(b: &[u8], field: &str) -> Result<[u8; 32], StateError> {
    b.try_into()
        .map_err(|_| StateError::Other(anyhow::anyhow!("corrupt {field}: expected 32 bytes, got {}", b.len())))
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
        MintedAction {
            name: name.to_owned(),
            action,
            txid: [tag; 32],
            cmx: [tag.wrapping_add(1); 32],
            rcm: [tag.wrapping_add(2); 32],
            psi: [tag.wrapping_add(3); 32],
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
}
