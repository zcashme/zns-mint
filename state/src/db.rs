//! SQLite-backed name registry store.
//!
//! Schema:
//!
//! ```sql
//! CREATE TABLE name_records (
//!   name       TEXT     PRIMARY KEY,
//!   tip_rcm    BLOB     NOT NULL,   -- 32 bytes: the rcm of the last Name Note
//!   ua         TEXT     NOT NULL,   -- current Unified Address binding
//!   height     INTEGER  NOT NULL,   -- block height at which this record was minted
//!   created_at INTEGER  NOT NULL    -- Unix timestamp (seconds)
//! );
//! ```

use rusqlite::{params, Connection, OptionalExtension};

use zns_core::RegistryError;

/// A row from `name_records`.
#[derive(Debug, Clone)]
pub struct NameRecord {
    pub name: String,
    /// The `rcm` of the most recently minted Name Note for this name.
    /// This becomes `prev_rcm` for the next UPDATE / RELEASE.
    pub tip_rcm: [u8; 32],
    /// The current Unified Address bound to the name.
    pub ua: String,
    /// The Zcash block height at which the record was last updated.
    pub height: u32,
}

/// Initialise the database schema (idempotent).
pub fn init_schema(conn: &Connection) -> Result<(), RegistryError> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS name_records (
             name       TEXT    PRIMARY KEY NOT NULL,
             tip_rcm    BLOB    NOT NULL,
             ua         TEXT    NOT NULL,
             height     INTEGER NOT NULL,
             created_at INTEGER NOT NULL
         );
         -- Intake ledger: notes the daemon has settled (acted on, or rejected
         -- for a reason that can never change). The intake scan is stateless
         -- and replays history every poll; without this, an UPDATE request
         -- re-issues a fresh OTP challenge each poll, churning the nonce the
         -- owner is trying to echo back.
         CREATE TABLE IF NOT EXISTS processed_notes (
             txid         BLOB    NOT NULL,
             output_index INTEGER NOT NULL,
             PRIMARY KEY (txid, output_index)
         ) WITHOUT ROWID;",
    )?;
    Ok(())
}

/// Whether the intake note `(txid, output_index)` has already been settled.
pub fn is_processed(
    conn: &Connection,
    txid: &[u8; 32],
    output_index: u32,
) -> Result<bool, RegistryError> {
    let hit: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM processed_notes WHERE txid = ?1 AND output_index = ?2",
            params![txid.as_slice(), output_index],
            |row| row.get(0),
        )
        .optional()?;
    Ok(hit.is_some())
}

/// Settle an intake note: it will be skipped on every future rescan.
pub fn mark_processed(
    conn: &Connection,
    txid: &[u8; 32],
    output_index: u32,
) -> Result<(), RegistryError> {
    conn.execute(
        "INSERT OR IGNORE INTO processed_notes (txid, output_index) VALUES (?1, ?2)",
        params![txid.as_slice(), output_index],
    )?;
    Ok(())
}

/// Retrieve a name record, returning `None` if the name is not registered.
pub fn get_record(conn: &Connection, name: &str) -> Result<Option<NameRecord>, RegistryError> {
    let row = conn
        .query_row(
            "SELECT name, tip_rcm, ua, height FROM name_records WHERE name = ?1",
            params![name],
            |row| {
                let tip_rcm_bytes: Vec<u8> = row.get(1)?;
                Ok((
                    row.get::<_, String>(0)?,
                    tip_rcm_bytes,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                ))
            },
        )
        .optional()?;

    match row {
        None => Ok(None),
        Some((name, tip_rcm_bytes, ua, height)) => {
            let tip_rcm = bytes_to_array32(&tip_rcm_bytes).map_err(|e| {
                RegistryError::Other(anyhow::anyhow!("corrupt tip_rcm in db: {e}"))
            })?;
            Ok(Some(NameRecord {
                name,
                tip_rcm,
                ua,
                height,
            }))
        }
    }
}

/// Insert or replace a name record (called after a successful mint).
pub fn upsert_record(
    conn: &Connection,
    name: &str,
    tip_rcm: &[u8; 32],
    ua: &str,
    height: u32,
) -> Result<(), RegistryError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO name_records (name, tip_rcm, ua, height, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(name) DO UPDATE SET
             tip_rcm    = excluded.tip_rcm,
             ua         = excluded.ua,
             height     = excluded.height",
        params![name, tip_rcm.as_slice(), ua, height, now],
    )?;
    Ok(())
}

/// Delete a name record (called after a successful RELEASE mint).
pub fn delete_record(conn: &Connection, name: &str) -> Result<(), RegistryError> {
    conn.execute(
        "DELETE FROM name_records WHERE name = ?1",
        params![name],
    )?;
    Ok(())
}

fn bytes_to_array32(b: &[u8]) -> Result<[u8; 32], String> {
    b.try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", b.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn insert_and_get() {
        let conn = open();
        let rcm = [0xabu8; 32];
        upsert_record(&conn, "alice", &rcm, "u1xxx", 1_000_000).unwrap();
        let rec = get_record(&conn, "alice").unwrap().unwrap();
        assert_eq!(rec.name, "alice");
        assert_eq!(rec.tip_rcm, rcm);
        assert_eq!(rec.ua, "u1xxx");
        assert_eq!(rec.height, 1_000_000);
    }

    #[test]
    fn missing_returns_none() {
        let conn = open();
        assert!(get_record(&conn, "nobody").unwrap().is_none());
    }

    #[test]
    fn upsert_updates() {
        let conn = open();
        let rcm1 = [0x11u8; 32];
        let rcm2 = [0x22u8; 32];
        upsert_record(&conn, "alice", &rcm1, "u1old", 100).unwrap();
        upsert_record(&conn, "alice", &rcm2, "u1new", 200).unwrap();
        let rec = get_record(&conn, "alice").unwrap().unwrap();
        assert_eq!(rec.tip_rcm, rcm2);
        assert_eq!(rec.ua, "u1new");
    }

    #[test]
    fn delete() {
        let conn = open();
        upsert_record(&conn, "alice", &[0u8; 32], "u1xxx", 100).unwrap();
        delete_record(&conn, "alice").unwrap();
        assert!(get_record(&conn, "alice").unwrap().is_none());
    }
}
