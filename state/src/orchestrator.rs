//! Orchestrator cursor persistence (`scan_tip`, `in_flight_spend`, `sweep_cursor`).

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StateError;

/// Persisted scan cursor: last block whose intake is fully classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanTip {
    pub height: u32,
    pub hash: [u8; 32],
}

/// Last successful cold sweep (rate gate + operator audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepCursor {
    /// Chain height when the sweep was broadcast. `0` = never swept.
    pub height: u32,
    /// Txid of that sweep. `None` until the first successful broadcast.
    pub txid: Option<[u8; 32]>,
}

/// Broadcast tx awaiting chain confirmation before the next spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightSpend {
    pub txid: [u8; 32],
    pub request_txid: [u8; 32],
    pub request_index: u32,
    pub expiry_height: u32,
    /// `true` = OTP relay; cleared when tx is on chain. `false` = name mint; cleared on name note sight.
    pub relay: bool,
    pub name: String,
}

pub fn init_orchestrator_schema(conn: &Connection) -> Result<(), StateError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scan_tip (
             id     INTEGER PRIMARY KEY CHECK (id = 1),
             height INTEGER NOT NULL,
             hash   BLOB    NOT NULL
         );
         CREATE TABLE IF NOT EXISTS in_flight_spend (
             id              INTEGER PRIMARY KEY CHECK (id = 1),
             txid            BLOB,
             request_txid    BLOB,
             request_index   INTEGER,
             expiry_height   INTEGER,
             relay           INTEGER NOT NULL DEFAULT 0,
             sweep           INTEGER NOT NULL DEFAULT 0,
             name            TEXT    NOT NULL DEFAULT ''
         );
         CREATE TABLE IF NOT EXISTS sweep_cursor (
             id     INTEGER PRIMARY KEY CHECK (id = 1),
             height INTEGER NOT NULL DEFAULT 0,
             txid   BLOB
         );",
    )?;
    for ddl in [
        "ALTER TABLE in_flight_spend ADD COLUMN relay INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE in_flight_spend ADD COLUMN name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE in_flight_spend ADD COLUMN sweep INTEGER NOT NULL DEFAULT 0",
    ] {
        match conn.execute(ddl, []) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
    }
    conn.execute(
        "INSERT OR IGNORE INTO scan_tip (id, height, hash)
         VALUES (1, 0, x'0000000000000000000000000000000000000000000000000000000000000000')",
        [],
    )?;
    conn.execute("INSERT OR IGNORE INTO in_flight_spend (id) VALUES (1)", [])?;
    conn.execute("INSERT OR IGNORE INTO sweep_cursor (id) VALUES (1)", [])?;
    Ok(())
}

pub fn get_sweep_cursor(conn: &Connection) -> Result<SweepCursor, StateError> {
    let row: (i64, Option<Vec<u8>>) = conn.query_row(
        "SELECT height, txid FROM sweep_cursor WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let height = u32::try_from(row.0).map_err(|_| StateError::CorruptRow {
        table: "sweep_cursor",
        field: "height",
        detail: format!("out of range: {}", row.0),
    })?;
    let txid = match row.1 {
        None => None,
        Some(bytes) => Some(bytes_to_hash(&bytes)?),
    };
    Ok(SweepCursor { height, txid })
}

pub fn set_sweep_cursor(conn: &Connection, cursor: &SweepCursor) -> Result<(), StateError> {
    conn.execute(
        "UPDATE sweep_cursor SET height = ?1, txid = ?2 WHERE id = 1",
        params![cursor.height, cursor.txid.as_ref().map(|t| t.as_slice())],
    )?;
    Ok(())
}

pub fn get_scan_tip(conn: &Connection) -> Result<Option<ScanTip>, StateError> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row("SELECT height, hash FROM scan_tip WHERE id = 1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()?;
    let Some((height, hash)) = row else {
        return Ok(None);
    };
    if height == 0 {
        return Ok(None);
    }
    Ok(Some(ScanTip {
        height: height as u32,
        hash: bytes_to_hash(&hash)?,
    }))
}

pub fn set_scan_tip(conn: &Connection, tip: &ScanTip) -> Result<(), StateError> {
    conn.execute(
        "INSERT INTO scan_tip (id, height, hash) VALUES (1, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET height = ?1, hash = ?2",
        params![tip.height, tip.hash.as_slice()],
    )?;
    Ok(())
}

/// Rewind the scan cursor so the next catch-up pass replays from `reorg_height`.
pub fn rewind_scan_tip(conn: &Connection, reorg_height: u32) -> Result<(), StateError> {
    let rewind_to = reorg_height.saturating_sub(1);
    if rewind_to == 0 {
        conn.execute(
            "UPDATE scan_tip SET height = 0,
             hash = x'0000000000000000000000000000000000000000000000000000000000000000'
             WHERE id = 1",
            [],
        )?;
    } else {
        conn.execute(
            "UPDATE scan_tip SET height = ?1,
             hash = x'0000000000000000000000000000000000000000000000000000000000000000'
             WHERE id = 1",
            params![rewind_to],
        )?;
    }
    Ok(())
}

pub fn get_in_flight(conn: &Connection) -> Result<Option<InFlightSpend>, StateError> {
    let row: Option<(
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
    )> = conn
        .query_row(
            "SELECT txid, request_txid, request_index, expiry_height, relay, sweep, name
             FROM in_flight_spend WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((txid, req_txid, req_idx, expiry, relay, _sweep, name)) = row else {
        return Ok(None);
    };
    let (Some(txid), Some(req_txid), Some(req_idx), Some(expiry)) = (txid, req_txid, req_idx, expiry)
    else {
        return Ok(None);
    };
    Ok(Some(InFlightSpend {
        txid: bytes_to_hash(&txid)?,
        request_txid: bytes_to_hash(&req_txid)?,
        request_index: req_idx as u32,
        expiry_height: expiry as u32,
        relay: relay.unwrap_or(0) != 0,
        name: name.unwrap_or_default(),
    }))
}

pub fn set_in_flight(conn: &Connection, flight: &InFlightSpend) -> Result<(), StateError> {
    conn.execute(
        "UPDATE in_flight_spend
         SET txid = ?1, request_txid = ?2, request_index = ?3, expiry_height = ?4,
             relay = ?5, sweep = ?6, name = ?7
         WHERE id = 1",
        params![
            flight.txid.as_slice(),
            flight.request_txid.as_slice(),
            flight.request_index,
            flight.expiry_height,
            i64::from(flight.relay),
            0i64,
            flight.name,
        ],
    )?;
    Ok(())
}

pub fn clear_in_flight(conn: &Connection) -> Result<(), StateError> {
    conn.execute(
        "UPDATE in_flight_spend
         SET txid = NULL, request_txid = NULL, request_index = NULL, expiry_height = NULL,
             relay = 0, sweep = 0, name = ''
         WHERE id = 1",
        [],
    )?;
    Ok(())
}

fn bytes_to_hash(bytes: &[u8]) -> Result<[u8; 32], StateError> {
    bytes
        .try_into()
        .map_err(|_| StateError::CorruptRow {
            table: "orchestrator",
            field: "hash",
            detail: format!("expected 32 bytes, got {}", bytes.len()),
        })
}