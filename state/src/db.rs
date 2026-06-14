//! SQLite-backed name registry store.
//!

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StateError;

/// A row from the live `names` table (current tip binding for an active name).
///
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
pub fn init_schema(conn: &Connection) -> Result<(), StateError> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         -- Live tip per name (denormalized latest event from name_events).
         -- One row per actively bound name. RELEASE removes the row; reorg may
         -- restore an earlier binding or remove the row if the new tip is RELEASE.
         CREATE TABLE IF NOT EXISTS names (
             name     TEXT    PRIMARY KEY NOT NULL,
             height   INTEGER NOT NULL,
             action   TEXT    NOT NULL,
             ua       TEXT    NOT NULL,
             prev_rcm BLOB    NOT NULL,
             rcm      BLOB    NOT NULL,
             psi      BLOB    NOT NULL,
             cmx      BLOB    NOT NULL,
             txid     BLOB    NOT NULL
         );
         -- Intake ledger: notes the daemon has settled (acted on, or rejected
         -- for a reason that can never change). The intake scan is stateless
         -- and replays history every poll; without this, an UPDATE request
         -- re-issues a fresh OTP challenge each poll, churning the nonce the
         -- owner is trying to echo back.
         CREATE TABLE IF NOT EXISTS processed_notes (
             txid         BLOB    NOT NULL,
             output_index INTEGER NOT NULL,
             block_height INTEGER NOT NULL,
             block_hash   BLOB    NOT NULL,
             PRIMARY KEY (txid, output_index)
         ) WITHOUT ROWID;
         -- Pending OTP challenges (zns-auth::PendingChallenge), durable so a
         -- daemon restart cannot void a mutation mid-flow. Expiry is by block
         -- height; rows are deleted in the same transaction as the record
         -- update of the mint they authorize.
         CREATE TABLE IF NOT EXISTS pending_challenges (
             name           TEXT    PRIMARY KEY NOT NULL,
             action         TEXT    NOT NULL CHECK (action IN ('update','release')),
             ua_new         TEXT    NOT NULL,
             nonce          TEXT    NOT NULL,
             expires_height INTEGER NOT NULL
         );
         -- Mint intents: written BEFORE broadcast, deleted in the same
         -- transaction as the mint's persistence. An intent that survives a
         -- crash is reconciled at poll start: if its txid is on chain the
         -- persistence is replayed; if the tx expired unmined the intent is
         -- dropped. Without this, a crash between broadcast and persistence
         -- re-mints the name next poll — two Name Notes, forked rcm chains.
         CREATE TABLE IF NOT EXISTS mint_intents (
             name          TEXT    PRIMARY KEY NOT NULL,
             action        TEXT    NOT NULL CHECK (action IN ('claim','update','release')),
             ua            TEXT    NOT NULL,
             txid          BLOB    NOT NULL,
             cmx           BLOB    NOT NULL,
             rcm           BLOB    NOT NULL,
             psi           BLOB    NOT NULL,
             prev_rcm      BLOB    NOT NULL,
             height        INTEGER NOT NULL,
             expiry_height INTEGER NOT NULL,
             -- the intake note that triggered the mint; dropping a dead
             -- intent releases this id from the signer's replay set
             request_txid  BLOB    NOT NULL,
              request_idx   INTEGER NOT NULL
          );
          -- Hot-path indexes: reorg rewind and expiry purge operate on ranges.
          CREATE INDEX IF NOT EXISTS idx_processed_notes_height ON processed_notes(block_height);
          CREATE INDEX IF NOT EXISTS idx_mint_intents_height ON mint_intents(height);
          CREATE INDEX IF NOT EXISTS idx_pending_challenges_expires ON pending_challenges(expires_height);",
    )?;
    // Migrate pre-`request_*` intent tables in place (the zeroed default is
    // only a placeholder; such intents simply release nothing on drop).
    for ddl in [
        "ALTER TABLE mint_intents ADD COLUMN request_txid BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000'",
        "ALTER TABLE mint_intents ADD COLUMN request_idx INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE processed_notes ADD COLUMN block_height INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE processed_notes ADD COLUMN block_hash BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000'",
        // prev_rcm added when we started storing the full chain witness in
        // MintedAction (and thus in durable intents for crash recovery).
        "ALTER TABLE mint_intents ADD COLUMN prev_rcm BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000'",
    ] {
        match conn.execute(ddl, []) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mint intents (broadcast/persistence crash recovery)
// ---------------------------------------------------------------------------

/// A mint that has been authored (and possibly broadcast) but whose
/// persistence has not yet been committed.
#[derive(Debug, Clone)]
pub struct PendingMint {
    /// Everything the history event will record about the mint (incl. prev_rcm
    /// chain link and the UA), plus the fields that will go into the live
    /// `names` row once the intent is reconciled via persist_mint.
    pub minted: crate::MintedAction,
    /// The transaction's expiry height (0 = never expires; such an intent is
    /// only ever resolved by finding the tx).
    pub expiry_height: u32,
    /// The intake note `(txid, output_index)` that triggered this mint —
    /// released from the signer's replay set if the intent dies.
    pub request: ([u8; 32], u32),
}

/// Record a mint intent before broadcasting it. At most one in-flight mint
/// per name (`INSERT OR REPLACE` — the guard in the mint path prevents a
/// replacement while one is genuinely pending).
pub fn put_intent(conn: &Connection, intent: &PendingMint) -> Result<(), StateError> {
    conn.execute(
        "INSERT OR REPLACE INTO mint_intents
             (name, action, ua, txid, cmx, rcm, psi, prev_rcm, height, expiry_height,
              request_txid, request_idx)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            intent.minted.name,
            std::str::from_utf8(intent.minted.action.as_bytes()).expect("ascii"),
            intent.minted.ua,
            intent.minted.txid.as_slice(),
            intent.minted.cmx.as_slice(),
            intent.minted.rcm.as_slice(),
            intent.minted.psi.as_slice(),
            intent.minted.prev_rcm.as_slice(),
            intent.minted.height,
            intent.expiry_height,
            intent.request.0.as_slice(),
            intent.request.1,
        ],
    )?;
    Ok(())
}

/// The in-flight mint for `name`, if any.
pub fn get_intent(conn: &Connection, name: &str) -> Result<Option<PendingMint>, StateError> {
    conn.query_row(
        "SELECT name, action, ua, txid, cmx, rcm, psi, prev_rcm, height, expiry_height,
                request_txid, request_idx
         FROM mint_intents WHERE name = ?1",
        params![name],
        row_to_intent,
    )
    .optional()
    .map_err(Into::into)
}

/// Every in-flight mint — the reconciliation work list.
pub fn list_intents(conn: &Connection) -> Result<Vec<PendingMint>, StateError> {
    let mut stmt = conn.prepare(
        "SELECT name, action, ua, txid, cmx, rcm, psi, prev_rcm, height, expiry_height,
                request_txid, request_idx
         FROM mint_intents",
    )?;
    let rows = stmt
        .query_map([], row_to_intent)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Remove the intent for `name` (idempotent) — in the same transaction as the
/// mint's persistence.
pub fn delete_intent(conn: &Connection, name: &str) -> Result<(), StateError> {
    conn.execute("DELETE FROM mint_intents WHERE name = ?1", params![name])?;
    Ok(())
}

/// Delete every mint intent at or above `height` — used during reorg rewind.
pub fn delete_intents_above(conn: &Connection, height: u32) -> Result<(), StateError> {
    conn.execute(
        "DELETE FROM mint_intents WHERE height >= ?1",
        params![height],
    )?;
    Ok(())
}

/// Rebuild the live `names` table for the given `names` after orphaned
/// events have been deleted from `name_events`.
///
/// For each name, the tip row in `names` is set from the latest remaining
/// event (by height), or the row is deleted if no events remain or the new
/// tip event is a RELEASE. Must be called inside an existing transaction so
/// the rollback is atomic with the event/intent deletions.
pub fn rebuild_records_after_reorg(conn: &Connection, names: &[String]) -> Result<(), StateError> {
    for name in names {
        match crate::actions::latest_action(conn, name)? {
            Some(action) if action.action == zns_core::Action::Release => {
                // The latest remaining event is a RELEASE: the name must not
                // exist in the live tip table.
                delete_record(conn, name)?;
            }
            Some(action) => {
                // Copy the latest surviving event (which carries its own
                // prev_rcm + rcm + ua + ...) into the live `names` table.
                // This gives O(1) name -> current binding + the chain witness.
                upsert_record_from_action(conn, &action)?;
            }
            None => {
                delete_record(conn, name)?;
            }
        }
    }
    Ok(())
}

/// Row counts for the daemon's status surface:
/// `(names (live count), pending_challenges, mint_intents)`.
pub fn table_counts(conn: &Connection) -> Result<(u64, u64, u64), StateError> {
    let count = |table: &str| -> Result<u64, rusqlite::Error> {
        // Table names are the compile-time constants below, never user input.
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
            r.get::<_, i64>(0)
        })
        .map(|n| n as u64)
    };
    Ok((
        count("names")?,
        count("pending_challenges")?,
        count("mint_intents")?,
    ))
}

fn row_to_intent(row: &rusqlite::Row) -> rusqlite::Result<PendingMint> {
    let to32 = |v: Vec<u8>, col| {
        v.try_into()
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(col, 0))
    };
    let action = zns_core::Action::from_bytes(row.get::<_, String>(1)?.as_bytes())
        .ok_or(rusqlite::Error::IntegralValueOutOfRange(1, 0))?;
    Ok(PendingMint {
        minted: crate::MintedAction {
            name: row.get(0)?,
            action,
            ua: row.get(2)?,
            txid: to32(row.get(3)?, 3)?,
            cmx: to32(row.get(4)?, 4)?,
            rcm: to32(row.get(5)?, 5)?,
            psi: to32(row.get(6)?, 6)?,
            prev_rcm: to32(row.get(7)?, 7)?,
            height: row.get(8)?,
        },
        expiry_height: row.get(9)?,
        request: (to32(row.get(10)?, 10)?, row.get(11)?),
    })
}

// ---------------------------------------------------------------------------
// Pending OTP challenges
// ---------------------------------------------------------------------------

/// Store (or replace — a retried request supersedes) the pending challenge
/// for its name.
pub fn put_challenge(conn: &Connection, c: &zns_auth::PendingChallenge) -> Result<(), StateError> {
    let action = match c.action {
        zns_core::Action::Update => "update",
        zns_core::Action::Release => "release",
        zns_core::Action::Claim => {
            return Err(StateError::Invariant(
                "claim challenges do not exist".into(),
            ))
        }
    };
    conn.execute(
        "INSERT OR REPLACE INTO pending_challenges
             (name, action, ua_new, nonce, expires_height)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![c.name, action, c.ua_new, c.nonce, c.expires_height],
    )?;
    Ok(())
}

/// Load the pending challenge for `name`, if any.
pub fn get_challenge(
    conn: &Connection,
    name: &str,
) -> Result<Option<zns_auth::PendingChallenge>, StateError> {
    conn.query_row(
        "SELECT name, action, ua_new, nonce, expires_height
         FROM pending_challenges WHERE name = ?1",
        params![name],
        |row| {
            let action = match row.get::<_, String>(1)?.as_str() {
                "update" => zns_core::Action::Update,
                "release" => zns_core::Action::Release,
                _ => return Err(rusqlite::Error::IntegralValueOutOfRange(1, 0)),
            };
            Ok(zns_auth::PendingChallenge {
                name: row.get(0)?,
                action,
                ua_new: row.get(2)?,
                nonce: row.get(3)?,
                expires_height: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

/// Delete the pending challenge for `name` (idempotent). Callers completing a
/// mint run this on the same connection/transaction as the record update.
pub fn delete_challenge(conn: &Connection, name: &str) -> Result<(), StateError> {
    conn.execute(
        "DELETE FROM pending_challenges WHERE name = ?1",
        params![name],
    )?;
    Ok(())
}

/// Drop every challenge that expired before `current_height` — run on each
/// new challenge so the table cannot grow without bound under request spam.
pub fn purge_expired_challenges(conn: &Connection, current_height: u32) -> Result<(), StateError> {
    conn.execute(
        "DELETE FROM pending_challenges WHERE expires_height < ?1",
        params![current_height],
    )?;
    Ok(())
}

/// Whether the intake note `(txid, output_index)` has already been settled.
pub fn is_processed(
    conn: &Connection,
    txid: &[u8; 32],
    output_index: u32,
) -> Result<bool, StateError> {
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
    block_height: u32,
    block_hash: &[u8; 32],
) -> Result<(), StateError> {
    conn.execute(
        "INSERT OR IGNORE INTO processed_notes (txid, output_index, block_height, block_hash)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            txid.as_slice(),
            output_index,
            block_height,
            block_hash.as_slice(),
        ],
    )?;
    Ok(())
}

/// The highest block height for which we have any settled note with a known
/// block hash. `None` means there are no tracked processed notes yet.
pub fn last_processed_height(conn: &Connection) -> Result<Option<u32>, StateError> {
    let height: Option<i64> = conn
        .query_row(
            "SELECT MAX(block_height) FROM processed_notes
             WHERE block_hash != x'0000000000000000000000000000000000000000000000000000000000000000'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(height.map(|h| h as u32))
}

/// The block hash recorded for settled notes at `height`.
pub fn processed_hash_at_height(
    conn: &Connection,
    height: u32,
) -> Result<Option<[u8; 32]>, StateError> {
    let hash: Option<Vec<u8>> = conn
        .query_row(
            "SELECT block_hash FROM processed_notes WHERE block_height = ?1 LIMIT 1",
            params![height],
            |row| row.get(0),
        )
        .optional()?;
    match hash {
        None => Ok(None),
        Some(bytes) => bytes_to_array32(&bytes)
            .map(Some)
            .map_err(|e| StateError::CorruptRow {
                table: "processed_notes",
                field: "block_hash",
                detail: e,
            }),
    }
}

/// Delete every settled note at or above `height` — used after detecting a
/// reorg at `height`.
pub fn delete_processed_above(conn: &Connection, height: u32) -> Result<(), StateError> {
    conn.execute(
        "DELETE FROM processed_notes WHERE block_height >= ?1",
        params![height],
    )?;
    Ok(())
}

/// Retrieve a name record, returning `None` if the name is not registered.
pub fn get_record(conn: &Connection, name: &str) -> Result<Option<NameRecord>, StateError> {
    let row = conn
        .query_row(
            "SELECT name, rcm, ua, height FROM names WHERE name = ?1",
            params![name],
            |row| {
                let rcm_bytes: Vec<u8> = row.get(1)?;
                Ok((
                    row.get::<_, String>(0)?,
                    rcm_bytes,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                ))
            },
        )
        .optional()?;

    match row {
        None => Ok(None),
        Some((name, rcm_bytes, ua, height)) => {
            let tip_rcm = bytes_to_array32(&rcm_bytes).map_err(|e| StateError::CorruptRow {
                table: "names",
                field: "rcm",
                detail: e,
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

/// Insert or replace the live tip row in `names` from a full `MintedAction`
/// (the latest event for the name). Used on successful non-RELEASE mint and
/// during reorg reconstruction.
pub fn upsert_record_from_action(
    conn: &Connection,
    a: &crate::MintedAction,
) -> Result<(), StateError> {
    conn.execute(
        "INSERT INTO names (name, height, action, ua, prev_rcm, rcm, psi, cmx, txid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(name) DO UPDATE SET
             height   = excluded.height,
             action   = excluded.action,
             ua       = excluded.ua,
             prev_rcm = excluded.prev_rcm,
             rcm      = excluded.rcm,
             psi      = excluded.psi,
             cmx      = excluded.cmx,
             txid     = excluded.txid",
        params![
            a.name,
            a.height,
            std::str::from_utf8(a.action.as_bytes()).expect("ascii"),
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

/// Legacy 4-arg upsert kept only for a few internal tests during transition.
/// Prefer `upsert_record_from_action`.
pub fn upsert_record(
    conn: &Connection,
    name: &str,
    tip_rcm: &[u8; 32],
    ua: &str,
    height: u32,
) -> Result<(), StateError> {
    // Synthesize a minimal action row for the live table. prev_rcm/psi/cmx/txid
    // are not observable via the NameRecord projection, so zeros are fine for
    // tests that only care about get_record roundtrips of (rcm,ua,height).
    let dummy = crate::MintedAction {
        name: name.to_owned(),
        action: zns_core::Action::Claim, // placeholder; not exposed in NameRecord
        ua: ua.to_owned(),
        txid: [0u8; 32],
        cmx: [0u8; 32],
        rcm: *tip_rcm,
        psi: [0u8; 32],
        prev_rcm: [0u8; 32],
        height,
    };
    upsert_record_from_action(conn, &dummy)
}

/// Delete a name record (called after a successful RELEASE mint, or when a
/// reorg leaves a RELEASE as the new tip).
pub fn delete_record(conn: &Connection, name: &str) -> Result<(), StateError> {
    conn.execute("DELETE FROM names WHERE name = ?1", params![name])?;
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
        // Use the crate-level schema init so both the registry tables and the
        // action log exist.
        crate::init_schema(&conn).unwrap();
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

    #[test]
    fn processed_notes_track_height_and_hash() {
        let conn = open();
        let txid = [1u8; 32];
        let hash10 = [10u8; 32];
        let hash20 = [20u8; 32];

        mark_processed(&conn, &txid, 0, 10, &hash10).unwrap();
        assert_eq!(last_processed_height(&conn).unwrap(), Some(10));
        assert_eq!(processed_hash_at_height(&conn, 10).unwrap(), Some(hash10));

        mark_processed(&conn, &txid, 1, 20, &hash20).unwrap();
        assert_eq!(last_processed_height(&conn).unwrap(), Some(20));
        assert_eq!(processed_hash_at_height(&conn, 20).unwrap(), Some(hash20));
    }

    #[test]
    fn delete_processed_above_reorg_height() {
        let conn = open();
        let h10 = [10u8; 32];
        let h20 = [20u8; 32];
        mark_processed(&conn, &[1u8; 32], 0, 10, &h10).unwrap();
        mark_processed(&conn, &[2u8; 32], 0, 20, &h20).unwrap();

        delete_processed_above(&conn, 15).unwrap();
        assert!(is_processed(&conn, &[1u8; 32], 0).unwrap());
        assert!(!is_processed(&conn, &[2u8; 32], 0).unwrap());
        assert_eq!(last_processed_height(&conn).unwrap(), Some(10));
    }

    #[test]
    fn rebuild_records_after_reorg_rolls_tip_back() {
        let conn = open();
        let claim_rcm = [0x11u8; 32];
        let update_rcm = [0x22u8; 32];

        // Simulate claim at height 10, update at height 20.
        crate::actions::append_action(
            &conn,
            &crate::MintedAction {
                name: "alice".into(),
                action: zns_core::Action::Claim,
                ua: "u1old".into(),
                txid: [1u8; 32],
                cmx: [0u8; 32],
                rcm: claim_rcm,
                psi: [0u8; 32],
                prev_rcm: [0u8; 32],
                height: 10,
            },
        )
        .unwrap();
        upsert_record(&conn, "alice", &claim_rcm, "u1old", 10).unwrap();

        crate::actions::append_action(
            &conn,
            &crate::MintedAction {
                name: "alice".into(),
                action: zns_core::Action::Update,
                ua: "u1new".into(),
                txid: [2u8; 32],
                cmx: [0u8; 32],
                rcm: update_rcm,
                psi: [0u8; 32],
                prev_rcm: claim_rcm, // the claim's rcm is prev for the update
                height: 20,
            },
        )
        .unwrap();
        upsert_record(&conn, "alice", &update_rcm, "u1new", 20).unwrap();

        // Reorg at height 20 removes the update.
        let tx = conn.unchecked_transaction().unwrap();
        crate::actions::delete_actions_above(&tx, 20).unwrap();
        rebuild_records_after_reorg(&tx, &["alice".into()]).unwrap();
        tx.commit().unwrap();

        let rec = get_record(&conn, "alice").unwrap().unwrap();
        assert_eq!(rec.tip_rcm, claim_rcm);
        assert_eq!(rec.height, 10);
        // The action log now stores the UA, so reorg reconstruction is exact:
        // the record reverts to the binding carried by the remaining claim.
        assert_eq!(rec.ua, "u1old");
    }

    #[test]
    fn rebuild_records_after_reorg_deletes_released_name() {
        let conn = open();
        let claim_rcm = [0x11u8; 32];
        let release_rcm = [0x33u8; 32];

        // Simulate claim at height 10, release at height 20.
        crate::actions::append_action(
            &conn,
            &crate::MintedAction {
                name: "alice".into(),
                action: zns_core::Action::Claim,
                ua: "u1old".into(),
                txid: [1u8; 32],
                cmx: [0u8; 32],
                rcm: claim_rcm,
                psi: [0u8; 32],
                prev_rcm: [0u8; 32],
                height: 10,
            },
        )
        .unwrap();
        upsert_record(&conn, "alice", &claim_rcm, "u1old", 10).unwrap();

        crate::actions::append_action(
            &conn,
            &crate::MintedAction {
                name: "alice".into(),
                action: zns_core::Action::Release,
                ua: String::new(),
                txid: [2u8; 32],
                cmx: [0u8; 32],
                rcm: release_rcm,
                psi: [0u8; 32],
                prev_rcm: claim_rcm,
                height: 20,
            },
        )
        .unwrap();
        delete_record(&conn, "alice").unwrap();

        // A reorg whose first orphaned height is *above* the release leaves the
        // release as the latest remaining action. Rebuild must delete the tip
        // record rather than resurrect the name with an empty UA.
        let tx = conn.unchecked_transaction().unwrap();
        crate::actions::delete_actions_above(&tx, 21).unwrap();
        rebuild_records_after_reorg(&tx, &["alice".into()]).unwrap();
        tx.commit().unwrap();

        // The name must be gone, not resurrected with an empty UA.
        assert!(get_record(&conn, "alice").unwrap().is_none());
    }

    #[test]
    fn intent_round_trip() {
        let conn = open();
        let minted = crate::MintedAction {
            name: "alice".into(),
            action: zns_core::Action::Claim,
            ua: "u1xxx".into(),
            txid: [1u8; 32],
            cmx: [2u8; 32],
            rcm: [3u8; 32],
            psi: [4u8; 32],
            prev_rcm: [0u8; 32],
            height: 100,
        };
        let intent = PendingMint {
            minted: minted.clone(),
            expiry_height: 140,
            request: ([5u8; 32], 7),
        };
        put_intent(&conn, &intent).unwrap();

        let loaded = get_intent(&conn, "alice").unwrap().unwrap();
        assert_eq!(loaded.minted, minted);
        assert_eq!(loaded.expiry_height, 140);
        assert_eq!(loaded.request, ([5u8; 32], 7));

        let list = list_intents(&conn).unwrap();
        assert_eq!(list.len(), 1);

        delete_intent(&conn, "alice").unwrap();
        assert!(get_intent(&conn, "alice").unwrap().is_none());
    }

    #[test]
    fn delete_intents_above_reorg_height() {
        let conn = open();
        let intent = |name: &str, height: u32| PendingMint {
            minted: crate::MintedAction {
                name: name.into(),
                action: zns_core::Action::Claim,
                ua: "u1x".into(),
                txid: [height as u8; 32],
                cmx: [0u8; 32],
                rcm: [0u8; 32],
                psi: [0u8; 32],
                prev_rcm: [0u8; 32],
                height,
            },
            expiry_height: height + 40,
            request: ([0u8; 32], 0),
        };
        put_intent(&conn, &intent("alice", 100)).unwrap();
        put_intent(&conn, &intent("bob", 200)).unwrap();

        delete_intents_above(&conn, 200).unwrap();
        assert!(get_intent(&conn, "bob").unwrap().is_none());
        assert!(get_intent(&conn, "alice").unwrap().is_some());
    }

    #[test]
    fn challenge_round_trip_and_purge() {
        let conn = open();
        let c = zns_auth::PendingChallenge {
            name: "alice".into(),
            action: zns_core::Action::Update,
            ua_new: "u1new".into(),
            nonce: "deadbeef".into(),
            expires_height: 200,
        };
        put_challenge(&conn, &c).unwrap();

        let loaded = get_challenge(&conn, "alice").unwrap().unwrap();
        assert_eq!(loaded, c);

        // At the exact expiry height the challenge is still valid; purge is
        // conservative and only drops strictly expired rows.
        purge_expired_challenges(&conn, 200).unwrap();
        assert!(get_challenge(&conn, "alice").unwrap().is_some());

        purge_expired_challenges(&conn, 201).unwrap();
        assert!(get_challenge(&conn, "alice").unwrap().is_none());
    }

    #[test]
    fn processed_notes_are_idempotent() {
        let conn = open();
        let txid = [1u8; 32];
        let hash = [10u8; 32];
        mark_processed(&conn, &txid, 0, 100, &hash).unwrap();
        mark_processed(&conn, &txid, 0, 100, &hash).unwrap(); // idempotent
        assert!(is_processed(&conn, &txid, 0).unwrap());
        assert_eq!(last_processed_height(&conn).unwrap(), Some(100));
    }

    #[test]
    fn claim_challenge_is_rejected() {
        let conn = open();
        let c = zns_auth::PendingChallenge {
            name: "alice".into(),
            action: zns_core::Action::Claim,
            ua_new: "u1new".into(),
            nonce: "nope".into(),
            expires_height: 100,
        };
        assert!(matches!(
            put_challenge(&conn, &c),
            Err(StateError::Invariant(_))
        ));
    }
}
