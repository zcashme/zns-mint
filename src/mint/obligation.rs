//! Payments the mint still owes a name transition for.
//!
//! The wallet is rebuilt from the chain. A Treasury memo is an instruction
//! only while it sits in a queue, so a restart used to drop it and keep the
//! money. This store is the instruction that survives the process.

use std::path::Path;

use rusqlite::{params, Connection};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use super::note::NameNoteQueue;
use super::treasury::{OtpChallenge, OtpCode, OtpQueue, RequestQueue};
use super::{Action, MintInbound, NameCommitment, NameNote, OtpMemo};
use crate::mint::registry::Registry;

/// The file next to the process working directory.
pub const PATH: &str = "obligations.db";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS obligations (
    txid BLOB NOT NULL,
    action_index INTEGER NOT NULL,
    memo BLOB NOT NULL,
    paid INTEGER NOT NULL,
    height INTEGER,
    status TEXT NOT NULL,
    enactment_txid BLOB,
    authorized BLOB,
    otp_code INTEGER,
    otp_expires INTEGER,
    tip_rcm BLOB,
    relayed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (txid, action_index)
);";

/// One sqlite file of open Treasury payments.
pub struct ObligationStore {
    conn: Connection,
}

impl ObligationStore {
    /// Opens or creates the store. A version other than 1 cannot be read.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 0 {
            conn.execute_batch(SCHEMA)?;
            conn.pragma_update(None, "user_version", 1i64)?;
        } else if version != 1 {
            panic!("FATAL: obligation store version {version} is not readable");
        }
        Ok(Self { conn })
    }

    pub fn open_default() -> rusqlite::Result<Self> {
        Self::open(Path::new(PATH))
    }

    /// Records a Treasury memo. A later confirmation fills in a height the
    /// mempool sighting did not have. A row already stored keeps its code.
    pub fn observe(
        &self,
        txid: TxId,
        action_index: u32,
        memo: &MemoBytes,
        paid: Zatoshis,
        height: Option<BlockHeight>,
    ) -> rusqlite::Result<()> {
        let txid = txid_bytes(&txid);
        let paid = i64::try_from(paid.into_u64()).expect("payment fits i64");
        let height = height.map(|height| i64::from(u32::from(height)));
        self.conn.execute(
            "INSERT OR IGNORE INTO obligations
                (txid, action_index, memo, paid, height, status, relayed)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open', 0)",
            params![
                txid.as_slice(),
                action_index,
                memo.as_array().as_slice(),
                paid,
                height,
            ],
        )?;
        if let Some(height) = height {
            self.conn.execute(
                "UPDATE obligations SET height = ?1
                 WHERE txid = ?2 AND action_index = ?3 AND height IS NULL",
                params![height, txid.as_slice(), action_index],
            )?;
        }
        Ok(())
    }

    /// Stores the challenge code once. A second call leaves the first code.
    pub fn remember_otp(
        &self,
        txid: TxId,
        action_index: u32,
        challenge: &OtpChallenge,
    ) -> rusqlite::Result<()> {
        let txid = txid_bytes(&txid);
        self.conn.execute(
            "UPDATE obligations
             SET otp_code = ?1, otp_expires = ?2, tip_rcm = ?3
             WHERE txid = ?4 AND action_index = ?5 AND otp_code IS NULL",
            params![
                challenge.code.raw(),
                challenge.expires_at.as_seconds(),
                challenge.tip_rcm.to_bytes().as_slice(),
                txid.as_slice(),
                action_index,
            ],
        )?;
        Ok(())
    }

    pub fn mark_relayed(&self, txid: TxId) -> rusqlite::Result<()> {
        let txid = txid_bytes(&txid);
        self.conn.execute(
            "UPDATE obligations SET relayed = 1
             WHERE txid = ?1 AND otp_code IS NOT NULL",
            params![txid.as_slice()],
        )?;
        Ok(())
    }

    /// The mempool dropped a payment whose challenge was not sent.
    pub fn drop_unrelayed(&self, txid: TxId) -> rusqlite::Result<()> {
        let txid = txid_bytes(&txid);
        self.conn.execute(
            "DELETE FROM obligations
             WHERE txid = ?1 AND height IS NULL AND relayed = 0",
            params![txid.as_slice()],
        )?;
        Ok(())
    }

    /// The name note this payment will broadcast. Kept so a restart
    /// resubmits the same transition.
    pub fn authorize<P: Parameters>(
        &self,
        txid: TxId,
        action_index: u32,
        network: &P,
        note: &NameNote,
    ) -> rusqlite::Result<()> {
        let txid = txid_bytes(&txid);
        let authorized = note.encode(network);
        self.conn.execute(
            "UPDATE obligations SET authorized = ?1
             WHERE txid = ?2 AND action_index = ?3 AND status = 'open'",
            params![authorized.as_slice(), txid.as_slice(), action_index],
        )?;
        Ok(())
    }

    /// The broadcast name-note transaction, matched by the authorized memo.
    pub fn enact<P: Parameters>(
        &self,
        network: &P,
        note: &NameNote,
        enactment: TxId,
    ) -> rusqlite::Result<()> {
        let authorized = note.encode(network);
        let enactment = txid_bytes(&enactment);
        self.conn.execute(
            "UPDATE obligations SET enactment_txid = ?1
             WHERE authorized = ?2 AND status = 'open'",
            params![enactment.as_slice(), authorized.as_slice()],
        )?;
        Ok(())
    }

    /// The law refused this payment. It is not retried.
    pub fn close(&self, txid: TxId, action_index: u32) -> rusqlite::Result<()> {
        let txid = txid_bytes(&txid);
        self.conn.execute(
            "UPDATE obligations SET status = 'closed'
             WHERE txid = ?1 AND action_index = ?2 AND status = 'open'",
            params![txid.as_slice(), action_index],
        )?;
        Ok(())
    }

    /// A challenge whose term ended before a name note was authorized.
    pub fn expire(&self, mtp_seconds: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE obligations SET status = 'closed'
             WHERE status = 'open' AND authorized IS NULL
               AND otp_expires IS NOT NULL AND otp_expires <= ?1",
            params![mtp_seconds],
        )?;
        Ok(())
    }

    /// Drops payments whose confirming block was orphaned.
    pub fn truncate_above(&self, ancestor: BlockHeight) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM obligations WHERE height IS NOT NULL AND height > ?1",
            params![i64::from(u32::from(ancestor))],
        )?;
        Ok(())
    }

    /// A stored name note that the registry now contains is confirmed.
    /// One the registry no longer contains is open again.
    pub fn reconcile<P: Parameters>(
        &self,
        network: &P,
        registry: &Registry,
    ) -> rusqlite::Result<()> {
        let mut stmt = self.conn.prepare(
            "SELECT txid, action_index, memo, authorized, height, status FROM obligations
             WHERE status != 'closed'",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        for (txid, action_index, memo, authorized, height, status) in rows {
            let origin = height.unwrap_or(0);
            let on_chain = if let Some(authorized) = authorized {
                let Some(note) = decode_note(network, &authorized) else {
                    continue;
                };
                registry.record_history(note.name()).iter().any(|record| {
                    i64::from(u32::from(record.confirmed_height)) >= origin
                        && record.commitment == note.commitment(network)
                })
            } else if height.is_some() {
                memo_already_settled(network, registry, &memo, origin)
            } else {
                false
            };
            if on_chain && status != "confirmed" {
                self.conn.execute(
                    "UPDATE obligations SET status = 'confirmed'
                     WHERE txid = ?1 AND action_index = ?2",
                    params![txid, action_index],
                )?;
            } else if !on_chain && status == "confirmed" {
                self.conn.execute(
                    "UPDATE obligations
                     SET status = 'open', enactment_txid = NULL
                     WHERE txid = ?1 AND action_index = ?2",
                    params![txid, action_index],
                )?;
            }
        }
        Ok(())
    }

    /// Replaces the run-loop queues with the open rows.
    pub fn reload<P: Parameters>(
        &self,
        network: &P,
        challenges: &mut OtpQueue,
        notes: &mut NameNoteQueue,
        requests: &mut RequestQueue,
        echoes: &mut Vec<(TxId, u32, OtpMemo, Zatoshis, BlockHeight)>,
    ) -> rusqlite::Result<()> {
        *challenges = OtpQueue::new();
        notes.clear();
        requests.clear();
        echoes.clear();

        let mut stmt = self.conn.prepare(
            "SELECT txid, action_index, memo, paid, height, authorized,
                    otp_code, otp_expires, tip_rcm, relayed
             FROM obligations
             WHERE status = 'open'
             ORDER BY height, txid, action_index",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(OpenRow {
                txid: row.get(0)?,
                action_index: row.get(1)?,
                memo: row.get(2)?,
                paid: row.get(3)?,
                height: row.get(4)?,
                authorized: row.get(5)?,
                otp_code: row.get(6)?,
                otp_expires: row.get(7)?,
                tip_rcm: row.get(8)?,
                relayed: row.get(9)?,
            })
        })?;

        let mut open = 0u64;
        let mut awaiting_broadcast = 0u64;
        let mut crowded_out = Vec::new();
        for row in rows {
            let row = row?;
            open += 1;
            let txid = TxId::from_bytes(bytes32(&row.txid).expect("stored txid is 32 bytes"));
            let action_index = u32::try_from(row.action_index).expect("action index fits u32");
            let paid = Zatoshis::from_u64(u64::try_from(row.paid).expect("paid fits u64"))
                .expect("stored payment is a zatoshis value");
            let memo =
                MemoBytes::from_bytes(&bytes512(&row.memo).expect("stored memo is 512 bytes"))
                    .expect("stored memo bytes");
            let inbound = MintInbound::decode(network, &memo);

            if let Some(authorized) = &row.authorized {
                awaiting_broadcast += 1;
                let note = decode_note(network, authorized)
                    .expect("FATAL: stored name note does not decode");
                let origin = BlockHeight::from_u32(
                    u32::try_from(row.height.unwrap_or(0)).expect("height fits u32"),
                );
                notes.admit(origin, note);
            } else if let Some(height) = row.height {
                let height = BlockHeight::from_u32(u32::try_from(height).expect("height fits u32"));
                match inbound.clone() {
                    MintInbound::Request(request) => {
                        if !requests.record(txid, request, paid, height, action_index) {
                            crowded_out.push((txid, action_index));
                        }
                    }
                    MintInbound::Echo(echo) => {
                        echoes.push((txid, action_index, echo, paid, height));
                    }
                    MintInbound::Unrecognized => {}
                }
            }

            if let (Some(code), Some(expires), Some(tip)) =
                (row.otp_code, row.otp_expires, row.tip_rcm.as_ref())
            {
                if let Some(challenge) = challenge_from(&inbound, code, expires, tip) {
                    let admitted = challenges.admit(challenge, txid);
                    if row.relayed != 0 {
                        challenges.challenge_issued(&admitted);
                    }
                }
            }
        }
        drop(stmt);
        for (txid, action_index) in crowded_out {
            self.close(txid, action_index)?;
        }
        let broadcast: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM obligations
             WHERE status = 'open' AND enactment_txid IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        if open > 0 {
            tracing::warn!(
                open,
                awaiting_broadcast,
                broadcast,
                "unfulfilled payments restored"
            );
        }
        Ok(())
    }
}

struct OpenRow {
    txid: Vec<u8>,
    action_index: i64,
    memo: Vec<u8>,
    paid: i64,
    height: Option<i64>,
    authorized: Option<Vec<u8>>,
    otp_code: Option<i64>,
    otp_expires: Option<i64>,
    tip_rcm: Option<Vec<u8>>,
    relayed: i64,
}

fn challenge_from(
    inbound: &MintInbound,
    code: i64,
    expires: i64,
    tip: &[u8],
) -> Option<OtpChallenge> {
    let MintInbound::Request(request) = inbound else {
        return None;
    };
    let (name, action, ua, term) = match request {
        super::Request::Update { name, ua, term } => {
            (name.clone(), Action::Update, ua.clone(), *term)
        }
        super::Request::Release { name, ua } => (name.clone(), Action::Release, ua.clone(), None),
        super::Request::Claim { .. } => return None,
    };
    let code = u32::try_from(code).ok()?;
    let digits = format!("{code:06}");
    let code = OtpCode::from_digits(digits.as_bytes().try_into().ok()?)?;
    let expires_at = time::Timestamp::from_seconds(expires).ok()?;
    let mut tip_bytes = [0u8; 32];
    tip_bytes.copy_from_slice(tip.get(..32)?);
    let tip_rcm = NameCommitment::from_bytes(&tip_bytes)?;
    Some(OtpChallenge {
        name,
        action,
        ua,
        term,
        tip_rcm,
        code,
        expires_at,
    })
}

/// A payment with no stored name note is finished when a matching
/// transition confirmed at or after the payment. That covers history
/// the store did not authorize itself.
fn memo_already_settled<P: Parameters>(
    network: &P,
    registry: &Registry,
    memo: &[u8],
    origin: i64,
) -> bool {
    let Some(memo) = bytes512(memo).and_then(|bytes| MemoBytes::from_bytes(&bytes).ok()) else {
        return false;
    };
    let (name, action) = match MintInbound::decode(network, &memo) {
        MintInbound::Request(super::Request::Claim { name, .. }) => (name, Action::Claim),
        MintInbound::Request(super::Request::Update { name, .. }) => (name, Action::Update),
        MintInbound::Request(super::Request::Release { name, .. }) => (name, Action::Release),
        MintInbound::Echo(echo) => (echo.name, echo.action),
        MintInbound::Unrecognized => return false,
    };
    registry.record_history(&name).iter().any(|record| {
        record.action == action && i64::from(u32::from(record.confirmed_height)) >= origin
    })
}

fn decode_note<P: Parameters>(network: &P, bytes: &[u8]) -> Option<NameNote> {
    let memo = bytes512(bytes)?;
    NameNote::decode(network, &memo)
}

fn txid_bytes(txid: &TxId) -> [u8; 32] {
    let bytes: &[u8] = txid.as_ref();
    bytes.try_into().expect("txid is 32 bytes")
}

fn bytes32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn bytes512(bytes: &[u8]) -> Option<[u8; 512]> {
    bytes.try_into().ok()
}

/// Test scratch path. Not used by boot.
#[cfg(test)]
pub fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zns-obligations-{name}-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn claim_memo() -> MemoBytes {
        let text = format!("ZNS:claim:forever:alice:{TEST_UA}");
        MemoBytes::from_bytes(text.as_bytes()).unwrap()
    }

    fn store(name: &str) -> (ObligationStore, PathBuf) {
        let path = scratch(name);
        let _ = std::fs::remove_file(&path);
        let store = ObligationStore::open(&path).unwrap();
        (store, path)
    }

    #[test]
    fn a_payment_survives_reopen_and_a_later_height() {
        let (store, path) = store("reopen");
        let txid = TxId::from_bytes([7; 32]);
        let memo = claim_memo();
        store
            .observe(txid, 1, &memo, Zatoshis::const_from_u64(50_000), None)
            .unwrap();
        drop(store);

        let store = ObligationStore::open(&path).unwrap();
        store
            .observe(
                txid,
                1,
                &memo,
                Zatoshis::const_from_u64(50_000),
                Some(BlockHeight::from_u32(40)),
            )
            .unwrap();

        let mut requests = RequestQueue::default();
        let mut notes = NameNoteQueue::default();
        let mut challenges = OtpQueue::new();
        let mut echoes = Vec::new();
        store
            .reload(
                &MainNetwork,
                &mut challenges,
                &mut notes,
                &mut requests,
                &mut echoes,
            )
            .unwrap();
        let pending = requests.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, txid);
        assert_eq!(pending[0].3, BlockHeight::from_u32(40));
        assert_eq!(pending[0].4, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_authorized_note_reloads_and_an_orphan_is_dropped() {
        let (store, path) = store("note");
        let txid = TxId::from_bytes([3; 32]);
        let memo = claim_memo();
        let network = MainNetwork;
        store
            .observe(
                txid,
                0,
                &memo,
                Zatoshis::const_from_u64(1),
                Some(BlockHeight::from_u32(10)),
            )
            .unwrap();
        let note = NameNote::Claim {
            name: crate::mint::Name::parse("alice").unwrap(),
            ua: match zcash_keys::address::Address::decode(&network, TEST_UA) {
                Some(zcash_keys::address::Address::Unified(ua)) => ua,
                _ => panic!("vector is a mainnet Unified Address"),
            },
            expires_at: crate::mint::Expiry::Never,
        };
        store.authorize(txid, 0, &network, &note).unwrap();

        let mut requests = RequestQueue::default();
        let mut notes = NameNoteQueue::default();
        let mut challenges = OtpQueue::new();
        let mut echoes = Vec::new();
        store
            .reload(
                &network,
                &mut challenges,
                &mut notes,
                &mut requests,
                &mut echoes,
            )
            .unwrap();
        assert!(requests.pending().is_empty());
        assert_eq!(notes.authorized_notes().len(), 1);

        store.truncate_above(BlockHeight::from_u32(9)).unwrap();
        notes.clear();
        store
            .reload(
                &network,
                &mut challenges,
                &mut notes,
                &mut requests,
                &mut echoes,
            )
            .unwrap();
        assert!(notes.authorized_notes().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_closed_payment_is_not_restored() {
        let (store, path) = store("closed");
        let txid = TxId::from_bytes([4; 32]);
        store
            .observe(
                txid,
                0,
                &claim_memo(),
                Zatoshis::const_from_u64(1),
                Some(BlockHeight::from_u32(3)),
            )
            .unwrap();
        store.close(txid, 0).unwrap();
        let mut requests = RequestQueue::default();
        let mut notes = NameNoteQueue::default();
        let mut challenges = OtpQueue::new();
        let mut echoes = Vec::new();
        store
            .reload(
                &MainNetwork,
                &mut challenges,
                &mut notes,
                &mut requests,
                &mut echoes,
            )
            .unwrap();
        assert!(requests.pending().is_empty());
        let _ = std::fs::remove_file(path);
    }
}
