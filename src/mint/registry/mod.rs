//! The name-chain state machine and transition authorization.

mod anchor_pool;

pub use anchor_pool::{AnchorPool, ANCHOR_POOL_SIZE};

use crate::mint::otp::OtpQueue;
use crate::mint::{Action, Expiry, Name, NameCommitment, NameNote, Request, UnifiedAddress};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use time::Timestamp;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::consensus::Parameters;

// ---------------------------------------------------------------------------
// NameRecord — the current state of a name chain
// ---------------------------------------------------------------------------

/// The current state of one name's chain.
#[derive(Clone, PartialEq, Eq)]
pub struct NameRecord {
    pub action: Action,
    pub ua: UnifiedAddress,
    pub expires_at: Expiry,
    pub commitment: NameCommitment,
    pub confirmed_height: BlockHeight,
    pub release_deadline: Timestamp,
    pub nullifier: orchard::note::Nullifier,
}

impl NameRecord {
    fn from_received<P: Parameters>(
        params: &P,
        note: &NameNote,
        nullifier: orchard::note::Nullifier,
        confirmed_height: BlockHeight,
        mtp: Timestamp,
    ) -> Self {
        let rcm = note.rcm(params);
        Self {
            action: note.action(),
            ua: note.ua().clone(),
            expires_at: note.expires_at().unwrap_or(Expiry::Never),
            commitment: NameCommitment::from_inner(orchard::note::NoteCommitTrapdoor::from_inner(
                rcm,
            )),
            confirmed_height,
            release_deadline: Timestamp::from_seconds(
                mtp.as_seconds() + crate::mint::LIVENESS_INTERVAL,
            )
            .expect("liveness deadline fits Timestamp"),
            nullifier,
        }
    }
}

impl std::fmt::Debug for NameRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameRecord")
            .field("action", &self.action)
            .field("ua", &self.ua)
            .field("commitment", &self.commitment)
            .field("confirmed_height", &self.confirmed_height)
            .field("nullifier", &self.nullifier)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Registry — name-chain state with reorg undo
// ---------------------------------------------------------------------------

/// An undo-log entry: the record before a set_record.
#[derive(Debug, Clone)]
pub struct RegistryHistoryRecord {
    pub height: BlockHeight,
    pub name: Name,
    pub prev_record: Option<NameRecord>,
}

/// Name records, a reorg undo log, and the anchor lineage pool.
#[derive(Default)]
pub struct Registry {
    records: BTreeMap<Name, NameRecord>,
    history: Vec<RegistryHistoryRecord>,
    anchors: AnchorPool,
}

impl Registry {
    /// Empty state; boot sync adopts the ceremony's anchor pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// The transition law: the NameNote a lawful request produces.
    /// `None` means unlawful; a claim's payment is kept.
    pub fn authorize(
        &self,
        challenges: &mut OtpQueue,
        request: Request,
        otp: Option<&[u8; 6]>,
        payment_height: BlockHeight,
        mtp: Timestamp,
    ) -> Option<NameNote> {
        match request {
            Request::Claim {
                name,
                ua,
                term,
                code: _,
            } => {
                match self.record(&name).cloned() {
                    None => {}
                    Some(record) if record.action.is_release() => {
                        if payment_height <= record.confirmed_height {
                            return None;
                        }
                    }
                    Some(_) => return None, // live
                }
                let expires_at = term.claim_expiry(mtp)?;
                Some(NameNote::Claim {
                    name,
                    ua,
                    expires_at,
                })
            }
            Request::Update { name, ua, term } => {
                let record = self.record(&name).cloned()?;
                if record.action.is_release() {
                    return None;
                }
                if record.expires_at.expired(mtp) {
                    return None;
                }
                let otp = otp?;
                if !challenges.accept(&name, Action::Update, &ua, record.commitment, otp, mtp) {
                    return None;
                }
                let expires_at = record.expires_at.extend(term, mtp)?;
                Some(NameNote::Update {
                    name,
                    ua,
                    expires_at,
                    prev: record.commitment,
                })
            }
            Request::Release { name, ua } => {
                let record = self.record(&name).cloned()?;
                if record.action.is_release() {
                    return None;
                }
                if record.ua != ua {
                    return None;
                }
                let otp = otp?;
                if !challenges.accept(&name, Action::Release, &ua, record.commitment, otp, mtp) {
                    return None;
                }
                Some(NameNote::Release {
                    name,
                    ua,
                    prev: record.commitment,
                })
            }
        }
    }

    /// The current record of a name.
    pub fn record(&self, name: &Name) -> Option<&NameRecord> {
        self.records.get(name)
    }

    /// The §4.5 clocks, swept: every live name whose purchased term or
    /// liveness deadline has passed at `mtp`, with the release note it
    /// is owed. Idempotent per tip.
    pub fn releases_due(&self, mtp: Timestamp) -> impl Iterator<Item = (Name, NameNote)> + '_ {
        self.records
            .iter()
            .filter(move |(_, record)| {
                !record.action.is_release()
                    && (record.expires_at.expired(mtp) || mtp >= record.release_deadline)
            })
            .map(move |(name, record)| {
                (
                    name.clone(),
                    NameNote::Release {
                        name: name.clone(),
                        ua: record.ua.clone(),
                        prev: record.commitment,
                    },
                )
            })
    }

    /// Ceremony filling: a zero-value Registry output joins the
    /// lineage pool below standing size.
    pub fn adopt_anchor(&mut self, height: BlockHeight, nf: orchard::note::Nullifier) {
        self.anchors.adopt(height, nf);
    }

    /// Offers a confirmed claim candidate; true when its transaction
    /// spent a standing anchor and the name was free (or released).
    /// A duplicate — the mint's restart and reorg worlds — still
    /// advances the pool; first confirmed wins, the live registration
    /// stands.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_claim<P: Parameters>(
        &mut self,
        params: &P,
        note: &NameNote,
        nullifier: orchard::note::Nullifier,
        successor: Option<orchard::note::Nullifier>,
        nfs: &[orchard::note::Nullifier],
        height: BlockHeight,
        mtp: Timestamp,
    ) -> bool {
        assert!(matches!(note, NameNote::Claim { .. }));
        let spent: Vec<_> = nfs
            .iter()
            .filter(|nf| self.anchors.contains(*nf))
            .copied()
            .collect();
        if spent.is_empty() {
            return false; // unbacked: a public output anyone could have written
        }
        assert!(
            self.names_spent_by(nfs).is_empty(),
            "claim transaction spent a record — assembly never \
             spends a Name Note when claiming"
        );
        assert!(
            spent.len() == 1,
            "a claim spends exactly one anchor — assembly never batches"
        );
        let successor_nf = successor.expect(
            "a backed claim creates exactly one zero-value successor anchor — \
             the Registry FVK derives its nullifier",
        );
        // Pool follows the chain either way: a duplicate claim still
        // spent a standing anchor and created a successor.
        let applied = self.anchors.apply_claim(height, spent[0], successor_nf);
        debug_assert!(applied, "spent nullifier was live per contains() above");
        if self
            .record(note.name())
            .is_some_and(|r| !r.action.is_release())
        {
            // A late or duplicate claim: first confirmed wins.
            return false;
        }
        self.set_record(
            note.name().clone(),
            NameRecord::from_received(params, note, nullifier, height, mtp),
            height,
        );
        true
    }

    /// Offers a confirmed update candidate; true when the transaction
    /// spent this name's current note.
    pub fn accept_update<P: Parameters>(
        &mut self,
        params: &P,
        note: &NameNote,
        nullifier: orchard::note::Nullifier,
        nfs: &[orchard::note::Nullifier],
        height: BlockHeight,
        mtp: Timestamp,
    ) -> bool {
        assert!(matches!(note, NameNote::Update { .. }));
        let Some(record) = self.predecessor_spent(note, nfs) else {
            return false;
        };
        assert!(
            note.prev_rcm() == Some(record.commitment),
            "predecessor mismatch — assembly reads commitment from the same registry"
        );
        self.set_record(
            note.name().clone(),
            NameRecord::from_received(params, note, nullifier, height, mtp),
            height,
        );
        true
    }

    /// Offers a confirmed release candidate; same law as accept_update.
    pub fn accept_release<P: Parameters>(
        &mut self,
        params: &P,
        note: &NameNote,
        nullifier: orchard::note::Nullifier,
        nfs: &[orchard::note::Nullifier],
        height: BlockHeight,
        mtp: Timestamp,
    ) -> bool {
        assert!(matches!(note, NameNote::Release { .. }));
        let Some(record) = self.predecessor_spent(note, nfs) else {
            return false;
        };
        assert!(
            note.prev_rcm() == Some(record.commitment),
            "predecessor mismatch — assembly reads commitment from the same registry"
        );
        self.set_record(
            note.name().clone(),
            NameRecord::from_received(params, note, nullifier, height, mtp),
            height,
        );
        true
    }

    /// The live predecessor this transaction spent, when it is this
    /// note's own current note.
    fn predecessor_spent(
        &self,
        note: &NameNote,
        nfs: &[orchard::note::Nullifier],
    ) -> Option<&NameRecord> {
        let spent = self.names_spent_by(nfs);
        if spent.is_empty() {
            return None; // unbacked: a public output anyone could have written
        }
        assert!(
            !nfs.iter().any(|nf| self.anchors.contains(nf)),
            "update/release must not advance the claim-anchor chain"
        );
        assert_eq!(
            spent.as_slice(),
            [note.name().clone()],
            "update/release did not spend the exact current Name Note \
             — assembly spends the exact current note"
        );
        Some(
            self.record(note.name())
                .filter(|record| !record.action.is_release())
                .expect(
                    "update/release has no live predecessor \
                     — assembly checks liveness before transitioning",
                ),
        )
    }

    /// The names whose current notes these nullifiers spend.
    pub fn names_spent_by(&self, nfs: &[orchard::note::Nullifier]) -> Vec<Name> {
        self.records
            .iter()
            .filter(|(_, record)| nfs.contains(&record.nullifier))
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn set_record(&mut self, name: Name, record: NameRecord, height: BlockHeight) {
        let prev_record = self.records.insert(name.clone(), record);
        self.history.push(RegistryHistoryRecord {
            height,
            name,
            prev_record,
        });
    }

    /// Every known name record; diagnostics only.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &NameRecord)> {
        self.records.iter()
    }

    /// The anchor lineage pool — the only source of claim authority.
    pub fn anchor_pool(&self) -> &BTreeSet<orchard::note::Nullifier> {
        self.anchors.live()
    }

    /// Rewinds the registry to height. Callers pass walk-found heights
    /// at or above the boot origin.
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        while let Some(entry) = self.history.last() {
            if entry.height <= height {
                break;
            }
            let entry = self.history.pop().unwrap();
            match entry.prev_record {
                Some(old_record) => {
                    self.records.insert(entry.name, old_record);
                }
                None => {
                    self.records.remove(&entry.name);
                }
            }
        }
        self.anchors.truncate_to(height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::NameNote;
    use zcash_protocol::consensus::MAIN_NETWORK;

    /// A valid mainnet ZIP-316 UA with an Orchard receiver (test vector
    /// shared with the note and treasury tests).
    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    fn test_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(&MAIN_NETWORK, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    fn test_name() -> Name {
        Name::parse("alice").unwrap()
    }

    /// Any [u8; 32] whose top two bits are zero is a valid Pallas base
    /// element; putting the seed in the low byte keeps the number small.
    fn commitment(seed: u8) -> NameCommitment {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        NameCommitment::from_bytes(&bytes).unwrap()
    }

    fn nullifier(seed: u8) -> orchard::note::Nullifier {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        orchard::note::Nullifier::from_bytes(&bytes)
            .into_option()
            .expect("test nullifier fits Pallas base")
    }

    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_seconds(secs).unwrap()
    }

    fn record(action: Action, expires_at: Expiry, release_deadline: i64, seed: u8) -> NameRecord {
        NameRecord {
            action,
            ua: test_ua(),
            expires_at,
            commitment: commitment(seed),
            confirmed_height: BlockHeight::from_u32(100),
            release_deadline: ts(release_deadline),
            nullifier: nullifier(seed),
        }
    }

    /// The plural sweep: only names whose clocks have fired, each paired
    /// with its release note. Live and already-released names are absent.
    #[test]
    fn releases_due_yields_only_fired_names() {
        let mut r = Registry::new();
        for (name, action, expires_at, deadline, seed) in [
            (
                "alpha",
                Action::Claim,
                Expiry::At(ts(1_500_000_000)),
                3_000_000_000_i64,
                1_u8,
            ),
            (
                "bravo",
                Action::Claim,
                Expiry::Never,
                1_500_000_000_i64,
                2_u8,
            ),
            (
                "delta",
                Action::Claim,
                Expiry::Never,
                3_000_000_000_i64,
                3_u8,
            ),
            (
                "gamma",
                Action::Release,
                Expiry::Never,
                1_000_000_000_i64,
                4_u8,
            ),
        ] {
            r.set_record(
                Name::parse(name).expect("test name parses"),
                record(action, expires_at, deadline, seed),
                BlockHeight::from_u32(100),
            );
        }
        // alpha: purchased term up (§4.5.2). bravo: liveness deadline
        // passed (§4.5.4). delta: live. gamma: already released.
        // BTreeMap order makes the batch deterministic: alpha, bravo.
        let due: Vec<(String, NameNote)> = r
            .releases_due(ts(1_500_000_000))
            .map(|(name, note)| (name.as_str().to_owned(), note))
            .collect();
        assert_eq!(
            due.iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "bravo"]
        );
        // Each yielded note is the release bound to its own record.
        assert!(matches!(due[0].1, NameNote::Release { .. }));
        assert_eq!(due[0].1.prev_rcm(), Some(commitment(1)));
        assert_eq!(due[1].1.prev_rcm(), Some(commitment(2)));
    }

    /// A claim sets `release_deadline = τ + L`. An update at a later block
    /// resets it to that block's MTP plus L (the σ+L check across §4.5.4).
    #[test]
    fn record_from_received_sets_deadline_from_mtp_and_liveness_interval() {
        let name = test_name();
        let ua = test_ua();
        let l = crate::mint::LIVENESS_INTERVAL;

        // Claim block MTP.
        let tau_claim = 1_700_000_000_i64;
        let claim = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::Never,
        };
        let rec = NameRecord::from_received(
            &MAIN_NETWORK,
            &claim,
            nullifier(1),
            BlockHeight::from_u32(100),
            ts(tau_claim),
        );
        assert_eq!(rec.release_deadline.as_seconds(), tau_claim + l);

        // Update at a later block: deadline resets.
        let tau_update = 1_710_000_000_i64;
        let update = NameNote::Update {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::Never,
            prev: commitment(3),
        };
        let rec2 = NameRecord::from_received(
            &MAIN_NETWORK,
            &update,
            nullifier(2),
            BlockHeight::from_u32(200),
            ts(tau_update),
        );
        assert_eq!(rec2.release_deadline.as_seconds(), tau_update + l);
    }

    /// Two backed claims for the same name confirm in order: the first
    /// registers, the second advances the pool and is ignored — no
    /// panic, first registration kept (#116).
    #[test]
    fn accept_claim_keeps_first_when_a_second_confirms() {
        let mut r = Registry::new();
        let h1 = BlockHeight::from_u32(10);
        let h2 = BlockHeight::from_u32(11);
        let mtp = ts(1_700_000_000);
        let a1 = nullifier(1);
        let a2 = nullifier(2);
        let succ1 = nullifier(10);
        let succ2 = nullifier(11);
        r.adopt_anchor(h1, a1);
        r.adopt_anchor(h1, a2);

        let claim = NameNote::Claim {
            name: test_name(),
            ua: test_ua(),
            expires_at: Expiry::Never,
        };

        assert!(r.accept_claim(
            &MAIN_NETWORK,
            &claim,
            nullifier(20),
            Some(succ1),
            &[a1],
            h1,
            mtp
        ));
        let first = r.record(&test_name()).expect("alice registered").clone();

        assert!(!r.accept_claim(
            &MAIN_NETWORK,
            &claim,
            nullifier(21),
            Some(succ2),
            &[a2],
            h2,
            mtp
        ));
        let kept = r.record(&test_name()).expect("alice still registered");
        assert_eq!(kept.commitment, first.commitment);
        assert_eq!(kept.nullifier, first.nullifier);
        assert_eq!(kept.confirmed_height, first.confirmed_height);

        // The pool followed the chain through both: one anchor out, one
        // successor in, each time.
        assert!(!r.anchor_pool().contains(&a1));
        assert!(!r.anchor_pool().contains(&a2));
        assert!(r.anchor_pool().contains(&succ1));
        assert!(r.anchor_pool().contains(&succ2));
    }
}
