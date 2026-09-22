//! The name-chain state machine and transition authorization.

mod anchor_pool;

use anchor_pool::AnchorPool;

pub use anchor_pool::ANCHOR_POOL_SIZE;

use crate::mint::otp::OtpQueue;
use crate::mint::{Action, Expiry, Name, NameCommitment, NameNote, Request, Term, UnifiedAddress};
use std::collections::{BTreeMap, BTreeSet};
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
    /// The §4.5 clocks, fired: the term lapsed or the liveness
    /// deadline reached at `mtp`.
    pub fn is_release_due(&self, mtp: Timestamp) -> bool {
        self.expires_at.expired(mtp) || mtp >= self.release_deadline
    }

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

    /// Does this record admit a relay trigger? The five refusals: the
    /// name is released — its last transition was a release; the term
    /// has expired; the trigger is stale, carried at or before the
    /// record's last confirmed transition, so it speaks against
    /// superseded state; a release aimed from another UA; or a term
    /// offered to a forever name, which has no runway to bank and no
    /// second upgrade to buy.
    pub fn admits(
        &self,
        action: Action,
        ua: &UnifiedAddress,
        term: Option<Term>,
        trigger_height: BlockHeight,
        mtp_now: Timestamp,
    ) -> bool {
        !self.action.is_release()
            && !self.expires_at.expired(mtp_now)
            && trigger_height > self.confirmed_height
            && !(action.is_release() && *ua != self.ua)
            && !(self.expires_at == Expiry::Never && term.is_some())
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
                if record.is_release_due(mtp) {
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
            .filter(move |(_, record)| !record.action.is_release() && record.is_release_due(mtp))
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
            .filter(|nf| self.anchors.contains(nf))
            .copied()
            .collect();
        // Facts first: the pool follows every spent standing anchor
        // and adopts the created successor — whatever the rest of the
        // transaction turns out to be. An unbacked claim retires
        // nothing and adopts nothing: both are no-ops.
        self.anchors.retire_spent(nfs, successor, height);

        // The law: a well-formed claim spends exactly one anchor,
        // spends no Name Note, creates a zero-value successor, and
        // finds the name free (or released).
        if successor.is_none() || spent.len() != 1 || !self.names_spent_by(nfs).is_empty() {
            self.mark_released(nfs, height);
            return false;
        }
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
    /// spent this name's current note and both clocks still allow a
    /// renewal at block MTP. A well-formed spend after expiry or
    /// liveness marks the name released and returns false.
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
            // Unbacked, or malformed (an anchor, extra names, an
            // already released record): the pool and the records
            // still follow what the chain spent.
            self.follow_spends(nfs, height);
            return false;
        };
        if note.prev_rcm() != Some(record.commitment) {
            // The predecessor was spent whatever the note claims.
            self.release_predecessor(params, note.name().clone(), &record, nullifier, height, mtp);
            return false;
        }
        let name = note.name().clone();
        if record.is_release_due(mtp) {
            self.release_predecessor(params, name, &record, nullifier, height, mtp);
            return false;
        }
        self.set_record(
            name,
            NameRecord::from_received(params, note, nullifier, height, mtp),
            height,
        );
        true
    }

    /// Offers a confirmed release candidate; true when the transaction
    /// spent this name's current note. Releases stay legal after either clock.
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
            // Malformed: the pool and the records still follow what
            // the chain spent.
            self.follow_spends(nfs, height);
            return false;
        };
        if note.prev_rcm() != Some(record.commitment) {
            // The predecessor was spent whatever the note claims.
            self.release_predecessor(params, note.name().clone(), &record, nullifier, height, mtp);
            return false;
        }
        self.set_record(
            note.name().clone(),
            NameRecord::from_received(params, note, nullifier, height, mtp),
            height,
        );
        true
    }

    /// The name's live note was spent but no renewal lands: the name
    /// is released, bound to the successor nullifier it received.
    fn release_predecessor<P: Parameters>(
        &mut self,
        params: &P,
        name: Name,
        record: &NameRecord,
        nullifier: orchard::note::Nullifier,
        height: BlockHeight,
        mtp: Timestamp,
    ) {
        let release = NameNote::Release {
            name: name.clone(),
            ua: record.ua.clone(),
            prev: record.commitment,
        };
        self.set_record(
            name,
            NameRecord::from_received(params, &release, nullifier, height, mtp),
            height,
        );
    }

    /// The live predecessor this transaction spent, when it is this
    /// note's own current note. Malformed spends (extra names, an
    /// anchor, a released record) return `None`.
    fn predecessor_spent(
        &self,
        note: &NameNote,
        nfs: &[orchard::note::Nullifier],
    ) -> Option<NameRecord> {
        let spent = self.names_spent_by(nfs);
        if spent.is_empty() {
            return None; // unbacked: a public output anyone could have written
        }
        if nfs.iter().any(|nf| self.anchors.contains(nf)) {
            return None;
        }
        if spent.as_slice() != [note.name().clone()] {
            return None;
        }
        self.record(note.name())
            .filter(|record| !record.action.is_release())
            .cloned()
    }

    /// The names whose current notes these nullifiers spend.
    fn names_spent_by(&self, nfs: &[orchard::note::Nullifier]) -> Vec<Name> {
        self.records
            .iter()
            .filter(|(_, record)| nfs.contains(&record.nullifier))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// A Registry spend landed without a single usable Name Note.
    /// The pool follows the spent anchors; spent live names are
    /// marked released.
    pub fn follow_spends(&mut self, nfs: &[orchard::note::Nullifier], height: BlockHeight) {
        self.anchors.retire_spent(nfs, None, height);
        self.mark_released(nfs, height);
    }

    /// Marks every live name released whose current note these
    /// nullifiers spent. A no-op when the spend touched no Name Note.
    fn mark_released(&mut self, nfs: &[orchard::note::Nullifier], height: BlockHeight) {
        for name in self.names_spent_by(nfs) {
            let Some(record) = self.record(&name).cloned() else {
                continue;
            };
            if record.action.is_release() {
                continue;
            }
            let mut tomb = record;
            tomb.action = Action::Release;
            tomb.confirmed_height = height;
            self.set_record(name, tomb, height);
        }
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

    /// A mainnet UA with every known receiver kind (shared with the
    /// note and treasury tests).
    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

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
    fn the_record_admits_its_triggers_and_refuses_the_stale_the_expired_and_the_forever_term() {
        let ua = test_ua();
        let now = ts(1_000_000_000);
        let above = BlockHeight::from_u32(101);
        let live = record(
            Action::Claim,
            Expiry::At(ts(2_000_000_000)),
            2_000_000_000,
            1,
        );

        // A live record admits an update, a term, and a release from
        // its own UA.
        assert!(live.admits(Action::Update, &ua, Some(Term::Years(1)), above, now));
        assert!(live.admits(Action::Release, &ua, None, above, now));

        // Released: the name is already released — nothing is admitted.
        let released = record(
            Action::Release,
            Expiry::At(ts(2_000_000_000)),
            2_000_000_000,
            2,
        );
        assert!(!released.admits(Action::Update, &ua, None, above, now));

        // Expired: the term has passed.
        assert!(!live.admits(Action::Update, &ua, None, above, ts(2_000_000_001)));

        // Stale: the trigger rides at or below the last confirmed
        // transition — it speaks against superseded state.
        assert!(!live.admits(Action::Update, &ua, None, BlockHeight::from_u32(100), now));
        assert!(!live.admits(Action::Update, &ua, None, BlockHeight::from_u32(99), now));

        // A forever name refuses any term — no runway to bank, no
        // second upgrade to buy — and admits the termless otherwise.
        let forever = record(Action::Claim, Expiry::Never, 2_000_000_000, 3);
        assert!(!forever.admits(Action::Update, &ua, Some(Term::Years(1)), above, now));
        assert!(forever.admits(Action::Update, &ua, None, above, now));
    }

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

    #[test]
    fn accept_claim_rejects_malformed_without_panic() {
        let mut r = Registry::new();
        let h = BlockHeight::from_u32(10);
        let mtp = ts(1_700_000_000);
        let a1 = nullifier(1);
        let a2 = nullifier(2);
        let succ = nullifier(10);
        r.adopt_anchor(h, a1);
        r.adopt_anchor(h, a2);
        let claim = NameNote::Claim {
            name: test_name(),
            ua: test_ua(),
            expires_at: Expiry::Never,
        };

        // No successor: retire the spent anchor, do not register.
        assert!(!r.accept_claim(&MAIN_NETWORK, &claim, nullifier(20), None, &[a1], h, mtp));
        assert!(!r.anchor_pool().contains(&a1));
        assert!(r.record(&test_name()).is_none());

        // Two anchors: retire both, keep the successor, do not register.
        r.adopt_anchor(h, a1);
        assert!(!r.accept_claim(
            &MAIN_NETWORK,
            &claim,
            nullifier(21),
            Some(succ),
            &[a2, a1],
            h,
            mtp
        ));
        assert!(!r.anchor_pool().contains(&a2));
        assert!(r.anchor_pool().contains(&succ));
        assert!(r.record(&test_name()).is_none());
    }

    #[test]
    fn accept_claim_that_spends_a_record_marks_it_released() {
        let mut r = live_alice(Expiry::Never, 3_000_000_000);
        let h = BlockHeight::from_u32(101);
        let mtp = ts(1_700_000_000);
        let anchor = nullifier(9);
        let succ = nullifier(10);
        r.adopt_anchor(h, anchor);
        let claim = NameNote::Claim {
            name: Name::parse("bob").unwrap(),
            ua: test_ua(),
            expires_at: Expiry::Never,
        };

        assert!(!r.accept_claim(
            &MAIN_NETWORK,
            &claim,
            nullifier(21),
            Some(succ),
            &[anchor, nullifier(1)],
            h,
            mtp
        ));
        let alice = r.record(&test_name()).expect("alice marked released");
        assert_eq!(alice.action, Action::Release);
        assert_eq!(alice.nullifier, nullifier(1));
        assert!(r.record(&Name::parse("bob").unwrap()).is_none());
        assert!(!r.anchor_pool().contains(&anchor));
        assert!(r.anchor_pool().contains(&succ));
    }

    #[test]
    fn follow_spends_retires_anchors_and_marks_names_released() {
        let mut r = live_alice(Expiry::Never, 3_000_000_000);
        let h = BlockHeight::from_u32(101);
        let anchor = nullifier(9);
        r.adopt_anchor(h, anchor);

        r.follow_spends(&[anchor, nullifier(1)], h);

        assert!(!r.anchor_pool().contains(&anchor));
        let alice = r.record(&test_name()).expect("alice marked released");
        assert_eq!(alice.action, Action::Release);
        assert_eq!(alice.nullifier, nullifier(1));
    }

    fn live_alice(expires_at: Expiry, deadline: i64) -> Registry {
        let mut r = Registry::new();
        r.set_record(
            test_name(),
            record(Action::Claim, expires_at, deadline, 1),
            BlockHeight::from_u32(100),
        );
        r
    }

    fn update_for_alice(expires_at: Expiry, prev: u8) -> NameNote {
        NameNote::Update {
            name: test_name(),
            ua: test_ua(),
            expires_at,
            prev: commitment(prev),
        }
    }

    #[test]
    fn accept_update_renews_while_both_clocks_are_live() {
        let mut r = live_alice(Expiry::At(ts(2_000_000_000)), 2_000_000_000);
        let note = update_for_alice(Expiry::At(ts(2_100_000_000)), 1);
        let succ = nullifier(20);
        assert!(r.accept_update(
            &MAIN_NETWORK,
            &note,
            succ,
            &[nullifier(1)],
            BlockHeight::from_u32(101),
            ts(1_000_000_000),
        ));
        let rec = r.record(&test_name()).expect("alice still bound");
        assert_eq!(rec.action, Action::Update);
        assert_eq!(rec.nullifier, succ);
    }

    #[test]
    fn accept_update_after_expiry_marks_released() {
        let mut r = live_alice(Expiry::At(ts(1_000_000_000)), 3_000_000_000);
        let note = update_for_alice(Expiry::At(ts(2_000_000_000)), 1);
        let succ = nullifier(20);
        assert!(!r.accept_update(
            &MAIN_NETWORK,
            &note,
            succ,
            &[nullifier(1)],
            BlockHeight::from_u32(101),
            ts(1_000_000_000),
        ));
        let rec = r.record(&test_name()).expect("alice marked released");
        assert_eq!(rec.action, Action::Release);
        assert_eq!(rec.nullifier, succ);
    }

    #[test]
    fn accept_update_after_liveness_marks_released() {
        let mut r = live_alice(Expiry::Never, 1_000_000_000);
        let note = update_for_alice(Expiry::Never, 1);
        let succ = nullifier(20);
        assert!(!r.accept_update(
            &MAIN_NETWORK,
            &note,
            succ,
            &[nullifier(1)],
            BlockHeight::from_u32(101),
            ts(1_000_000_000),
        ));
        let rec = r.record(&test_name()).expect("alice marked released");
        assert_eq!(rec.action, Action::Release);
        assert_eq!(rec.nullifier, succ);
    }

    #[test]
    fn accept_update_with_anchor_spend_follows_the_pool() {
        let mut r = live_alice(Expiry::Never, 3_000_000_000);
        r.set_record(
            Name::parse("bob").unwrap(),
            record(Action::Claim, Expiry::Never, 3_000_000_000, 2),
            BlockHeight::from_u32(100),
        );
        r.adopt_anchor(BlockHeight::from_u32(100), nullifier(9));
        let note = update_for_alice(Expiry::Never, 1);
        let height = BlockHeight::from_u32(101);
        let mtp = ts(1_000_000_000);

        // Well-formed update that also spends a claim anchor: rejected,
        // and the chain facts still land — alice's note was consumed,
        // so she is marked released, and the anchor retires.
        assert!(!r.accept_update(
            &MAIN_NETWORK,
            &note,
            nullifier(20),
            &[nullifier(1), nullifier(9)],
            height,
            mtp,
        ));
        let alice = r.record(&test_name()).expect("alice marked released");
        assert_eq!(alice.action, Action::Release);
        assert_eq!(alice.nullifier, nullifier(1));
        assert!(!r.anchor_pool().contains(&nullifier(9)));
        assert_eq!(
            r.record(&Name::parse("bob").unwrap())
                .expect("bob unchanged")
                .nullifier,
            nullifier(2)
        );
    }

    #[test]
    fn accept_update_prev_rcm_mismatch_marks_released() {
        let mut r = live_alice(Expiry::Never, 3_000_000_000);
        let wrong_prev = update_for_alice(Expiry::Never, 99);
        let height = BlockHeight::from_u32(101);
        let mtp = ts(1_000_000_000);

        // Alice's note was spent whatever the payload claims: the name
        // is released, bound to the successor nullifier it received.
        assert!(!r.accept_update(
            &MAIN_NETWORK,
            &wrong_prev,
            nullifier(20),
            &[nullifier(1)],
            height,
            mtp,
        ));
        let alice = r.record(&test_name()).expect("alice marked released");
        assert_eq!(alice.action, Action::Release);
        assert_eq!(alice.nullifier, nullifier(20));
    }

    #[test]
    fn accept_release_stays_legal_after_both_clocks() {
        let mut r = live_alice(Expiry::At(ts(1_000_000_000)), 1_000_000_000);
        let note = NameNote::Release {
            name: test_name(),
            ua: test_ua(),
            prev: commitment(1),
        };
        let succ = nullifier(20);
        assert!(r.accept_release(
            &MAIN_NETWORK,
            &note,
            succ,
            &[nullifier(1)],
            BlockHeight::from_u32(101),
            ts(1_000_000_000),
        ));
        let rec = r.record(&test_name()).expect("alice released");
        assert_eq!(rec.action, Action::Release);
        assert_eq!(rec.nullifier, succ);
    }
}
