//! Registry: the ZNS name-chain state machine and transition authorization.
//!

use crate::mint::otp::OtpQueue;
use crate::mint::{Action, Expiry, Name, NameCommitment, NameNote, Request, UnifiedAddress};
use std::collections::{BTreeMap, BTreeSet};
use time::Timestamp;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::consensus::Parameters;

/// Reads the current record of the name chain for `name`.
pub fn current_record(registry: &Registry, name: &Name) -> Option<NameRecord> {
    registry.record(name).cloned()
}

/// Which §4.5 clock fired to make a unilateral release due.
///
/// The mint releases a name for one of two reasons: the purchased term
/// (§4.5.2) or the liveness deadline `τ + L` (§4.5.4). Both settle to the
/// same on-chain `NameNote::Release`; the distinction is for operators.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReleaseReason {
    /// The purchased registration term has passed (`expires_at ≤ mtp`).
    Expiry,
    /// One liveness interval has elapsed since the last accepted
    /// transition (claim or update) and the controller did not re-prove
    /// control by `release_deadline`.
    Liveness,
}

impl ReleaseReason {
    /// A short label for logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReleaseReason::Expiry => "expiry",
            ReleaseReason::Liveness => "liveness",
        }
    }
}

// ---------------------------------------------------------------------------
// NameRecord — the current state of a name chain
// ---------------------------------------------------------------------------

/// The current state of a name in the registry.
///
/// Each name has a chain of Name Notes on-chain. This struct holds the
/// most recent confirmed note's derived state: what action created it,
/// what UA it points to, its cryptographic commitment, and when it was
/// confirmed. The nullifier is the note's authority identity: an update or
/// release is accepted only when its transaction spends this exact note.
#[derive(Clone, PartialEq, Eq)]
pub struct NameRecord {
    pub action: Action,
    /// The binding UA. A release retains the address it terminated so the
    /// on-chain transition remains historically complete.
    pub ua: UnifiedAddress,
    /// The committed expiration (§4.5); absent for the post-release state.
    pub expires_at: Expiry,
    pub commitment: NameCommitment,
    /// The block height at which this Name Note was confirmed.
    pub confirmed_height: BlockHeight,
    /// The MTP by which an accepted update must re-prove control of the
    /// bound address; past it, the Mint releases the name (§4.5.4).
    pub release_deadline: Timestamp,
    /// The exact nullifier this Name Note reveals when spent.
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

/// An undo-log entry: records what the record was before a `set_record` so a
/// reorg can rewind the registry to a prior height.
#[derive(Debug, Clone)]
pub struct RegistryHistoryRecord {
    pub height: BlockHeight,
    pub name: Name,
    pub prev_record: Option<NameRecord>,
}

/// The standing size of the anchor lineage pool: the ceremony's root,
/// conserved one-for-one by every accepted claim (spend one anchor, mint
/// one successor). Mirrors keygen's NUM_ANCHORS.
pub const ANCHOR_POOL_SIZE: usize = 40;

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed record for that name, plus an undo log for reorgs.
/// The anchor lineage pool lives here too: born as the first
/// ANCHOR_POOL_SIZE zero-value Registry outputs in chain history (the
/// ceremony's root — nothing can predate them), extended only by
/// successors of accepted claims, retired when spent.
pub struct Registry {
    records: BTreeMap<Name, NameRecord>,
    history: Vec<RegistryHistoryRecord>,
    claim_anchor_height: BlockHeight,
    anchor_pool: BTreeSet<orchard::note::Nullifier>,
    pool_checkpoints: BTreeMap<BlockHeight, BTreeSet<orchard::note::Nullifier>>,
}

impl Registry {
    /// Creates an empty name map. The height is the reorg
    /// boundary: a rewind below it discards the Registry.
    pub fn new(claim_anchor_height: BlockHeight) -> Self {
        Self {
            records: BTreeMap::new(),
            history: Vec::new(),
            claim_anchor_height,
            anchor_pool: BTreeSet::new(),
            pool_checkpoints: BTreeMap::new(),
        }
    }

    /// The transition law: is this request lawful against the current
    /// registry state, and what NameNote does it produce?
    ///
    /// `None` means unlawful. Claims keep their payment — retained in full,
    /// by policy; the payer may re-request. Echoes that fail verification
    /// are dropped: the name was simply not renewed.
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
                match current_record(self, &name) {
                    None => {}
                    Some(
                        record @ NameRecord {
                            action: Action::Release,
                            ..
                        },
                    ) => {
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
                let record = current_record(self, &name)?;
                if record.action == Action::Release {
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
                let record = current_record(self, &name)?;
                if record.action == Action::Release {
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

    /// Read the current record of a ZNS name chain.
    pub fn record(&self, name: &Name) -> Option<&NameRecord> {
        self.records.get(name)
    }

    /// Produces the mint's unilateral release when a live registration has
    /// reached either its purchased expiry or its liveness deadline (§4.5).
    ///
    /// The second component names which clock fired: `Expiry` for §4.5.2,
    /// `Liveness` for §4.5.4. When both are due at the same MTP, expiry
    /// wins — the purchased term is the more specific rule.
    pub fn release_due(&self, name: &Name, mtp: Timestamp) -> Option<(NameNote, ReleaseReason)> {
        let record = self.record(name)?;
        if record.action == Action::Release {
            return None;
        }
        let reason = if record.expires_at.expired(mtp) {
            ReleaseReason::Expiry
        } else if mtp >= record.release_deadline {
            ReleaseReason::Liveness
        } else {
            return None;
        };

        Some((
            NameNote::Release {
                name: name.clone(),
                ua: record.ua.clone(),
                prev: record.commitment,
            },
            reason,
        ))
    }

    /// Ceremony filling: a zero-value Registry output joins the lineage
    /// pool while below standing size. The first ANCHOR_POOL_SIZE are the
    /// ceremony's root — nothing can predate them, so nothing later can
    /// displace them. Name Notes are invisible to the standard scanner
    /// and never adopted; post-root successors enter only by induction on
    /// accepted claims, never by this cap.
    pub fn adopt_anchor(&mut self, height: BlockHeight, nf: orchard::note::Nullifier) {
        if self.anchor_pool.len() < ANCHOR_POOL_SIZE && self.anchor_pool.insert(nf) {
            self.pool_checkpoints
                .insert(height, self.anchor_pool.clone());
        }
    }

    /// Offers a confirmed claim candidate. `nfs` are the transaction's
    /// Ironwood spends; `successor` is the nullifier of the transaction's
    /// single zero-value Registry output (`None` when the outputs lack
    /// the claim shape).
    ///
    /// A claim is backed only when its transaction spent a standing
    /// anchor — a public UFVK lets anyone construct a valid ZNS output,
    /// but only the mint can spend an anchor. All invariant checks are
    /// assertions — only the mint can reach them; if one fires, it is a
    /// bug in the assembly path.
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
            .filter(|nf| self.anchor_pool.contains(*nf))
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
        self.anchor_pool.remove(&spent[0]);
        self.anchor_pool.insert(successor_nf);
        self.pool_checkpoints
            .insert(height, self.anchor_pool.clone());
        assert!(
            self.record(note.name())
                .is_none_or(|r| r.action == Action::Release),
            "claim attempted to replace live name {:?} — authorize \
             checks availability",
            note.name()
        );
        self.set_record(
            note.name().clone(),
            NameRecord::from_received(params, note, nullifier, height, mtp),
            height,
        );
        true
    }

    /// Offers a confirmed update candidate. Backed only when the
    /// transaction spent exactly the current Name Note of this note's
    /// own name; an unbacked candidate — a correctly formed public
    /// output that is not mint-authored — has no effect. A backed
    /// transition always enacts: only the mint can spend the current
    /// note, and assembly checks liveness before transitioning.
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

    /// Offers a confirmed release candidate. Same law as
    /// [`Self::accept_update`].
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

    /// The shared law of update and release: the transaction must have
    /// spent exactly the current Name Note of `note`'s own name.
    /// Returns the live predecessor, or `None` when unbacked.
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
            !nfs.iter().any(|nf| self.anchor_pool.contains(nf)),
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
                .filter(|record| record.action != Action::Release)
                .expect(
                    "update/release has no live predecessor \
                     — assembly checks liveness before transitioning",
                ),
        )
    }

    /// The names whose current Name Note these nullifiers spend.
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

    /// Read-only iterator over all known name records. Used for diagnostics.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &NameRecord)> {
        self.records.iter()
    }

    /// The anchor lineage pool: the ceremony's root, conserved one-for-one
    /// by every accepted claim. Registration authority is drawn only from
    /// this set; forged or donated zero-value Registry notes are not in it,
    /// never count toward genesis, and can never be spent as anchors.
    pub fn anchor_pool(&self) -> &BTreeSet<orchard::note::Nullifier> {
        &self.anchor_pool
    }

    /// Rewinds the registry state back to the specified height (linear undo).
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        assert!(
            height >= self.claim_anchor_height,
            "FATAL: rewind crossed the boot-created Registry anchor"
        );
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
        self.pool_checkpoints.retain(|&h, _| h <= height);
        self.anchor_pool = self
            .pool_checkpoints
            .last_key_value()
            .map(|(_, pool)| pool.clone())
            .unwrap_or_default();
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

    /// A live claim before either clock fires: nothing to do.
    #[test]
    fn release_due_returns_none_while_live() {
        let mut r = Registry::new(BlockHeight::from_u32(100));
        let name = test_name();
        r.set_record(
            name.clone(),
            record(Action::Claim, Expiry::Never, 2_000_000_000, 1),
            BlockHeight::from_u32(100),
        );
        assert_eq!(r.release_due(&name, ts(1_999_999_999)), None);
    }

    /// The purchased term is up but the liveness deadline is not: the mint
    /// releases with `ReleaseReason::Expiry`.
    #[test]
    fn release_due_reports_expiry_when_purchased_term_lapses() {
        let mut r = Registry::new(BlockHeight::from_u32(100));
        let name = test_name();
        // deadline far in the future — only the expiry clock can fire.
        r.set_record(
            name.clone(),
            record(
                Action::Claim,
                Expiry::At(ts(1_500_000_000)),
                3_000_000_000,
                1,
            ),
            BlockHeight::from_u32(100),
        );
        let (note, reason) = r
            .release_due(&name, ts(1_500_000_000))
            .expect("purchased term expired");
        assert_eq!(reason, ReleaseReason::Expiry);
        assert!(matches!(note, NameNote::Release { .. }));
    }

    /// A Never-expiring name whose liveness deadline has passed: only the
    /// liveness clock can retire it.
    #[test]
    fn release_due_reports_liveness_when_deadline_passes() {
        let mut r = Registry::new(BlockHeight::from_u32(100));
        let name = test_name();
        r.set_record(
            name.clone(),
            record(Action::Claim, Expiry::Never, 1_700_000_000, 1),
            BlockHeight::from_u32(100),
        );
        let (_, reason) = r
            .release_due(&name, ts(1_700_000_000))
            .expect("liveness deadline passed");
        assert_eq!(reason, ReleaseReason::Liveness);
    }

    /// The purchased term is the more specific rule: when both clocks
    /// fire at the same MTP, expiry is reported.
    #[test]
    fn release_due_prefers_expiry_when_both_clocks_fire_together() {
        let mut r = Registry::new(BlockHeight::from_u32(100));
        let name = test_name();
        let same = 1_700_000_000_i64;
        r.set_record(
            name.clone(),
            record(Action::Claim, Expiry::At(ts(same)), same, 1),
            BlockHeight::from_u32(100),
        );
        let (_, reason) = r.release_due(&name, ts(same)).expect("both clocks fired");
        assert_eq!(reason, ReleaseReason::Expiry);
    }

    /// An already-released record is not releasable again, no matter how
    /// far the tip has moved past its deadlines.
    #[test]
    fn release_due_yields_nothing_for_already_released_records() {
        let mut r = Registry::new(BlockHeight::from_u32(100));
        let name = test_name();
        r.set_record(
            name.clone(),
            record(Action::Release, Expiry::Never, 1_000_000_000, 1),
            BlockHeight::from_u32(100),
        );
        assert_eq!(r.release_due(&name, ts(9_999_999_999)), None);
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
}
