//! The live mint's name-chain law, copied from zns-mint `46f61f9`
//! (`src/mint/registry.rs`). Do not change this law; it is mainnet's.
//!
//! The copy is verbatim apart from imports, the `NameRcm` rename, and the
//! authorization laws that need the old mint's requests (`allows_challenge`,
//! `authorize_*`). zns-rebind does not call every item it keeps.
#![allow(dead_code)]

mod anchor_pool;

use anchor_pool::AnchorPool;

pub use anchor_pool::is_ceremony_fill;

use crate::note::{Action, Expiry, Name, NameNote, NameRcm};
use std::collections::{BTreeMap, BTreeSet};
use zcash_primitives::transaction::builder::default_tx_expiry_delta;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zns_mint::mint::Timestamp;
use zns_mint::mint::UnifiedAddress;

// ---------------------------------------------------------------------------
// NameRecord — a confirmed state in one name's chain
// ---------------------------------------------------------------------------

/// One confirmed state in a name's chain.
#[derive(Clone, PartialEq, Eq)]
pub struct NameRecord {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    pub expires_at: Expiry,
    pub commitment: NameRcm,
    pub confirmed_height: BlockHeight,
    pub release_deadline: Timestamp,
    pub predecessor_nullifier: orchard::note::Nullifier,
}

impl NameRecord {
    /// The §4.5 clocks, fired: the term lapsed or the liveness
    /// deadline reached at `mtp`.
    pub fn is_release_due(&self, mtp: Timestamp) -> bool {
        self.has_expired(mtp) || mtp >= self.release_deadline
    }

    /// The §4.5.2 term test at `mtp`.
    pub fn has_expired(&self, mtp: Timestamp) -> bool {
        self.expires_at.expired(mtp)
    }

    /// The name's state as of `note` taking effect at `confirmed_height`:
    /// commitment = the note's identity, liveness clock restarted from
    /// `mtp`, `spent` = the nullifier it will reveal when next spent.
    fn create<P: Parameters>(
        params: &P,
        note: &NameNote,
        spent: orchard::note::Nullifier,
        confirmed_height: BlockHeight,
        mtp: Timestamp,
    ) -> Self {
        Self {
            name: note.name().clone(),
            action: note.action(),
            ua: note.ua().clone(),
            expires_at: note.expires_at().unwrap_or(Expiry::Never),
            commitment: note.commitment(params),
            confirmed_height,
            release_deadline: Timestamp::from_seconds(
                mtp.as_seconds() + crate::note::LIVENESS_INTERVAL,
            )
            .expect("liveness deadline fits Timestamp"),
            predecessor_nullifier: spent,
        }
    }

    /// This record's nullifier, when `note` still names this exact
    /// state.
    pub fn nullifier(&self, note: &NameNote) -> Option<orchard::note::Nullifier> {
        (Some(self.commitment) == note.prev_rcm()).then_some(self.predecessor_nullifier)
    }
}

impl std::fmt::Debug for NameRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameRecord")
            .field("name", &self.name)
            .field("action", &self.action)
            .field("ua", &self.ua)
            .field("commitment", &self.commitment)
            .field("confirmed_height", &self.confirmed_height)
            .field("predecessor_nullifier", &self.predecessor_nullifier)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Registry — tip records, per-name chains, and anchor lineage
// ---------------------------------------------------------------------------

/// Name records at the applied tip, each name's confirmed record chain, and
/// the anchor lineage pool.
#[derive(Default)]
pub struct Registry {
    /// Names that are live at the applied tip. Released names are absent.
    records: BTreeMap<Name, NameRecord>,
    /// All confirmed records for each name, in canonical application order.
    history: BTreeMap<Name, Vec<NameRecord>>,
    anchors: AnchorPool,
}

impl Registry {
    /// Empty state; boot sync adopts the ceremony's anchor pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// The record for a name at the applied tip. Released names are absent.
    pub fn record(&self, name: &Name) -> Option<&NameRecord> {
        self.records.get(name)
    }

    /// The confirmed record chain for a name, oldest first.
    pub fn record_history(&self, name: &Name) -> &[NameRecord] {
        self.history.get(name).map_or(&[], Vec::as_slice)
    }

    /// Whether the name has no record in the applied-tip registry.
    pub fn is_available(&self, name: &Name) -> bool {
        self.record(name).is_none()
    }

    /// The §4.5 clocks, swept: every live name whose purchased term or
    /// liveness deadline has passed at `mtp`, with the release note it
    /// is owed. Idempotent per tip.
    pub fn releases_due(&self, mtp: Timestamp) -> impl Iterator<Item = (Name, NameNote)> + '_ {
        self.records
            .iter()
            .filter(move |(_, record)| record.is_release_due(mtp))
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

    /// Offers a confirmed claim candidate; true when it spent one
    /// standing anchor, spent no Name Note, and the name was free.
    /// After a release, `expiry` must sit past the standard expiry
    /// window, so a transaction built earlier does not register.
    /// A rejected claim retires the anchor it spent and does not seat
    /// its successor.
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
        expiry: BlockHeight,
    ) -> bool {
        assert!(matches!(note, NameNote::Claim { .. }));
        let spent: Vec<_> = nfs
            .iter()
            .filter(|nf| self.anchors.contains(nf))
            .copied()
            .collect();
        let name_free = self.record(note.name()).is_none();
        let built_after_release = !self.built_before_release(params, note.name(), expiry);
        // Spent anchors retire on any verdict. The successor joins only
        // when this claim is admitted: one anchor, no Name Note, name free,
        // and not an older transaction mining after a release.
        let seated = successor.filter(|_| {
            spent.len() == 1
                && self.names_spent_by(nfs).is_empty()
                && name_free
                && built_after_release
        });
        self.anchors.retire_spent(nfs, seated, height);

        // The law: a well-formed claim spends exactly one anchor,
        // spends no Name Note, creates a zero-value successor, and
        // finds the name free (or released after this transaction was built).
        if successor.is_none() || spent.len() != 1 || !self.names_spent_by(nfs).is_empty() {
            self.mark_released(nfs, height);
            return false;
        }
        if !name_free {
            // A late or duplicate claim: first confirmed wins.
            return false;
        }
        if !built_after_release {
            return false;
        }
        self.set_record(NameRecord::create(params, note, nullifier, height, mtp));
        true
    }

    /// The mint builds a claim only after a release is applied, and sets
    /// expiry to the target height plus the standard delta at that
    /// height: 40 blocks, 120 from NU7. The delta never shrinks, so a
    /// transaction inside the release height's window was built before
    /// the release.
    fn built_before_release<P: Parameters>(
        &self,
        params: &P,
        name: &Name,
        expiry: BlockHeight,
    ) -> bool {
        let Some(latest) = self.record_history(name).last() else {
            return false;
        };
        let released = latest.confirmed_height;
        let delta = default_tx_expiry_delta(BranchId::for_height(params, released));
        latest.action.is_release() && expiry <= released + delta
    }

    /// Offers a confirmed update candidate; true when the transaction
    /// spent this name's current note. A signed update renews, and the
    /// new liveness deadline starts at this block's median.
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
        self.set_record(NameRecord::create(params, note, nullifier, height, mtp));
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
        self.set_record(NameRecord::create(params, note, nullifier, height, mtp));
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
        self.set_record(NameRecord::create(params, &release, nullifier, height, mtp));
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
        self.record(note.name()).cloned()
    }

    /// The names whose current notes these nullifiers spend.
    fn names_spent_by(&self, nfs: &[orchard::note::Nullifier]) -> Vec<Name> {
        self.records
            .iter()
            .filter(|(_, record)| nfs.contains(&record.predecessor_nullifier))
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
            let mut released_record = record;
            released_record.action = Action::Release;
            released_record.confirmed_height = height;
            self.set_record(released_record);
        }
    }

    fn set_record(&mut self, record: NameRecord) {
        let name = record.name.clone();
        let history = self.history.entry(name.clone()).or_default();
        if let Some(previous) = history.last() {
            debug_assert!(previous.confirmed_height <= record.confirmed_height);
        }
        history.push(record.clone());
        if record.action.is_release() {
            self.records.remove(&name);
        } else {
            self.records.insert(name, record);
        }
    }

    /// Every name record live at the applied tip; diagnostics only.
    pub fn name_chain(&self) -> impl Iterator<Item = &NameRecord> {
        self.records.values()
    }

    /// The anchor lineage pool — the only source of claim authority.
    pub fn anchor_pool(&self) -> &BTreeSet<orchard::note::Nullifier> {
        self.anchors.live()
    }

    /// The first anchor in pool order that `spendable` accepts.
    /// `None` when the pool is empty or every anchor is refused.
    pub fn spendable_claim_anchor(
        &self,
        mut spendable: impl FnMut(orchard::note::Nullifier) -> bool,
    ) -> Option<orchard::note::Nullifier> {
        self.anchor_pool().iter().copied().find(|&nf| spendable(nf))
    }

    /// Whether ceremony adoption has reached standing size and stays closed.
    pub fn anchor_adoption_closed(&self) -> bool {
        self.anchors.adoption_closed()
    }

    /// Truncates every name's record chain to `height` and rebuilds the
    /// records live at that tip. Callers pass walk-found heights at or above
    /// the boot origin.
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        self.history.retain(|_, records| {
            while records
                .last()
                .is_some_and(|record| record.confirmed_height > height)
            {
                records.pop();
            }
            !records.is_empty()
        });

        self.records.clear();
        for records in self.history.values() {
            if let Some(record) = records.last().filter(|record| !record.action.is_release()) {
                self.records.insert(record.name.clone(), record.clone());
            }
        }
        self.anchors.truncate_to(height);
    }
}

// ---------------------------------------------------------------------------
// Block application: the Name Note half of `46f61f9`'s `apply_block`
// ---------------------------------------------------------------------------

/// The live mint's confirmation pass over one block, at or after its
/// birthday. `block_mtp` is the median including this block.
///
/// The live mint took each transaction's spends and Registry outputs from
/// its wallet scan. Here they come from the block: every Ironwood
/// nullifier the transaction reveals, and every output that decrypts to
/// the Registry under the standard domain, external or internal scope —
/// the keys the live wallet scanned with. Old Name Notes fail standard
/// decryption there as here. A nullifier the law does not hold changes
/// nothing, so reading every spend, not only the wallet's, is the same
/// verdict.
pub fn apply<P: Parameters>(
    network: &P,
    registry_keys: &zns_mint::RegistryKeys,
    block: &zcash_primitives::block::Block,
    height: BlockHeight,
    block_mtp: Timestamp,
    registry: &mut Registry,
) {
    use zcash_primitives::transaction::TxId;

    let candidates = crate::note::decrypt_name_notes(network, block, registry_keys);
    let expiry_by_txid: BTreeMap<TxId, BlockHeight> = block
        .vtx()
        .iter()
        .map(|tx| (tx.txid(), tx.expiry_height()))
        .collect();

    // The confirmation pass: the scanner's transactions in block order.
    // Two claims for one name in the same block: the lower vtx is
    // offered first and wins. The loser's payment is not returned.
    // Sequencing is here; the law is the Registry's.
    let mut notes_by_tx: BTreeMap<TxId, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        notes_by_tx.entry(candidate.txid).or_default().push(index);
    }
    for notes in notes_by_tx.values_mut() {
        notes.sort_by_key(|index| candidates[*index].action_index);
    }

    let registry_fvk = registry_keys.orchard_fvk();
    let registry_ivks = [
        orchard::keys::Scope::External,
        orchard::keys::Scope::Internal,
    ]
    .map(|scope| registry_fvk.to_ivk(scope).prepare());

    for tx in block.vtx() {
        let txid = tx.txid();
        let actions = tx
            .ironwood_bundle()
            .map(|bundle| bundle.actions().iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let nfs: Vec<orchard::note::Nullifier> =
            actions.iter().map(|action| *action.nullifier()).collect();
        // (zero value, nullifier) of each Registry output.
        let registry_outputs: Vec<(bool, orchard::note::Nullifier)> = actions
            .iter()
            .filter_map(|action| {
                let domain = orchard::note_encryption::IronwoodDomain::for_action(*action);
                registry_ivks.iter().find_map(|ivk| {
                    zcash_note_encryption::try_note_decryption(&domain, ivk, *action)
                })
            })
            .map(|(note, _, _)| (note.value().inner() == 0, note.nullifier(&registry_fvk)))
            .collect();

        // The keygen transaction carries every standing anchor and no
        // name note. A zero-value note in any other transaction does not
        // join. A claim's successor still enters through `accept_claim`.
        let name_notes = notes_by_tx.get(&txid).map(Vec::len).unwrap_or(0);
        let ceremony: Vec<_> = registry_outputs
            .iter()
            .filter(|(zero, _)| *zero)
            .map(|(_, nf)| *nf)
            .collect();
        if is_ceremony_fill(ceremony.len(), name_notes) {
            for nf in ceremony {
                registry.adopt_anchor(height, nf);
            }
        }

        let notes: &[usize] = notes_by_tx.get(&txid).map(Vec::as_slice).unwrap_or(&[]);
        match notes {
            [index] => {
                let candidate = &candidates[*index];
                let action = candidate.payload.action();
                if action.is_claim() {
                    // The successor anchor: a backed claim creates
                    // exactly one zero-value Registry output.
                    let successor = match registry_outputs.as_slice() {
                        [(true, nf)] => Some(*nf),
                        _ => None,
                    };
                    let expiry = expiry_by_txid
                        .get(&txid)
                        .copied()
                        .expect("FATAL: scanned transaction is missing from the block");
                    registry.accept_claim(
                        network,
                        &candidate.payload,
                        candidate.nullifier,
                        successor,
                        &nfs,
                        height,
                        block_mtp,
                        expiry,
                    );
                } else {
                    match action {
                        Action::Update => {
                            registry.accept_update(
                                network,
                                &candidate.payload,
                                candidate.nullifier,
                                &nfs,
                                height,
                                block_mtp,
                            );
                        }
                        Action::Release => {
                            registry.accept_release(
                                network,
                                &candidate.payload,
                                candidate.nullifier,
                                &nfs,
                                height,
                                block_mtp,
                            );
                        }
                        Action::Claim => unreachable!("claims are routed above"),
                    }
                }
            }
            _ => registry.follow_spends(&nfs, height),
        }
    }
}
