//! Registry: the ZNS name-chain state machine and transition authorization.
//!

use crate::mint::otp::OtpQueue;
use crate::mint::{
    Action, Expiry, Name, NameCommitment, NameNote, Request, Term, UnifiedAddress,
    LIVENESS_INTERVAL, MAX_TERM_YEARS, REGISTRY_ACCOUNT,
};
use std::collections::BTreeMap;
use time::Timestamp;
use zcash_client_backend::data_api::ScannedBlock;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::consensus::Parameters;
use zip32::AccountId;

/// Reads the current record of the name chain for `name`.
pub fn current_record(registry: &Registry, name: &Name) -> Option<NameRecord> {
    registry.record(name).cloned()
}

// ---------------------------------------------------------------------------
// ReceivedNameNote — scanner evidence for one Name Note
// ---------------------------------------------------------------------------

/// A cryptographically validated Name Note received at the exact Registry address.
///
/// Produced by the orchestrator's ZNS decryption pass over an applied block
/// (each candidate's ZNS-derived cmx is checked against the action's actual
/// cmx before the note is exposed) and consumed by [`Registry::apply_block`].
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedNameNote {
    txid: TxId,
    action_index: usize,
    nullifier: orchard::note::Nullifier,
    payload: NameNote,
}

impl ReceivedNameNote {
    pub fn new(
        txid: TxId,
        action_index: usize,
        nullifier: orchard::note::Nullifier,
        payload: NameNote,
    ) -> Self {
        Self {
            txid,
            action_index,
            nullifier,
            payload,
        }
    }

    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    pub fn action_index(&self) -> usize {
        self.action_index
    }

    /// The exact nullifier this Name Note reveals when spent.
    pub fn nullifier(&self) -> orchard::note::Nullifier {
        self.nullifier
    }

    /// The decoded typed transition from the note's memo.
    pub fn payload(&self) -> &NameNote {
        &self.payload
    }
}

impl std::fmt::Debug for ReceivedNameNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedNameNote")
            .field("txid", &self.txid)
            .field("action_index", &self.action_index)
            .field("payload", &"<redacted>")
            .finish()
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
        received: ReceivedNameNote,
        confirmed_height: BlockHeight,
        mtp: Timestamp,
    ) -> Self {
        let note = received.payload();
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
            nullifier: received.nullifier(),
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

/// One claim-anchor advance, retained so a reorg restores the exact prior
/// anchor before any replacement block is applied.
#[derive(Debug, Clone)]
struct ClaimAnchorHistory {
    height: BlockHeight,
    previous: orchard::note::Nullifier,
}

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed record for that name, plus an undo log for reorgs.
#[derive(Clone)]
pub struct Registry {
    records: BTreeMap<Name, NameRecord>,
    history: Vec<RegistryHistoryRecord>,
    claim_anchor: orchard::note::Nullifier,
    claim_anchor_height: BlockHeight,
    claim_anchor_history: Vec<ClaimAnchorHistory>,
}

impl Registry {
    /// Creates an empty name map rooted at the confirmed anchor created by
    /// boot. A claim can advance this chain, but cannot create its root.
    pub fn new(claim_anchor: orchard::note::Nullifier, claim_anchor_height: BlockHeight) -> Self {
        Self {
            records: BTreeMap::new(),
            history: Vec::new(),
            claim_anchor,
            claim_anchor_height,
            claim_anchor_history: Vec::new(),
        }
    }

    /// The zero-value Registry anchor the next accepted claim must spend.
    pub fn claim_anchor(&self) -> orchard::note::Nullifier {
        self.claim_anchor
    }

    /// The height at which the current anchor chain began.
    ///
    /// A reorg below this height removes the root itself, so the orchestrator
    /// must discard this Registry and recover the root while rescanning.
    pub fn claim_anchor_height(&self) -> BlockHeight {
        self.claim_anchor_height
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
            Request::Claim { name, ua, term } => {
                // Availability: unseen, or released with a payment that
                // postdates the tombstone — a payment mined before the
                // release predates the freedom it claims.
                match current_record(self, &name) {
                    None => {}
                    Some(record @ NameRecord { action: Action::Release, .. }) => {
                        if payment_height <= record.confirmed_height {
                            return None;
                        }
                    }
                    Some(_) => return None, // live
                }
                let expires_at = match term {
                    Term::Forever => Expiry::Never,
                    Term::Years(years) => {
                        let seconds = years.checked_mul(LIVENESS_INTERVAL as u64)? as i64;
                        let at = mtp.as_seconds().checked_add(seconds)?;
                        Expiry::At(Timestamp::from_seconds(at).ok()?)
                    }
                };
                Some(NameNote::Claim {
                    name,
                    ua,
                    expires_at,
                })
            }
            Request::Update {
                name,
                ua,
                extend_years,
            } => {
                let record = current_record(self, &name)?;
                if record.action == Action::Release {
                    return None;
                }
                // §4.5.3: no update is accepted once expiry is reached —
                // the Mint's lifecycle release owns that moment.
                if record.expires_at.expired(mtp) {
                    return None;
                }
                let otp = otp?;
                if !challenges.accept(&name, Action::Update, &ua, record.commitment, otp, mtp) {
                    return None;
                }
                // §4.5.3: an ordinary update carries the current expiry
                // forward; an extension adds whole years to it — never
                // past the ninety-nine-year fence measured from now.
                let expires_at = match (record.expires_at, extend_years) {
                    (Expiry::Never, _) | (_, None) => record.expires_at,
                    (Expiry::At(current), Some(years)) => {
                        let extension = years.checked_mul(LIVENESS_INTERVAL as u64)? as i64;
                        let extended = current.as_seconds().checked_add(extension)?;
                        let fence = mtp
                            .as_seconds()
                            .checked_add((MAX_TERM_YEARS as i64).checked_mul(LIVENESS_INTERVAL)?)?;
                        if extended > fence {
                            return None;
                        }
                        Expiry::At(Timestamp::from_seconds(extended).ok()?)
                    }
                };
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
    /// reached either its purchased expiry or its liveness deadline.
    pub fn release_due(&self, name: &Name, mtp: Timestamp) -> Option<NameNote> {
        let record = self.record(name)?;
        if record.action == Action::Release
            || (!record.expires_at.expired(mtp) && mtp < record.release_deadline)
        {
            return None;
        }

        Some(NameNote::Release {
            name: name.clone(),
            ua: record.ua.clone(),
            prev: record.commitment,
        })
    }

    /// Applies every Registry transition in block order.
    ///
    /// Takes the upstream [`ScannedBlock`] directly, plus the supplemental
    /// [`ReceivedNameNote`] lane from the orchestrator's ZNS decryption pass.
    /// The scanner supplies both pieces of unforgeable Registry evidence:
    /// spent nullifiers and ordinary zero-value Registry outputs.
    ///
    /// All ZNS invariant checks are assertions — only the mint can create or
    /// spend Name Notes, and its assembly code prevents every violation by
    /// construction. If an assertion fires, it's a bug in the assembly path.
    pub fn apply_block<P: Parameters>(
        &self,
        params: &P,
        scanned: &ScannedBlock<AccountId>,
        name_notes: &[ReceivedNameNote],
        mtp: Timestamp,
    ) -> (Self, Vec<usize>) {
        let mut next = self.clone();
        let mut accepted = Vec::new();
        let height = scanned.height();

        // Group the supplemental Name Note lane and every revealed Ironwood
        // nullifier by transaction. Name Notes use the ZNS encryption domain,
        // while nullifiers and ordinary anchor outputs come from the standard
        // scanner; joining on txid is the authentication boundary.
        let mut name_notes_by_tx: BTreeMap<TxId, Vec<(usize, &ReceivedNameNote)>> = BTreeMap::new();
        for (index, note) in name_notes.iter().enumerate() {
            name_notes_by_tx
                .entry(*note.txid())
                .or_default()
                .push((index, note));
        }
        for notes in name_notes_by_tx.values_mut() {
            notes.sort_by_key(|(_, note)| note.action_index());
        }
        let mut nullifiers_by_tx: BTreeMap<TxId, Vec<orchard::note::Nullifier>> = BTreeMap::new();
        for (_index, txid, nullifiers) in scanned.ironwood().nullifier_map() {
            nullifiers_by_tx
                .entry(*txid)
                .or_default()
                .extend(nullifiers.iter().copied());
        }

        for wtx in scanned.transactions() {
            let txid = wtx.txid();
            let ironwood_nullifiers: &[orchard::note::Nullifier] = nullifiers_by_tx
                .get(&txid)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let received_name_notes: &[(usize, &ReceivedNameNote)] = name_notes_by_tx
                .get(&txid)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let registry_outputs: Vec<_> = wtx
                .ironwood_outputs()
                .iter()
                .filter(|output| *output.account_id() == REGISTRY_ACCOUNT)
                .collect();

            let spends_claim_anchor = ironwood_nullifiers.contains(&next.claim_anchor);
            let spent_record_names: Vec<_> = next
                .records
                .iter()
                .filter_map(|(name, record)| {
                    ironwood_nullifiers
                        .contains(&record.nullifier)
                        .then(|| name.clone())
                })
                .collect();
            let spends_registry_authority = spends_claim_anchor || !spent_record_names.is_empty();

            match received_name_notes {
                [] => {
                    assert!(
                        !spends_registry_authority,
                        "Registry authority was spent without a Name Note successor"
                    );
                }
                notes if notes.len() > 1 => {
                    if spends_registry_authority {
                        panic!(
                            "mint produced multiple Name Notes in one transaction \
                                — assembly creates exactly one"
                        );
                    }
                }
                [entry] => {
                    let (note_index, note) = *entry;
                    let payload = note.payload();
                    let name = payload.name();
                    match payload.action() {
                        Action::Claim => {
                            // A public UFVK lets anyone construct a valid ZNS
                            // output. Only the mint can spend the current
                            // zero-value claim anchor, so without that spend
                            // this candidate has no Registry effect.
                            if !spends_claim_anchor {
                                continue;
                            }
                            assert!(
                                spent_record_names.is_empty(),
                                "claim transaction spent a record — assembly never \
                                 spends a Name Note when claiming"
                            );
                            assert_eq!(
                                registry_outputs.len(),
                                1,
                                "claim must create exactly one successor anchor"
                            );
                            let successor = registry_outputs[0];
                            assert_eq!(
                                successor.note().0.value().inner(),
                                0,
                                "Registry anchor value must remain zero"
                            );
                            let successor_nullifier = successor
                                .nf()
                                .copied()
                                .expect("Registry FVK must derive the successor anchor nullifier");
                            assert!(
                                next.record(name)
                                    .is_none_or(|r| r.action == Action::Release),
                                "claim attempted to replace live name {name:?} \
                                 — authorize_claim checks availability"
                            );
                            next.claim_anchor_history.push(ClaimAnchorHistory {
                                height,
                                previous: next.claim_anchor,
                            });
                            next.claim_anchor = successor_nullifier;
                        }
                        Action::Update | Action::Release => {
                            if spent_record_names.is_empty() {
                                // Correctly formed public output, but no spend
                                // of the current Name Note: not mint-authored.
                                continue;
                            }
                            assert!(
                                !spends_claim_anchor,
                                "update/release must not advance the claim-anchor chain"
                            );
                            assert!(
                                registry_outputs.is_empty(),
                                "update/release must not create a claim anchor"
                            );
                            let record = next
                                .record(name)
                                .filter(|record| record.action != Action::Release)
                                .expect(
                                    "update/release has no live predecessor \
                                        — assembly checks liveness before transitioning",
                                );
                            assert!(
                                payload.prev_rcm() == Some(record.commitment),
                                "predecessor mismatch — assembly reads commitment \
                                 from the same registry"
                            );
                            assert!(
                                spent_record_names.as_slice() == [name.clone()],
                                "update/release did not spend the exact current Name Note \
                                 — assembly spends the exact current note"
                            );
                        }
                    }

                    next.set_record(
                        name.clone(),
                        NameRecord::from_received(params, (*note).clone(), height, mtp),
                        height,
                    );
                    accepted.push(note_index);
                }
                _ => unreachable!("slice cardinality was handled above"),
            }
        }

        (next, accepted)
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
        while let Some(entry) = self.claim_anchor_history.last() {
            if entry.height <= height {
                break;
            }
            let entry = self.claim_anchor_history.pop().unwrap();
            self.claim_anchor = entry.previous;
        }
    }
}
