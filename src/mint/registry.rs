//! Registry: the ZNS name-chain state machine, transition authorization, and
//! transaction assembly path.
//!
//! Submodules:
//! - [`authorize`] — `NameNoteRequest`, `authorize_claim`/`update`/`release`,
//!   OTP challenge state (`ChallengeKey`, `PendingOtps`), relay memo encoding
//! - [`liquidity`] — Registry fee-note classification and top-up policy
//! - [`transaction`] — `build_transaction`
//!
//! V6 assembly/proving/signing lives in [`crate::mint::signer`]; transparent
//! outputs ([`crate::mint::signer::TransparentOutput`]) moved with it.

pub mod authorize;
pub mod liquidity;
pub mod transaction;

// The module's primary public API — the authorization functions and the
// request types they produce.
pub use authorize::{
    authorize_claim, authorize_release, authorize_update, current_record,
    NameNoteRequest,
};
pub use liquidity::{
    classify_registry_ironwood_note, classify_registry_note_parts, RegistryFeeLiquidity,
    RegistryFundingPlan, RegistryNoteClass,
};
pub use transaction::{build_transaction, select_registry_fee_inputs, RegistryFeeInputs};

use crate::mint::{Action, Expiry, Name, NameCommitment, NameNote, UnifiedAddress, REGISTRY_ACCOUNT};
use zcash_protocol::consensus::Parameters;
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use zcash_client_backend::data_api::ScannedBlock;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zip32::AccountId;

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
    note: orchard::note::Note,
    payload: NameNote,
}

impl ReceivedNameNote {
    pub fn new(
        txid: TxId,
        action_index: usize,
        note: orchard::note::Note,
        payload: NameNote,
    ) -> Self {
        Self { txid, action_index, note, payload }
    }

    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    pub fn action_index(&self) -> usize {
        self.action_index
    }

    /// The raw decrypted note — carries recipient, value, rho, rseed.
    pub fn note(&self) -> &orchard::note::Note {
        &self.note
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
// Record — the current state of a name chain
// ---------------------------------------------------------------------------

/// The current state of a name in the registry.
///
/// Each name has a chain of Name Notes on-chain. This struct holds the
/// most recent confirmed note's derived state: what action created it,
/// what UA it points to, its cryptographic commitment, and when it was
/// confirmed. The `rho` field links to the actual shielded note in the
/// wallet — the wallet indexes notes by `rho`, so one lookup retrieves
/// everything needed to spend it (the note, its Merkle position, and its
/// memo for psi recomputation).
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    pub action: Action,
    /// The bound UA; `None` once released (§3.1 encodes the field empty;
    /// §4.6 retains knowledge of the released binding via history).
    pub ua: Option<UnifiedAddress>,
    /// The committed expiration (§4.5); absent for the post-release state.
    pub expires_at: Expiry,
    pub commitment: NameCommitment,
    /// The block height at which this Name Note was confirmed.
    pub confirmed_height: BlockHeight,
    /// The note's unique identity — links to the shielded note in the wallet.
    pub rho: orchard::note::Rho,
}

impl Record {
    fn from_received<P: Parameters>(
        params: &P,
        received: ReceivedNameNote,
        confirmed_height: BlockHeight,
    ) -> Self {
        let note = received.payload();
        let (rcm, _) = note.opening(params);
        Self {
            action: note.action(),
            ua: note.ua().cloned(),
            expires_at: note.expires_at().unwrap_or(Expiry::Never),
            commitment: NameCommitment::from_inner(orchard::note::NoteCommitTrapdoor::from_inner(
                rcm,
            )),
            confirmed_height,
            rho: received.note().rho(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        action: Action,
        ua: Option<UnifiedAddress>,
        expires_at: Expiry,
        commitment: NameCommitment,
        confirmed_height: BlockHeight,
        rho: orchard::note::Rho,
    ) -> Self {
        Self {
            action,
            ua,
            expires_at,
            commitment,
            confirmed_height,
            rho,
        }
    }
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("action", &self.action)
            .field("ua", &self.ua)
            .field("commitment", &self.commitment)
            .field("confirmed_height", &self.confirmed_height)
            .field("rho", &self.rho)
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
    pub prev_record: Option<Record>,
}

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed record for that name, plus an undo log for reorgs.
#[derive(Clone)]
pub struct Registry {
    records: BTreeMap<Name, Record>,
    history: Vec<RegistryHistoryRecord>,
}

impl Registry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            history: Vec::new(),
        }
    }

    /// Read the current record of a ZNS name chain.
    pub fn record(&self, name: &Name) -> Option<&Record> {
        self.records.get(name)
    }

    /// Applies every Registry transition in block order.
    ///
    /// Takes the upstream [`ScannedBlock`] directly, plus the supplemental
    /// [`ReceivedNameNote`] lane from the orchestrator's ZNS decryption pass;
    /// per-transaction grouping (spent nullifiers, ordinary received Ironwood
    /// notes) is read from the scanner's own structures — `nullifier_map` and
    /// `WalletTx::ironwood_outputs`, whose nullifiers the scanner already
    /// derived. Callers cannot supply a detached authorship boolean or
    /// nullifier list.
    ///
    /// All ZNS invariant checks are assertions — only the mint can create or
    /// spend Name Notes, and its assembly code prevents every violation by
    /// construction. If an assertion fires, it's a bug in the assembly path.
    pub fn apply_block<P: Parameters>(
        &self,
        params: &P,
        wallet: &Wallet,
        scanned: &ScannedBlock<AccountId>,
        name_notes: &[ReceivedNameNote],
    ) -> Self {
        let mut next = self.clone();
        let height = scanned.height();
        let mut available_registry_fees: Vec<_> = wallet
            .ironwood_notes_for(REGISTRY_ACCOUNT)
            .filter(|note| note.note.value().inner() > 0)
            .map(|note| note.nullifier)
            .collect();

        // Group the supplemental Name Note lane and the scanner's spent
        // nullifiers by txid, in one pass each.
        let mut name_notes_by_tx: BTreeMap<TxId, Vec<&ReceivedNameNote>> = BTreeMap::new();
        for note in name_notes {
            name_notes_by_tx.entry(*note.txid()).or_default().push(note);
        }
        let mut nullifiers_by_tx: BTreeMap<TxId, Vec<orchard::note::Nullifier>> =
            BTreeMap::new();
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
            let received_name_notes: &[&ReceivedNameNote] = name_notes_by_tx
                .get(&txid)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let received_ironwood = wtx.ironwood_outputs();

            let has_registry_fee_spend = ironwood_nullifiers
                .iter()
                .any(|nullifier| available_registry_fees.contains(nullifier));
            let spent_record_names: Vec<_> = next
                .records
                .iter()
                .filter_map(|(name, record)| {
                    // A record is spent when a new Name Note in this tx extends
                    // its chain — i.e., the new note's prev_rcm matches this
                    // record's commitment. This replaces nullifier matching.
                    let record_commitment = record.commitment;
                    received_name_notes
                        .iter()
                        .any(|new_note| {
                            new_note.payload().prev_rcm() == Some(record_commitment)
                        })
                        .then(|| name.clone())
                })
                .collect();

            match received_name_notes {
                [] => {
                    debug_assert!(spent_record_names.is_empty(),
                        "record commitment matched a prev_rcm but no Name Notes were received \
                         — impossible: spent_record_names is derived from received_name_notes \
                         which is empty");
                }
                notes if notes.len() > 1 => {
                    // Public output construction is not Registry authorship.
                    // Ignore attacker-created ambiguity unless this transaction
                    // also spends Registry authority.
                    if has_registry_fee_spend || !spent_record_names.is_empty() {
                        panic!("mint produced multiple Name Notes in one transaction \
                                — assembly creates exactly one");
                    }
                }
                [note] => {
                    // An unauthenticated output candidate has no namespace
                    // effect and must not make canonical block following fail.
                    if !has_registry_fee_spend && spent_record_names.is_empty() {
                        Self::advance_fee_set(
                            &mut available_registry_fees,
                            ironwood_nullifiers,
                            received_ironwood,
                        );
                        continue;
                    }
                    assert!(has_registry_fee_spend,
                        "mint transition transaction missing Registry fee-note spend \
                         — assembly always includes fee funding");

                    let payload = note.payload();
                    let name = payload.name();
                    match payload.action() {
                        Action::Claim => {
                            assert!(spent_record_names.is_empty(),
                                "claim transaction spent a record — assembly never \
                                 spends a Name Note when claiming");
                            assert!(
                                next.record(name).is_none_or(|r| r.action == Action::Release),
                                "claim attempted to replace live name {name:?} \
                                 — authorize_claim checks availability"
                            );
                        }
                        Action::Update | Action::Release => {
                            let record = next
                                .record(name)
                                .filter(|record| record.action != Action::Release)
                                .expect("update/release has no live predecessor \
                                        — assembly checks liveness before transitioning");
                            assert!(payload.prev_rcm() == Some(record.commitment),
                                "predecessor mismatch — assembly reads commitment \
                                 from the same registry");
                            assert!(spent_record_names.as_slice() == [name.clone()],
                                "update/release did not spend the exact current Name Note \
                                 — assembly spends the exact current note");
                        }
                    }

                    next.set_record(
                        name.clone(),
                        Record::from_received(params, (*note).clone(), height),
                        height,
                    );
                }
                _ => unreachable!("slice cardinality was handled above"),
            }

            Self::advance_fee_set(
                &mut available_registry_fees,
                ironwood_nullifiers,
                received_ironwood,
            );
        }

        next
    }

    fn advance_fee_set(
        available: &mut Vec<orchard::note::Nullifier>,
        spent: &[orchard::note::Nullifier],
        received: &[zcash_client_backend::wallet::WalletIronwoodOutput<AccountId>],
    ) {
        available.retain(|nullifier| !spent.contains(nullifier));
        available.extend(
            received
                .iter()
                .filter(|output| {
                    *output.account_id() == REGISTRY_ACCOUNT && output.note().0.value().inner() > 0
                })
                .filter_map(|output| output.nf().copied()),
        );
    }

    fn set_record(&mut self, name: Name, record: Record, height: BlockHeight) {
        let prev_record = self.records.insert(name.clone(), record);
        self.history.push(RegistryHistoryRecord {
            height,
            name,
            prev_record,
        });
    }

    /// Read-only iterator over all known name records. Used for diagnostics.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &Record)> {
        self.records.iter()
    }

    /// Rewinds the registry state back to the specified height (linear undo).
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
    }

    #[cfg(test)]
    pub(crate) fn set_record_for_test(
        &mut self,
        name: Name,
        action: Action,
        ua: Option<UnifiedAddress>,
        expires_at: Expiry,
        commitment: NameCommitment,
        height: BlockHeight,
        rho: orchard::note::Rho,
    ) {
        self.set_record(
            name,
            Record::for_test(action, ua, expires_at, commitment, height, rho),
            height,
        );
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}