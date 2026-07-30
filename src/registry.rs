//! Registry: the ZNS name-chain state machine, transition authorization, and
//! transaction assembly path.
//!
//! Submodules:
//! - [`authorize`] — `NameNoteRequest`, `authorize_claim`/`update`/`release`
//! - [`liquidity`] — Registry fee-note classification and top-up policy
//! - [`transaction`] — `build_transaction`, `TransparentOutput`
//! - [`signing`] — `assemble_and_sign_transaction`

pub mod authorize;
pub mod liquidity;
pub mod signing;
pub mod transaction;

// Re-export the primary public API so existing `crate::registry::` paths work.
pub use authorize::{
    authorize_claim, authorize_release, authorize_update, current_record, NameNoteRequest,
};
pub use liquidity::{
    classify_registry_ironwood_note, classify_registry_note_parts, RegistryFeeLiquidity,
    RegistryFundingPlan, RegistryNoteClass,
};
pub use signing::assemble_and_sign_transaction;
pub use transaction::{
    build_transaction, select_registry_fee_inputs, RegistryFeeInputs, TransparentOutput,
};

use crate::mint::{Action, Name, NameCommitment, REGISTRY_ACCOUNT, UnifiedAddress};
use crate::sync::{BlockOutput, ReceivedNameNote};
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use zcash_protocol::consensus::BlockHeight;

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
    pub ua: UnifiedAddress,
    pub commitment: NameCommitment,
    /// The block height at which this Name Note was confirmed.
    pub confirmed_height: BlockHeight,
    /// The note's unique identity — links to the shielded note in the wallet.
    pub rho: orchard::note::Rho,
}

impl Record {
    fn from_received(received: ReceivedNameNote, confirmed_height: BlockHeight) -> Self {
        let payload = received.payload();
        let (rcm, _) = payload.opening();
        Self {
            action: payload.action(),
            ua: payload.ua().clone(),
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
        ua: UnifiedAddress,
        commitment: NameCommitment,
        confirmed_height: BlockHeight,
        rho: orchard::note::Rho,
    ) -> Self {
        Self {
            action,
            ua,
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

/// A canonical block transaction could not advance Registry state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryApplyError {
    #[error("one transaction contained multiple validated Name Note candidates")]
    AmbiguousNameNotes,
    #[error("a Name Note transition lacked a recognized Registry fee-note spend")]
    MissingRegistryFeeSpend,
    #[error("a claim attempted to replace a live name")]
    NameAlreadyLive,
    #[error("an update or release had no live predecessor")]
    MissingLiveRecord,
    #[error("an update or release did not name the current predecessor commitment")]
    WrongPredecessor,
    #[error("an update or release did not spend the exact current Name Note")]
    MissingRecordSpend,
    #[error("a current Name Note was spent without exactly one legal successor")]
    RecordSpentWithoutSuccessor,
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

    /// Validates and simulates every Registry transition in block order.
    ///
    /// The evidence boundary takes the scanner's complete transaction and the
    /// wallet's ordinary-note state directly. Callers cannot supply a detached
    /// authorship boolean or nullifier list.
    pub fn apply_block(
        &self,
        wallet: &Wallet,
        output: &BlockOutput,
    ) -> Result<Self, RegistryApplyError> {
        let mut next = self.clone();
        let mut available_registry_fees: Vec<_> = wallet
            .ironwood_notes_for(REGISTRY_ACCOUNT)
            .filter(|note| note.note.value().inner() > 0)
            .map(|note| note.nullifier)
            .collect();

        for tx in output.transactions() {
            let has_registry_fee_spend = tx
                .ironwood_nullifiers()
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
                    tx.received_name_notes()
                        .iter()
                        .any(|new_note| new_note.payload().prev_rcm() == Some(record_commitment))
                        .then(|| name.clone())
                })
                .collect();

            match tx.received_name_notes() {
                [] => {
                    if !spent_record_names.is_empty() {
                        return Err(RegistryApplyError::RecordSpentWithoutSuccessor);
                    }
                }
                notes if notes.len() > 1 => {
                    // Public output construction is not Registry authorship.
                    // Ignore attacker-created ambiguity unless this transaction
                    // also spends Registry authority.
                    if has_registry_fee_spend || !spent_record_names.is_empty() {
                        return Err(RegistryApplyError::AmbiguousNameNotes);
                    }
                }
                [note] => {
                    // An unauthenticated output candidate has no namespace
                    // effect and must not make canonical block following fail.
                    if !has_registry_fee_spend && spent_record_names.is_empty() {
                        Self::advance_fee_set(
                            &mut available_registry_fees,
                            tx.ironwood_nullifiers(),
                            tx.received_ironwood(),
                        );
                        continue;
                    }
                    if !has_registry_fee_spend {
                        return Err(RegistryApplyError::MissingRegistryFeeSpend);
                    }

                    let payload = note.payload();
                    let name = payload.name();
                    match payload.action() {
                        Action::Claim => {
                            if !spent_record_names.is_empty() {
                                return Err(RegistryApplyError::RecordSpentWithoutSuccessor);
                            }
                            if next
                                .record(name)
                                .is_some_and(|record| record.action != Action::Release)
                            {
                                return Err(RegistryApplyError::NameAlreadyLive);
                            }
                        }
                        Action::Update | Action::Release => {
                            let record = next
                                .record(name)
                                .filter(|record| record.action != Action::Release)
                                .ok_or(RegistryApplyError::MissingLiveRecord)?;
                            if payload.prev_rcm() != Some(record.commitment) {
                                return Err(RegistryApplyError::WrongPredecessor);
                            }
                            if spent_record_names.as_slice() != [name.clone()] {
                                return Err(RegistryApplyError::MissingRecordSpend);
                            }
                        }
                    }

                    next.set_record(
                        name.clone(),
                        Record::from_received(note.clone(), output.metadata().block_height()),
                        output.metadata().block_height(),
                    );
                }
                _ => unreachable!("slice cardinality was handled above"),
            }

            Self::advance_fee_set(
                &mut available_registry_fees,
                tx.ironwood_nullifiers(),
                tx.received_ironwood(),
            );
        }

        Ok(next)
    }

    fn advance_fee_set(
        available: &mut Vec<orchard::note::Nullifier>,
        spent: &[orchard::note::Nullifier],
        received: &[crate::sync::ReceivedIronwood],
    ) {
        available.retain(|nullifier| !spent.contains(nullifier));
        available.extend(
            received
                .iter()
                .filter(|note| note.account_id == REGISTRY_ACCOUNT && note.note.value().inner() > 0)
                .map(|note| note.nullifier),
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
        ua: UnifiedAddress,
        commitment: NameCommitment,
        height: BlockHeight,
        rho: orchard::note::Rho,
    ) {
        self.set_record(name, Record::for_test(action, ua, commitment, height, rho), height);
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}