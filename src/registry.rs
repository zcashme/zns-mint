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
    authorize_claim, authorize_release, authorize_update, current_tip, NameNoteRequest,
};
pub use liquidity::{
    classify_registry_ironwood_note, classify_registry_note_parts, RegistryFeeLiquidity,
    RegistryFundingPlan, RegistryNoteClass,
};
pub use signing::assemble_and_sign_transaction;
pub use transaction::{
    build_transaction, select_registry_fee_inputs, RegistryFeeInputs, TransparentOutput,
};

use crate::mint::{Action, Name, NameCommitment, REGISTRY_ACCOUNT};
use crate::sync::{BlockOutput, ReceivedNameNote};
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use zcash_protocol::consensus::BlockHeight;

// ---------------------------------------------------------------------------
// Tip — the current state of a name chain
// ---------------------------------------------------------------------------

/// The current state of a name chain.
///
/// Production tips are constructed only from a scanner-validated Name Note.
/// The duplicated public view fields are derived from that retained note at
/// construction and exist so authorization code cannot access memo plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct Tip {
    pub action: Action,
    pub commitment: NameCommitment,
    /// Canonical height at which this Name Note became the live tip.
    pub confirmed_height: BlockHeight,
    received: Option<ReceivedNameNote>,
}

impl Tip {
    fn from_received(received: ReceivedNameNote, confirmed_height: BlockHeight) -> Self {
        let payload = received.payload();
        let (rcm, _) = payload.opening();
        Self {
            action: payload.action(),
            commitment: NameCommitment::from_inner(orchard::note::NoteCommitTrapdoor::from_inner(
                rcm,
            )),
            confirmed_height,
            received: Some(received),
        }
    }

    /// The exact validated note and chain locator needed to spend this tip.
    pub fn received(&self) -> Option<&ReceivedNameNote> {
        self.received.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        action: Action,
        commitment: NameCommitment,
        confirmed_height: BlockHeight,
    ) -> Self {
        Self {
            action,
            commitment,
            confirmed_height,
            received: None,
        }
    }
}

impl std::fmt::Debug for Tip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tip")
            .field("action", &self.action)
            .field("commitment", &self.commitment)
            .field("name_note", &self.received.as_ref().map(|_| "<validated>"))
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
    MissingLiveTip,
    #[error("an update or release did not name the current predecessor commitment")]
    WrongPredecessor,
    #[error("an update or release did not spend the exact current Name Note")]
    MissingTipSpend,
    #[error("a current Name Note was spent without exactly one legal successor")]
    TipSpentWithoutSuccessor,
}

// ---------------------------------------------------------------------------
// Registry — name-chain state with reorg undo
// ---------------------------------------------------------------------------

/// An undo-log entry: records what the tip was before a `set_tip` so a reorg
/// can rewind the registry to a prior height.
#[derive(Debug, Clone)]
pub struct RegistryHistoryRecord {
    pub height: BlockHeight,
    pub name: Name,
    pub prev_tip: Option<Tip>,
}

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed tip for that name, plus an undo log for reorgs.
#[derive(Clone)]
pub struct Registry {
    tips: BTreeMap<Name, Tip>,
    history: Vec<RegistryHistoryRecord>,
}

impl Registry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            tips: BTreeMap::new(),
            history: Vec::new(),
        }
    }

    /// Read the current tip of a ZNS name chain.
    pub fn tip(&self, name: &Name) -> Option<&Tip> {
        self.tips.get(name)
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
            let spent_tip_names: Vec<_> = next
                .tips
                .iter()
                .filter_map(|(name, tip)| {
                    // A tip is spent when a new Name Note in this tx extends its
                    // chain — i.e., the new note's prev_rcm matches this tip's
                    // commitment. This replaces nullifier matching.
                    let tip_commitment = tip.commitment;
                    tx.received_name_notes()
                        .iter()
                        .any(|new_note| new_note.payload().prev_rcm() == Some(tip_commitment))
                        .then(|| name.clone())
                })
                .collect();

            match tx.received_name_notes() {
                [] => {
                    if !spent_tip_names.is_empty() {
                        return Err(RegistryApplyError::TipSpentWithoutSuccessor);
                    }
                }
                notes if notes.len() > 1 => {
                    // Public output construction is not Registry authorship.
                    // Ignore attacker-created ambiguity unless this transaction
                    // also spends Registry authority.
                    if has_registry_fee_spend || !spent_tip_names.is_empty() {
                        return Err(RegistryApplyError::AmbiguousNameNotes);
                    }
                }
                [note] => {
                    // An unauthenticated output candidate has no namespace
                    // effect and must not make canonical block following fail.
                    if !has_registry_fee_spend && spent_tip_names.is_empty() {
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
                            if !spent_tip_names.is_empty() {
                                return Err(RegistryApplyError::TipSpentWithoutSuccessor);
                            }
                            if next
                                .tip(name)
                                .is_some_and(|tip| tip.action != Action::Release)
                            {
                                return Err(RegistryApplyError::NameAlreadyLive);
                            }
                        }
                        Action::Update | Action::Release => {
                            let tip = next
                                .tip(name)
                                .filter(|tip| tip.action != Action::Release)
                                .ok_or(RegistryApplyError::MissingLiveTip)?;
                            if payload.prev_rcm() != Some(tip.commitment) {
                                return Err(RegistryApplyError::WrongPredecessor);
                            }
                            if spent_tip_names.as_slice() != [name.clone()] {
                                return Err(RegistryApplyError::MissingTipSpend);
                            }
                        }
                    }

                    next.set_tip(
                        name.clone(),
                        Tip::from_received(note.clone(), output.metadata().block_height()),
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

    fn set_tip(&mut self, name: Name, tip: Tip, height: BlockHeight) {
        let prev_tip = self.tips.insert(name.clone(), tip);
        self.history.push(RegistryHistoryRecord {
            height,
            name,
            prev_tip,
        });
    }

    /// Read-only iterator over all known name tips. Used for diagnostics.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &Tip)> {
        self.tips.iter()
    }

    /// Rewinds the registry state back to the specified height (linear undo).
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        while let Some(record) = self.history.last() {
            if record.height <= height {
                break;
            }
            let record = self.history.pop().unwrap();
            match record.prev_tip {
                Some(old_tip) => {
                    self.tips.insert(record.name, old_tip);
                }
                None => {
                    self.tips.remove(&record.name);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn set_tip_for_test(
        &mut self,
        name: Name,
        action: Action,
        commitment: NameCommitment,
        height: BlockHeight,
    ) {
        self.set_tip(name, Tip::for_test(action, commitment, height), height);
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}