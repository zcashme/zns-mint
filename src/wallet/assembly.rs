//! Assembly-slice wallet projections.
//!
//! The transaction-assembly paths (Registry lifecycle, Treasury relay, claim
//! settlement) address wallet notes by capability, not by storage key:
//! [`NoteLocator`] names exactly one wallet Ironwood note as
//! `(account, rho)`, and [`IronwoodNote`] is the assembled projection the
//! builders consume — note, position, memo, nullifier — drawn from the
//! wallet's ordinary received-note state. Nullifiers are derived here (not
//! stored) via the account's Orchard-family viewing key, mirroring the
//! scanner's own derivation.

use incrementalmerkletree::{MerklePath, Position};
use zcash_client_backend::data_api::WalletCommitmentTrees;
use zcash_client_backend::wallet::NoteId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;
use zip32::AccountId;

use super::{TreeError, Wallet};

/// The witness path type produced by the Ironwood shard tree.
pub type IronwoodWitness =
    MerklePath<orchard::tree::MerkleHashOrchard, 32>;

/// A capability handle to one wallet Ironwood note: `(account, rho)`.
///
/// `rho` is the note's unique identity across all pools; pairing it with the
/// owning account makes the locator total over the wallet's fixed accounts.
/// `Copy + Ord + Hash` so it can serve as a reservation-set key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoteLocator {
    account_id: AccountId,
    rho: orchard::note::Rho,
}

impl NoteLocator {
    /// Locates the Ironwood note `rho` received by `account_id`.
    pub fn ironwood(account_id: AccountId, rho: orchard::note::Rho) -> Self {
        Self { account_id, rho }
    }

    pub fn account(&self) -> AccountId {
        self.account_id
    }

    pub fn rho(&self) -> orchard::note::Rho {
        self.rho
    }
}

/// The assembled projection of one unspent wallet Ironwood note.
///
/// Built by [`Wallet::ironwood_note`] / [`Wallet::ironwood_notes_for`] from
/// the received-note table; `nullifier` is derived through the account's
/// Orchard FVK at projection time.
#[derive(Clone, Debug)]
pub struct IronwoodNote {
    /// The owning wallet account (Treasury or Registry).
    pub account_id: AccountId,
    /// The decrypted note — recipient, value, rho, rseed.
    pub note: orchard::note::Note,
    /// The note's position in the Ironwood commitment tree.
    pub position: Position,
    /// The stored memo as canonical 512 bytes (ZIP-302 padding when the
    /// memo slot holds a non-bytes memo).
    pub memo: [u8; 512],
    /// The spend nullifier, derived from the account FVK.
    pub nullifier: orchard::note::Nullifier,
}

impl Wallet {
    /// Projects one unspent Ironwood note by locator, or `None` when the
    /// wallet has no such unspent note.
    pub(crate) fn ironwood_note(&self, locator: NoteLocator) -> Option<IronwoodNote> {
        self.locate_ironwood(locator)
    }

    /// Projects every unspent Ironwood note of `account`, oldest-first by
    /// commitment tree position.
    pub(crate) fn ironwood_notes_for(
        &self,
        account: AccountId,
    ) -> impl Iterator<Item = IronwoodNote> + '_ {
        self.ironwood_notes
            .iter()
            .filter(move |(_, output)| *output.account_id() == account)
            .filter(|(note_id, _)| !self.ironwood_note_spends.contains_key(note_id))
            .filter_map(|(note_id, output)| self.project_ironwood(*note_id, output))
    }

    /// Whether the wallet holds the located note and it is unspent.
    pub(crate) fn contains_unspent_locator(&self, locator: NoteLocator) -> bool {
        self.locate_ironwood(locator).is_some()
    }

    /// The Ironwood witness at `anchor_height` for the note at `position`.
    ///
    /// `Ok(None)` means no witness exists yet at that checkpoint (note not
    /// yet observed under that anchor); errors are tree-structural.
    pub(crate) fn ironwood_witness(
        &mut self,
        position: Position,
        anchor_height: BlockHeight,
    ) -> Result<Option<IronwoodWitness>, TreeError> {
        // with_ironwood_tree_mut wraps the callback's Ok payload in an
        // outer Option; `?` then flatten collapses both layers.
        let witnessed = self
            .with_ironwood_tree_mut(|tree| {
                tree.witness_at_checkpoint_id_caching(position, &anchor_height)
            })
            .map_err(|e| e)?;
        Ok(witnessed.flatten())
    }

    /// The Ironwood tree root at `anchor_height` as an Orchard-family
    /// anchor for the builder.
    pub(crate) fn ironwood_anchor(
        &mut self,
        anchor_height: BlockHeight,
    ) -> Result<Option<orchard::tree::Anchor>, TreeError> {
        let root = self
            .with_ironwood_tree_mut(|tree| tree.root_at_checkpoint_id(&anchor_height))
            .map_err(|e| e)?;
        Ok(root.flatten().map(Into::into))
    }

    // -- internals ----------------------------------------------------------

    fn locate_ironwood(&self, locator: NoteLocator) -> Option<IronwoodNote> {
        self.ironwood_notes
            .iter()
            .find(|(_, output)| {
                *output.account_id() == locator.account_id
                    && output.note().0.rho() == locator.rho
            })
            .filter(|(note_id, _)| !self.ironwood_note_spends.contains_key(note_id))
            .and_then(|(note_id, output)| self.project_ironwood(*note_id, output))
    }

    fn project_ironwood(
        &self,
        note_id: NoteId,
        output: &zcash_client_backend::wallet::WalletIronwoodOutput<AccountId>,
    ) -> Option<IronwoodNote> {
        let fvk = self
            .ufvks
            .get(output.account_id())?
            .orchard()?
            .clone();
        let note = output.note().0.clone();
        let memo = match self.memos.get(&note_id) {
            Some(Memo::Future(bytes)) => *bytes.as_array(),
            Some(Memo::Arbitrary(bytes)) => {
                let mut raw = [0u8; 512];
                raw[0] = 0xFF;
                raw[1..512].copy_from_slice(&bytes[..]);
                raw
            }
            _ => {
                // Empty and Text memos are not part of any mint protocol
                // lane; project them as the ZIP-302 empty memo.
                let mut empty = [0u8; 512];
                empty[0] = 0xF6;
                empty
            }
        };
        Some(IronwoodNote {
            account_id: *output.account_id(),
            nullifier: note.nullifier(&fvk),
            note,
            position: output.note_commitment_tree_position(),
            memo,
        })
    }
}
