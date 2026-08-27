//! Ironwood wallet queries used by transaction assembly.
//!
//! Assembly consumes LRZ [`ReceivedNote`] and [`NoteId`] values directly.
//! This module provides only the wallet-specific lookups that LRZ's generic
//! traits cannot express: finding an owned note by a ZNS record's `rho`, and
//! retrieving the unspent Registry fee-note nullifiers.

use incrementalmerkletree::{MerklePath, Position};
use zcash_client_backend::data_api::{ScannedBlock, WalletCommitmentTrees};
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_primitives::transaction::TxId;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;
use zcash_protocol::value::Zatoshis;
use zip32::AccountId;

use crate::mint::REGISTRY_ACCOUNT;

use super::{TreeError, Wallet};

impl Wallet {
    /// Returns every unspent Ironwood note owned by `account`.
    pub fn unspent_ironwood_notes(
        &self,
        account: AccountId,
    ) -> Vec<ReceivedNote<NoteId, orchard::note::Note>> {
        self.ironwood_notes
            .iter()
            .filter(move |(_, output)| *output.account_id() == account)
            .filter(|(note_id, _)| !self.ironwood_note_spends.contains_key(note_id))
            .filter_map(|(note_id, _)| self.ironwood_received_note(*note_id))
            .collect()
    }

    /// Returns one unspent Ironwood note by its LRZ wallet identity.
    pub(crate) fn unspent_ironwood_note(
        &self,
        account: AccountId,
        note_id: NoteId,
    ) -> Option<ReceivedNote<NoteId, orchard::note::Note>> {
        let output = self.ironwood_notes.get(&note_id)?;
        (*output.account_id() == account && !self.ironwood_note_spends.contains_key(&note_id))
            .then(|| self.ironwood_received_note(note_id))
            .flatten()
    }

    /// Finds an unspent owned Ironwood note by the `rho` persisted in a ZNS
    /// record, returning its native LRZ wallet representation.
    pub(crate) fn unspent_ironwood_note_by_rho(
        &self,
        account: AccountId,
        rho: orchard::note::Rho,
    ) -> Option<ReceivedNote<NoteId, orchard::note::Note>> {
        let note_id = self
            .ironwood_notes
            .iter()
            .find(|(_, output)| {
                *output.account_id() == account && output.note().0.rho() == rho
            })
            .map(|(note_id, _)| *note_id)?;
        self.unspent_ironwood_note(account, note_id)
    }

    /// Returns the nullifiers of all unspent Ironwood notes owned by `account`.
    pub(crate) fn unspent_ironwood_nullifiers(
        &self,
        account: AccountId,
    ) -> Vec<orchard::note::Nullifier> {
        self.ironwood_notes
            .iter()
            .filter(|(note_id, output)| {
                *output.account_id() == account
                    && !self.ironwood_note_spends.contains_key(note_id)
            })
            .filter_map(|(note_id, output)| {
                (self
                    .ironwood_received_note(*note_id)?
                    .note_value()
                    .ok()? > Zatoshis::ZERO)
                    .then(|| output.nf().copied())
                    .flatten()
            })
            .collect()
    }

    /// The Ironwood witness at `anchor_height` for the note at `position`.
    ///
    /// `Ok(None)` means no witness exists yet at that checkpoint (note not
    /// yet observed under that anchor); errors are tree-structural.
    pub(crate) fn ironwood_witness(
        &mut self,
        position: Position,
        anchor_height: BlockHeight,
    ) -> Result<Option<MerklePath<orchard::tree::MerkleHashOrchard, 32>>, TreeError> {
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

    /// Stores one decrypted ZNS Name Note as the Registry account's ordinary
    /// received Ironwood note, at its consensus-derived tree position.
    ///
    /// The standard scanning lane cannot see Name Notes (its domain re-derives
    /// the commitment from rseed and rejects the ZNS-derived cmx), so the
    /// orchestrator's ZNS pass supplies them here. Storage mirrors
    /// `put_blocks`: note table + memo + mined status. `ordinal` is the
    /// action's index in the block's full Ironwood commitment stream.
    pub fn store_name_note(
        &mut self,
        scanned: &ScannedBlock<AccountId>,
        ordinal: usize,
        txid: TxId,
        action_index: usize,
        note: orchard::note::Note,
        ephemeral_key: zcash_note_encryption::EphemeralKeyBytes,
        memo: [u8; 512],
    ) -> Option<()> {
        let fvk = self.ufvks.get(&REGISTRY_ACCOUNT)?.orchard()?.clone();
        let bundles = scanned.ironwood();
        let start_size = bundles
            .final_tree_size()
            .checked_sub(u32::try_from(bundles.commitments().len()).ok()?)?;
        let position = Position::from(u64::from(start_size) + ordinal as u64);
        let note_id = NoteId::new(txid, ShieldedPool::Ironwood, u16::try_from(action_index).ok()?);
        self.ironwood_notes.insert(
            note_id,
            zcash_client_backend::wallet::WalletIronwoodOutput::from_parts(
                action_index,
                ephemeral_key,
                (note.clone(), orchard::ValuePool::Ironwood),
                false,
                position,
                Some(note.nullifier(&fvk)),
                REGISTRY_ACCOUNT,
                Some(zip32::Scope::External),
            ),
        );
        self.ironwood_nullifiers
            .insert(note.nullifier(&fvk), note_id);
        self.memos.insert(
            note_id,
            Memo::Future(
                zcash_protocol::memo::MemoBytes::from_bytes(&memo)
                    .expect("512-byte memo always parses"),
            ),
        );
        self.transaction_statuses
            .insert(txid, zcash_client_backend::data_api::TransactionStatus::Mined(scanned.height()));
        Some(())
    }
}
