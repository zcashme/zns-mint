//! ZNS mint wallet.
//!
pub mod balance;
pub mod selection;
pub mod transaction;
pub mod trees;

use std::collections::BTreeMap;

use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zip32::AccountId;

use crate::sync::BlockOutput;
use crate::zcash::CheckpointData;
use balance::WalletBalance;
use transaction::{
    ReceivedIronwoodNote, ReceivedOrchardNote, ReceivedSaplingNote, SpentIronwoodNote,
    SpentOrchardNote, SpentSaplingNote, TransactionRecord,
};
use trees::ShardTrees;

/// The in-memory ZNS wallet engine: a notes table and a tree.
pub struct Wallet {
    // Identity / scanning inputs (read-only after boot).
    ufvk_map: BTreeMap<AccountId, UnifiedFullViewingKey>,

    // Tracks unspent notes and spent nullifiers. Private so all mutation
    // flows through `Wallet` methods and can be kept in sync with `trees`.
    balance: WalletBalance,

    // The running commitment trees for Orchard and Sapling. Private for the
    // same reason as `balance`: must stay in sync with the note set.
    trees: ShardTrees,
}

impl Wallet {
    /// Create a new, empty wallet.
    pub fn new(ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>) -> Self {
        Self {
            ufvk_map: ufvks.into_iter().collect(),
            balance: WalletBalance::new(),
            trees: ShardTrees::new(),
        }
    }

    /// Read-only access to an account's unified full viewing key.
    /// Used by the scanner to derive IVKs for trial decryption.
    pub fn ufvk_for(&self, account: AccountId) -> Option<&UnifiedFullViewingKey> {
        self.ufvk_map.get(&account)
    }

    /// Seeds the commitment trees from the birthday checkpoint.
    ///
    /// Called once at boot after [`Wallet::new`]. Converts each
    /// `CommitmentTree` from `z_gettreestate` into a `Frontier` and inserts
    /// it as a checkpoint at `birthday_height`.
    pub fn seed_trees(&mut self, checkpoint: &CheckpointData, birthday_height: BlockHeight) {
        // Sapling
        let sapling_frontier = checkpoint.sapling_tree.to_frontier();
        self.trees
            .insert_sapling_frontier(sapling_frontier, birthday_height)
            .expect("FATAL: failed to seed Sapling commitment tree from checkpoint");

        // Orchard
        let orchard_frontier = checkpoint.orchard_tree.to_frontier();
        self.trees
            .insert_orchard_frontier(orchard_frontier, birthday_height)
            .expect("FATAL: failed to seed Orchard commitment tree from checkpoint");

        let ironwood_frontier = ironwood_frontier(checkpoint);
        self.trees
            .insert_ironwood_frontier(ironwood_frontier, birthday_height)
            .expect("FATAL: failed to seed Ironwood commitment tree from checkpoint");
        tracing::info!(
            "wallet: Ironwood commitment tree seeded at height {}",
            u32::from(birthday_height)
        );
    }

    pub fn orchard_notes_for(
        &self,
        account: AccountId,
    ) -> impl Iterator<Item = &crate::wallet::transaction::ReceivedOrchardNote> {
        self.balance
            .unspent
            .orchard
            .get(&account)
            .into_iter()
            .flat_map(|m| m.values())
    }

    pub fn sapling_notes_for(
        &self,
        account: AccountId,
    ) -> impl Iterator<Item = &crate::wallet::transaction::ReceivedSaplingNote> {
        self.balance
            .unspent
            .sapling
            .get(&account)
            .into_iter()
            .flat_map(|m| m.values())
    }

    pub fn ironwood_notes_for(
        &self,
        account: AccountId,
    ) -> impl Iterator<Item = &ReceivedIronwoodNote> {
        self.balance
            .unspent
            .ironwood
            .get(&account)
            .into_iter()
            .flat_map(|m| m.values())
    }

    pub fn balance(&self, account: AccountId) -> Zatoshis {
        let orchard_val: u64 = self
            .balance
            .unspent
            .orchard
            .get(&account)
            .map(|m| m.values().map(|n| n.note.value().inner()).sum())
            .unwrap_or(0);
        let ironwood_val: u64 = self
            .balance
            .unspent
            .ironwood
            .get(&account)
            .map(|m| m.values().map(|n| n.note.value().inner()).sum())
            .unwrap_or(0);
        let sapling_val: u64 = self
            .balance
            .unspent
            .sapling
            .get(&account)
            .map(|m| m.values().map(|n| n.note.value().inner()).sum())
            .unwrap_or(0);
        Zatoshis::from_u64(orchard_val + ironwood_val + sapling_val).unwrap()
    }

    pub fn orchard_anchor(
        &mut self,
        height: BlockHeight,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, trees::TreeError> {
        self.trees.orchard_anchor(height)
    }

    pub fn orchard_witness(
        &mut self,
        position: incrementalmerkletree::Position,
        height: BlockHeight,
    ) -> Result<
        Option<incrementalmerkletree::MerklePath<orchard::tree::MerkleHashOrchard, 32>>,
        trees::TreeError,
    > {
        self.trees.orchard_witness(position, height)
    }

    pub fn ironwood_anchor(
        &mut self,
        height: BlockHeight,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, trees::TreeError> {
        self.trees.ironwood_anchor(height)
    }

    pub fn ironwood_witness(
        &mut self,
        position: incrementalmerkletree::Position,
        height: BlockHeight,
    ) -> Result<
        Option<incrementalmerkletree::MerklePath<orchard::tree::MerkleHashOrchard, 32>>,
        trees::TreeError,
    > {
        self.trees.ironwood_witness(position, height)
    }

    /// Applies a scanned block to the wallet: converts `BlockOutput` into
    /// `TransactionRecord`s, appends commitments to `ShardTree`s, and updates
    /// the balance.
    ///
    /// Called by the orchestrator after `scan_block` returns. This is the
    /// connective tissue between the pure scanner and the wallet's mutable state.
    pub fn apply_block(&mut self, output: &BlockOutput) {
        let height = output.height;

        // 1. Build TransactionRecords and apply to balance, per-tx in order.
        for tx in &output.transactions {
            // Look up original notes for spent nullifiers BEFORE
            // add_transaction removes them from the unspent set.
            let spent_orchard: Vec<_> = tx
                .spent_orchard
                .iter()
                .filter_map(|s| {
                    self.balance
                        .get_orchard_note_by_nf(&s.nullifier)
                        .map(|note| SpentOrchardNote {
                            account_id: s.account_id,
                            nullifier: s.nullifier,
                            original_note: note.clone(),
                        })
                })
                .collect();

            let spent_sapling: Vec<_> = tx
                .spent_sapling
                .iter()
                .filter_map(|s| {
                    self.balance
                        .get_sapling_note_by_nf(&s.nullifier)
                        .map(|note| SpentSaplingNote {
                            account_id: s.account_id,
                            nullifier: s.nullifier,
                            original_note: note.clone(),
                        })
                })
                .collect();

            let spent_ironwood: Vec<_> = tx
                .spent_ironwood
                .iter()
                .filter_map(|s| {
                    self.balance
                        .get_ironwood_note_by_nf(&s.nullifier)
                        .map(|note| SpentIronwoodNote {
                            account_id: s.account_id,
                            nullifier: s.nullifier,
                            original_note: note.clone(),
                        })
                })
                .collect();

            // Convert received notes, adding confirmed_height.
            let received_orchard: Vec<_> = tx
                .received_orchard
                .iter()
                .map(|r| ReceivedOrchardNote {
                    account_id: r.account_id,
                    note: r.note,
                    nullifier: r.nullifier,
                    memo: r.memo.clone(),
                    position: r.position,
                    confirmed_height: height,
                })
                .collect();

            let received_sapling: Vec<_> = tx
                .received_sapling
                .iter()
                .map(|r| ReceivedSaplingNote {
                    account_id: r.account_id,
                    note: r.note.clone(),
                    nullifier: r.nullifier,
                    memo: r.memo.clone(),
                    position: r.position,
                    confirmed_height: height,
                })
                .collect();

            let received_ironwood: Vec<_> = tx
                .received_ironwood
                .iter()
                .map(|r| ReceivedIronwoodNote {
                    account_id: r.account_id,
                    note: r.note,
                    nullifier: r.nullifier,
                    memo: r.memo.clone(),
                    position: r.position,
                    confirmed_height: height,
                })
                .collect();

            let record = TransactionRecord {
                txid: tx.txid,
                block_height: height,
                received_orchard,
                received_sapling,
                received_ironwood,
                spent_orchard,
                spent_sapling,
                spent_ironwood,
            };

            self.balance.add_transaction(&record);
        }

        // 2. Append all commitments to ShardTrees for Merkle witness integrity.
        for (cmx, retention) in &output.orchard_commitments {
            self.trees
                .append_orchard(*cmx, *retention)
                .expect("FATAL: failed to append Orchard commitment");
        }
        for (node, retention) in &output.sapling_commitments {
            self.trees
                .append_sapling(*node, *retention)
                .expect("FATAL: failed to append Sapling commitment");
        }
        for (cmx, retention) in &output.ironwood_commitments {
            self.trees
                .append_ironwood(*cmx, *retention)
                .expect("FATAL: failed to append Ironwood commitment");
        }
    }
}

#[cfg(not(feature = "pre-nu63-activation"))]
fn ironwood_frontier(
    checkpoint: &CheckpointData,
) -> incrementalmerkletree::frontier::Frontier<
    orchard::tree::MerkleHashOrchard,
    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
> {
    checkpoint
        .ironwood_tree
        .as_ref()
        .expect("FATAL: NU6.3 active but checkpoint has no Ironwood tree")
        .to_frontier()
}

#[cfg(feature = "pre-nu63-activation")]
fn ironwood_frontier(
    checkpoint: &CheckpointData,
) -> incrementalmerkletree::frontier::Frontier<
    orchard::tree::MerkleHashOrchard,
    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
> {
    checkpoint
        .ironwood_tree
        .as_ref()
        .map(|tree| tree.to_frontier())
        .unwrap_or_else(incrementalmerkletree::frontier::Frontier::empty)
}
