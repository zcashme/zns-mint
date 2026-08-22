//! In-memory wallet database for the ZNS mint.

mod input;
mod read;
mod trees;
mod write;

use std::collections::{BTreeMap, BTreeSet};

use incrementalmerkletree::{frontier::Frontier, Address};
use shardtree::{store::memory::MemoryShardStore, ShardTree};
use transparent::bundle::OutPoint;
use zcash_client_backend::{
    data_api::locking::LockOwner,
    data_api::{
        BlockMetadata, SentTransactionOutput, TransactionStatus, ORCHARD_SHARD_HEIGHT,
        SAPLING_SHARD_HEIGHT,
    },
    wallet::{
        NoteId, OutputRef, WalletIronwoodOutput, WalletSaplingOutput, WalletTransparentOutput,
    },
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    consensus::{BlockHeight, TxIndex},
    memo::Memo,
};
use zip32::AccountId;

/// The in-memory backing store for the two fixed mint accounts.
///
/// The values are the current upstream wallet/scanner values. The wallet is a
/// disposable projection of the Zebra chain; it deliberately has no scan queue
/// or mutable account registry.
pub struct Wallet {
    /// Exactly account 0 (Treasury) and account 1 (Registry).
    ufvks: BTreeMap<AccountId, UnifiedFullViewingKey>,

    /// The Zebra consensus tip last supplied through `WalletWrite::update_chain_tip`.
    last_zebra_tip: Option<BlockHeight>,

    /// Canonical Zebra blocks this in-memory projection has applied.
    blocks: BTreeMap<BlockHeight, BlockMetadata>,

    transactions: BTreeMap<TxId, Transaction>,
    transaction_statuses: BTreeMap<TxId, TransactionStatus>,
    transaction_indices: BTreeMap<TxId, TxIndex>,

    /// Transactions whose outputs are trusted at the ZIP 315 "trusted"
    /// confirmation depth, set via `WalletWrite::set_tx_trust`.
    trusted_transactions: BTreeSet<TxId>,

    sapling_notes: BTreeMap<NoteId, WalletSaplingOutput<AccountId>>,
    ironwood_notes: BTreeMap<NoteId, WalletIronwoodOutput<AccountId>>,
    memos: BTreeMap<NoteId, Memo>,

    sapling_note_spends: BTreeMap<NoteId, TxId>,
    ironwood_note_spends: BTreeMap<NoteId, TxId>,
    sapling_nullifiers: BTreeMap<sapling::Nullifier, NoteId>,
    ironwood_nullifiers: BTreeMap<orchard::note::Nullifier, NoteId>,

    sent_outputs: BTreeMap<TxId, Vec<SentTransactionOutput<AccountId>>>,

    transparent_outputs: BTreeMap<OutPoint, WalletTransparentOutput<AccountId>>,
    transparent_output_spends: BTreeMap<OutPoint, TxId>,
    transparent_spends: BTreeSet<(TxId, OutPoint)>,

    /// Advisory locks use upstream `OutputRef` and `LockOwner` values directly.
    locks: BTreeMap<OutputRef, (LockOwner, BlockHeight)>,

    sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { sapling::NOTE_COMMITMENT_TREE_DEPTH },
        SAPLING_SHARD_HEIGHT,
    >,
    sapling_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
    orchard_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    ironwood_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
    ironwood_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
}

impl Wallet {
    /// Creates the database for the boot-established Treasury and Registry UFVKs.
    pub fn new(ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>) -> Self {
        Self {
            ufvks: ufvks.into_iter().collect(),
            last_zebra_tip: None,
            blocks: BTreeMap::new(),
            transactions: BTreeMap::new(),
            transaction_statuses: BTreeMap::new(),
            transaction_indices: BTreeMap::new(),
            trusted_transactions: BTreeSet::new(),
            sapling_notes: BTreeMap::new(),
            ironwood_notes: BTreeMap::new(),
            memos: BTreeMap::new(),
            sapling_note_spends: BTreeMap::new(),
            ironwood_note_spends: BTreeMap::new(),
            sapling_nullifiers: BTreeMap::new(),
            ironwood_nullifiers: BTreeMap::new(),
            sent_outputs: BTreeMap::new(),
            transparent_outputs: BTreeMap::new(),
            transparent_output_spends: BTreeMap::new(),
            transparent_spends: BTreeSet::new(),
            locks: BTreeMap::new(),
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), 101),
            sapling_tree_shard_end_heights: BTreeMap::new(),
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), 101),
            orchard_tree_shard_end_heights: BTreeMap::new(),
            ironwood_tree: ShardTree::new(MemoryShardStore::empty(), 101),
            ironwood_tree_shard_end_heights: BTreeMap::new(),
        }
    }

    /// Returns the fixed account UFVKs for scanner construction.
    pub fn ufvk_map(&self) -> &BTreeMap<AccountId, UnifiedFullViewingKey> {
        &self.ufvks
    }

    /// Returns the viewing key of one fixed mint account.
    pub fn ufvk_for(&self, account: AccountId) -> Option<&UnifiedFullViewingKey> {
        self.ufvks.get(&account)
    }

    /// Seeds all three commitment trees from the verified Zebra checkpoint.
    ///
    /// The checkpoint height is chain state, not an account birthday.
    pub fn seed_trees(
        &mut self,
        sapling_frontier: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>,
        orchard_frontier: Frontier<orchard::tree::MerkleHashOrchard, 32>,
        ironwood_frontier: Frontier<orchard::tree::MerkleHashOrchard, 32>,
        checkpoint_height: BlockHeight,
    ) -> Result<(), shardtree::error::ShardTreeError<std::convert::Infallible>> {
        let retention = incrementalmerkletree::Retention::Checkpoint {
            id: checkpoint_height,
            marking: incrementalmerkletree::Marking::Reference,
        };
        self.sapling_tree
            .insert_frontier(sapling_frontier, retention)?;
        self.orchard_tree
            .insert_frontier(orchard_frontier, retention)?;
        self.ironwood_tree
            .insert_frontier(ironwood_frontier, retention)?;
        Ok(())
    }
}

const _: () = {
    assert!(sapling::NOTE_COMMITMENT_TREE_DEPTH == SAPLING_SHARD_HEIGHT * 2);
    assert!(32 == ORCHARD_SHARD_HEIGHT * 2);
};
