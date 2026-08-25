//! In-memory wallet database for the ZNS mint.

mod assembly;
mod input;
mod read;
mod trees;
mod write;

pub use assembly::{IronwoodNote, NoteLocator};

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use incrementalmerkletree::{Address, Marking, Retention};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use transparent::bundle::OutPoint;
use zcash_client_backend::{
    data_api::locking::LockOwner,
    data_api::{BlockMetadata, SentTransactionOutput, TransactionStatus},
    data_api::chain::ChainState,
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

/// Depth of the Sapling note commitment tree,
const SAPLING_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;

/// Depth of the Orchard and Ironwood note commitment tree;
const ORCHARD_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;

/// Shard height of the Sapling note commitment tree;
const SAPLING_SHARD_HEIGHT: u8 = 16;

/// Shard height of the Orchard and Ironwood note commitment trees;
const ORCHARD_SHARD_HEIGHT: u8 = 16;

/// Maximum checkpoints retained per note commitment tree. Matches upstream
/// `zcash_client_sqlite::PRUNING_DEPTH`. Checkpoints pinned via `ensure_retained`
/// (e.g. for ZIP-318 anchor retention) are exempt from this cap.
const MAX_CHECKPOINTS: usize = 100;

/// Shard-tree error over the infallible in-memory store: only tree-structural
/// failures (`Query`, `Insert`) are reachable, never storage failures.
type TreeError = ShardTreeError<Infallible>;

/// The in-memory wallet for the two fixed mint accounts.
pub struct Wallet {
    /// Exactly account 0 (Treasury) and account 1 (Registry).
    ufvks: BTreeMap<AccountId, UnifiedFullViewingKey>,

    /// The Zebra consensus tip last supplied through `WalletWrite::update_chain_tip`.
    zebra_tip: Option<BlockHeight>,

    /// Canonical Zebra blocks this in-memory projection has applied.
    blocks: BTreeMap<BlockHeight, BlockMetadata>,

    transactions: BTreeMap<TxId, Transaction>,
    transaction_statuses: BTreeMap<TxId, TransactionStatus>,
    transaction_indices: BTreeMap<TxId, TxIndex>,

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
        SAPLING_NOTE_COMMITMENT_TREE_DEPTH,
        SAPLING_SHARD_HEIGHT,
    >,
    sapling_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        ORCHARD_NOTE_COMMITMENT_TREE_DEPTH,
        ORCHARD_SHARD_HEIGHT,
    >,
    orchard_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    ironwood_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        ORCHARD_NOTE_COMMITMENT_TREE_DEPTH,
        ORCHARD_SHARD_HEIGHT,
    >,
    ironwood_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
}

impl Wallet {
    pub fn new(
        ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>,
        chain_state: &ChainState,
    ) -> Result<Self, TreeError> {
        let mut wallet = Self {
            ufvks: ufvks.into_iter().collect(),
            zebra_tip: None,
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
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS),
            sapling_tree_shard_end_heights: BTreeMap::new(),
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS),
            orchard_tree_shard_end_heights: BTreeMap::new(),
            ironwood_tree: ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS),
            ironwood_tree_shard_end_heights: BTreeMap::new(),
        };
        let retention = Retention::Checkpoint {
            id: chain_state.block_height(),
            marking: Marking::Reference,
        };
        wallet
            .sapling_tree
            .insert_frontier(chain_state.final_sapling_tree().clone(), retention)?;
        wallet
            .orchard_tree
            .insert_frontier(chain_state.final_orchard_tree().clone(), retention)?;
        wallet
            .ironwood_tree
            .insert_frontier(chain_state.final_ironwood_tree().clone(), retention)?;
        Ok(wallet)
    }

    /// Returns the fixed account UFVKs for scanner construction.
    pub fn ufvk_map(&self) -> &BTreeMap<AccountId, UnifiedFullViewingKey> {
        &self.ufvks
    }

    /// Returns the viewing key of one fixed mint account.
    pub fn ufvk_for(&self, account: AccountId) -> Option<&UnifiedFullViewingKey> {
        self.ufvks.get(&account)
    }

    /// The wallet's applied-tip continuity metadata, if any block is applied.
    ///
    /// This is the `prior_metadata` input to the next block scan and the
    /// reorg-detection baseline.
    pub fn applied_tip_metadata(&self) -> Option<BlockMetadata> {
        self.blocks.last_key_value().map(|(_, m)| m.clone())
    }

    /// The applied block metadata at `height`, if that height was applied.
    ///
    /// Reorg detection walks applied heights backwards until one matches the
    /// node's best chain, yielding the common ancestor.
    pub fn block_metadata_at(&self, height: BlockHeight) -> Option<BlockMetadata> {
        self.blocks.get(&height).cloned()
    }
}
