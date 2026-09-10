//! In-memory wallet database for the ZNS mint.

mod input;
mod read;
mod trees;
mod write;

pub use read::WalletError;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use incrementalmerkletree::{Address, Marking, Retention};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use transparent::bundle::OutPoint;
use zcash_client_backend::scanning::ScanningKeys;
use zcash_client_backend::{
    data_api::chain::ChainState,
    data_api::locking::LockOwner,
    data_api::{
        BlockMetadata, SentTransaction, SentTransactionOutput, TransactionStatus, WalletWrite,
    },
    wallet::{
        NoteId, OutputRef, ReceivedNote, WalletIronwoodOutput, WalletSaplingOutput,
        WalletTransparentOutput,
    },
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    consensus::{BlockHeight, TxIndex},
    memo::Memo,
    value::Zatoshis,
};
use zip32::AccountId;

use crate::mint::TREASURY_ACCOUNT;

/// Depth of the Sapling note commitment tree,
const SAPLING_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;

/// Depth of the Orchard and Ironwood note commitment tree;
const ORCHARD_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;

/// Shard height of the Sapling note commitment tree;
const SAPLING_SHARD_HEIGHT: u8 = 16;

/// Shard height of the Orchard and Ironwood note commitment trees;
const ORCHARD_SHARD_HEIGHT: u8 = 16;

/// Maximum checkpoints retained per note commitment tree.
const MAX_CHECKPOINTS: usize = 100;

/// Shard-tree error over the infallible in-memory store: only tree-structural
/// failures (`Query`, `Insert`) are reachable, never storage failures.
pub(crate) type TreeError = ShardTreeError<Infallible>;

/// The in-memory wallet for the two fixed mint accounts.
pub struct Wallet {
    /// Exactly account 0 (Treasury) and account 1 (Registry).
    ufvks: BTreeMap<AccountId, UnifiedFullViewingKey>,

    /// Derived from those same UFVKs at birth: the scanner scans exactly
    /// what the wallet stores, by construction.
    scanning_keys: ScanningKeys<AccountId, (AccountId, zip32::Scope)>,

    /// The Zebra consensus tip last supplied through `WalletWrite::update_chain_tip`.
    zebra_tip: Option<BlockHeight>,

    /// Canonical Zebra blocks this in-memory projection has applied.
    blocks: BTreeMap<BlockHeight, BlockMetadata>,

    /// The boot origin cursor: the block before the birthday.
    seed: BlockMetadata,

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
        let ufvks: BTreeMap<AccountId, UnifiedFullViewingKey> = ufvks.into_iter().collect();
        let scanning_keys = ScanningKeys::from_account_ufvks(ufvks.clone());
        let mut wallet = Self {
            ufvks,
            scanning_keys,
            zebra_tip: None,
            blocks: BTreeMap::new(),
            seed: block_metadata(chain_state),
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
        // Checkpoint id is birthday − 1: each frontier is the tree state at
        // the start of `MINT_BIRTHDAY`. Empty frontiers are inserted too —
        // the per-pool origin checkpoint is the reorg floor.
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

    /// The wallet's own scanning faculty, born from the same UFVKs.
    pub fn scanning_keys(&self) -> &ScanningKeys<AccountId, (AccountId, zip32::Scope)> {
        &self.scanning_keys
    }

    /// Returns the viewing key of one fixed mint account.
    pub fn ufvk_for(&self, account: AccountId) -> Option<&UnifiedFullViewingKey> {
        self.ufvks.get(&account)
    }

    /// Witnesses one received Ironwood note at `tip`.
    pub fn witness(
        &mut self,
        note: &ReceivedNote<NoteId, orchard::note::Note>,
        tip: BlockHeight,
    ) -> Option<orchard::tree::MerklePath> {
        let path = self
            .ironwood_witness(note.note_commitment_tree_position(), tip)
            .expect("FATAL: Ironwood tree access failed")
            .expect("FATAL: owned note has no witness at the applied tip");
        Some(orchard::tree::MerklePath::from(path))
    }

    /// The Ironwood anchor at `tip`: the root every spend of this block's
    /// transaction must prove against.
    pub fn anchor_at(&mut self, tip: BlockHeight) -> orchard::tree::Anchor {
        self.ironwood_anchor(tip)
            .expect("FATAL: Ironwood tree access failed")
            .expect("FATAL: wallet has no Ironwood anchor at its applied tip")
    }

    /// Records a mint-built transaction as sent-but-unconfirmed intent:
    /// marks its input spends (which also releases any locks) so the same
    /// notes cannot be selected again until the transaction either mines
    /// or expires.
    pub fn record_sent(
        &mut self,
        transaction: &Transaction,
        target_height: BlockHeight,
        fee: Zatoshis,
    ) {
        use zcash_client_backend::data_api::WalletWrite as _;
        use zcash_client_backend::data_api::wallet::TargetHeight;
        let sent = SentTransaction::new(
            transaction,
            time::OffsetDateTime::now_utc(),
            TargetHeight::from(target_height),
            TREASURY_ACCOUNT,
            &[],
            fee,
            &[],
        );
        self.store_transactions_to_be_sent(&[sent])
            .expect("FATAL: wallet rejected a locally built transaction");
    }

    /// The block hash at `height`: an applied block, or the boot origin.
    pub fn block_hash_at(&self, height: BlockHeight) -> Option<BlockHash> {
        self.blocks
            .get(&height)
            .map(|m| m.block_hash())
            .or_else(|| (height == self.seed.block_height()).then(|| self.seed.block_hash()))
    }

    /// Continuity metadata at `height`: an applied block, or the boot origin.
    pub fn block_metadata_at(&self, height: BlockHeight) -> Option<BlockMetadata> {
        self.blocks
            .get(&height)
            .cloned()
            .or_else(|| (height == self.seed.block_height()).then(|| self.seed.clone()))
    }

    /// Truncates the wallet to `max_height` and returns the
    /// [`BlockMetadata`] at that height — the new chain tip after reorg.
    pub fn truncate_to(&mut self, max_height: BlockHeight) -> Result<BlockMetadata, WalletError> {
        WalletWrite::truncate_to_height(self, max_height)?;
        self.block_metadata_at(max_height)
            .ok_or(WalletError::TruncationTargetUnavailable(max_height))
    }
}

/// Scan-cursor metadata implied by a [`ChainState`]: height, hash, tree sizes.
pub fn block_metadata(state: &ChainState) -> BlockMetadata {
    let sapling_size =
        u32::try_from(state.final_sapling_tree().tree_size()).expect("tree size fits u32");
    let orchard_size =
        u32::try_from(state.final_orchard_tree().tree_size()).expect("tree size fits u32");
    let ironwood_size =
        u32::try_from(state.final_ironwood_tree().tree_size()).expect("tree size fits u32");
    BlockMetadata::from_parts(
        state.block_height(),
        state.block_hash(),
        Some(sapling_size),
        Some(orchard_size),
        Some(ironwood_size),
    )
}
