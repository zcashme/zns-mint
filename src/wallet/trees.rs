use std::convert::Infallible;

use incrementalmerkletree::{Position, Retention};
use shardtree::{
    error::{InsertionError, QueryError, ShardTreeError},
    store::memory::MemoryShardStore,
    ShardTree,
};
use zcash_protocol::consensus::BlockHeight;

pub const COMMITMENT_TREE_DEPTH: u8 = 32;
pub const SHARD_HEIGHT: u8 = 16;
/// Maximum number of accepted predecessors that can be rewound from the tip.
pub const MAX_REORG_DEPTH: usize = 100;
/// Current checkpoint plus every predecessor in [`MAX_REORG_DEPTH`].
pub const RETAINED_CHECKPOINTS: usize = MAX_REORG_DEPTH + 1;

pub type OrchardShardStore = MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>;
pub type SaplingShardStore = MemoryShardStore<sapling::Node, BlockHeight>;

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("commitment-tree insert failed: {0}")]
    Insert(#[from] InsertionError),
    #[error("commitment-tree query at height {height} failed: {inner}")]
    Query {
        height: BlockHeight,
        inner: QueryError,
    },
    #[error("{pool} commitment tree has no checkpoint at accepted height {height}")]
    MissingCheckpoint {
        pool: &'static str,
        height: BlockHeight,
    },
}

impl From<ShardTreeError<Infallible>> for TreeError {
    fn from(e: ShardTreeError<Infallible>) -> Self {
        match e {
            ShardTreeError::Storage(inf) => match inf {},
            ShardTreeError::Insert(i) => TreeError::Insert(i),
            ShardTreeError::Query(q) => TreeError::Query {
                height: BlockHeight::from_u32(0),
                inner: q,
            },
        }
    }
}

/// In-memory cache of the Orchard, Ironwood, and Sapling commitment trees.
/// This allows retroactive witness construction for any position within the reorg allowance.
///
/// Ironwood (NU6.3) has its own commitment tree, distinct from Orchard, even
/// though both use `MerkleHashOrchard` as the hash type. The two pools are
/// tracked separately per ZIP 2005.
pub struct ShardTrees {
    orchard: ShardTree<OrchardShardStore, COMMITMENT_TREE_DEPTH, SHARD_HEIGHT>,
    ironwood: ShardTree<OrchardShardStore, COMMITMENT_TREE_DEPTH, SHARD_HEIGHT>,
    sapling: ShardTree<SaplingShardStore, COMMITMENT_TREE_DEPTH, SHARD_HEIGHT>,
}

impl Default for ShardTrees {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardTrees {
    /// Constructs empty trees with the standard reorg allowance.
    pub fn new() -> Self {
        Self {
            orchard: ShardTree::new(MemoryShardStore::empty(), RETAINED_CHECKPOINTS),
            ironwood: ShardTree::new(MemoryShardStore::empty(), RETAINED_CHECKPOINTS),
            sapling: ShardTree::new(MemoryShardStore::empty(), RETAINED_CHECKPOINTS),
        }
    }

    // --- Orchard ---

    pub fn insert_orchard_frontier(
        &mut self,
        frontier: incrementalmerkletree::frontier::Frontier<
            orchard::tree::MerkleHashOrchard,
            COMMITMENT_TREE_DEPTH,
        >,
        height: BlockHeight,
    ) -> Result<(), TreeError> {
        self.orchard.insert_frontier(
            frontier,
            Retention::Checkpoint {
                id: height,
                marking: incrementalmerkletree::Marking::Reference,
            },
        )?;
        Ok(())
    }

    pub fn append_orchard(
        &mut self,
        cmx: orchard::tree::MerkleHashOrchard,
        retention: Retention<BlockHeight>,
    ) -> Result<(), TreeError> {
        self.orchard.append(cmx, retention)?;
        Ok(())
    }

    pub fn orchard_witness(
        &mut self,
        position: Position,
        height: BlockHeight,
    ) -> Result<
        Option<
            incrementalmerkletree::MerklePath<
                orchard::tree::MerkleHashOrchard,
                COMMITMENT_TREE_DEPTH,
            >,
        >,
        TreeError,
    > {
        self.orchard
            .witness_at_checkpoint_id_caching(position, &height)
            .map_err(|e| match e {
                ShardTreeError::Storage(inf) => match inf {},
                ShardTreeError::Insert(i) => TreeError::Insert(i),
                ShardTreeError::Query(q) => TreeError::Query { height, inner: q },
            })
    }

    pub fn orchard_anchor(
        &mut self,
        height: BlockHeight,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, TreeError> {
        self.orchard
            .root_at_checkpoint_id_caching(&height)
            .map_err(|e| match e {
                ShardTreeError::Storage(inf) => match inf {},
                ShardTreeError::Insert(i) => TreeError::Insert(i),
                ShardTreeError::Query(q) => TreeError::Query { height, inner: q },
            })
    }

    // --- Ironwood ---

    pub fn insert_ironwood_frontier(
        &mut self,
        frontier: incrementalmerkletree::frontier::Frontier<
            orchard::tree::MerkleHashOrchard,
            COMMITMENT_TREE_DEPTH,
        >,
        height: BlockHeight,
    ) -> Result<(), TreeError> {
        self.ironwood.insert_frontier(
            frontier,
            Retention::Checkpoint {
                id: height,
                marking: incrementalmerkletree::Marking::Reference,
            },
        )?;
        Ok(())
    }

    pub fn append_ironwood(
        &mut self,
        cmx: orchard::tree::MerkleHashOrchard,
        retention: Retention<BlockHeight>,
    ) -> Result<(), TreeError> {
        self.ironwood.append(cmx, retention)?;
        Ok(())
    }

    pub fn ironwood_witness(
        &mut self,
        position: Position,
        height: BlockHeight,
    ) -> Result<
        Option<
            incrementalmerkletree::MerklePath<
                orchard::tree::MerkleHashOrchard,
                COMMITMENT_TREE_DEPTH,
            >,
        >,
        TreeError,
    > {
        self.ironwood
            .witness_at_checkpoint_id_caching(position, &height)
            .map_err(|e| match e {
                ShardTreeError::Storage(inf) => match inf {},
                ShardTreeError::Insert(i) => TreeError::Insert(i),
                ShardTreeError::Query(q) => TreeError::Query { height, inner: q },
            })
    }

    pub fn ironwood_anchor(
        &mut self,
        height: BlockHeight,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, TreeError> {
        self.ironwood
            .root_at_checkpoint_id_caching(&height)
            .map_err(|e| match e {
                ShardTreeError::Storage(inf) => match inf {},
                ShardTreeError::Insert(i) => TreeError::Insert(i),
                ShardTreeError::Query(q) => TreeError::Query { height, inner: q },
            })
    }

    /// Returns the root at the newest retained Ironwood checkpoint.
    ///
    /// Unlike [`Self::ironwood_anchor`], this does not require a checkpoint
    /// whose identifier exactly equals a block height. It is appropriate for
    /// output-only bundles: if no Ironwood commitments were appended in later
    /// scanned blocks, the newest checkpoint root is still the current root.
    pub fn latest_ironwood_anchor(
        &mut self,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, TreeError> {
        self.ironwood
            .root_at_checkpoint_depth_caching(Some(0))
            .map_err(TreeError::from)
    }

    pub fn ironwood_tree_size(&self) -> Result<Option<u32>, TreeError> {
        Ok(self
            .ironwood
            .max_leaf_position(None)?
            .map(|p| (u64::from(p) + 1) as u32))
    }

    // --- Sapling ---

    pub fn insert_sapling_frontier(
        &mut self,
        frontier: incrementalmerkletree::frontier::Frontier<sapling::Node, COMMITMENT_TREE_DEPTH>,
        height: BlockHeight,
    ) -> Result<(), TreeError> {
        self.sapling.insert_frontier(
            frontier,
            Retention::Checkpoint {
                id: height,
                marking: incrementalmerkletree::Marking::Reference,
            },
        )?;
        Ok(())
    }

    pub fn append_sapling(
        &mut self,
        node: sapling::Node,
        retention: Retention<BlockHeight>,
    ) -> Result<(), TreeError> {
        self.sapling.append(node, retention)?;
        Ok(())
    }

    pub fn sapling_witness(
        &mut self,
        position: Position,
        height: BlockHeight,
    ) -> Result<
        Option<incrementalmerkletree::MerklePath<sapling::Node, COMMITMENT_TREE_DEPTH>>,
        TreeError,
    > {
        self.sapling
            .witness_at_checkpoint_id_caching(position, &height)
            .map_err(|e| match e {
                ShardTreeError::Storage(inf) => match inf {},
                ShardTreeError::Insert(i) => TreeError::Insert(i),
                ShardTreeError::Query(q) => TreeError::Query { height, inner: q },
            })
    }

    pub fn sapling_anchor(
        &mut self,
        height: BlockHeight,
    ) -> Result<Option<sapling::Node>, TreeError> {
        self.sapling
            .root_at_checkpoint_id_caching(&height)
            .map_err(|e| match e {
                ShardTreeError::Storage(inf) => match inf {},
                ShardTreeError::Insert(i) => TreeError::Insert(i),
                ShardTreeError::Query(q) => TreeError::Query { height, inner: q },
            })
    }

    pub fn sapling_tree_size(&self) -> Result<Option<u32>, TreeError> {
        Ok(self
            .sapling
            .max_leaf_position(None)?
            .map(|p| (u64::from(p) + 1) as u32))
    }

    pub fn orchard_tree_size(&self) -> Result<Option<u32>, TreeError> {
        Ok(self
            .orchard
            .max_leaf_position(None)?
            .map(|p| (u64::from(p) + 1) as u32))
    }

    /// Ensures every pool has a checkpoint for `height`, including pools with
    /// no commitments in that block.
    ///
    /// `ShardTree::checkpoint` returns `false` when the same height was already
    /// installed by a final leaf carrying `Retention::Checkpoint`; that is the
    /// expected idempotent case here.
    pub fn checkpoint_all(&mut self, height: BlockHeight) -> Result<(), TreeError> {
        self.orchard.checkpoint(height)?;
        self.ironwood.checkpoint(height)?;
        self.sapling.checkpoint(height)?;

        for (pool, present) in [
            (
                "Orchard",
                self.orchard
                    .root_at_checkpoint_id(&height)
                    .map_err(TreeError::from)?
                    .is_some(),
            ),
            (
                "Ironwood",
                self.ironwood
                    .root_at_checkpoint_id(&height)
                    .map_err(TreeError::from)?
                    .is_some(),
            ),
            (
                "Sapling",
                self.sapling
                    .root_at_checkpoint_id(&height)
                    .map_err(TreeError::from)?
                    .is_some(),
            ),
        ] {
            if !present {
                return Err(TreeError::MissingCheckpoint { pool, height });
            }
        }
        Ok(())
    }

    // --- Reorg Handling ---

    pub fn truncate_to_checkpoint(&mut self, height: BlockHeight) -> Result<bool, TreeError> {
        // Preflight every pool before mutating any tree. All three stores are
        // in-memory with an Infallible storage error; once these exact
        // checkpoints exist, truncation cannot discover a later missing pool
        // after an earlier pool has already changed.
        if self
            .orchard
            .root_at_checkpoint_id(&height)
            .map_err(TreeError::from)?
            .is_none()
        {
            return Err(TreeError::MissingCheckpoint {
                pool: "Orchard",
                height,
            });
        }
        if self
            .ironwood
            .root_at_checkpoint_id(&height)
            .map_err(TreeError::from)?
            .is_none()
        {
            return Err(TreeError::MissingCheckpoint {
                pool: "Ironwood",
                height,
            });
        }
        if self
            .sapling
            .root_at_checkpoint_id(&height)
            .map_err(TreeError::from)?
            .is_none()
        {
            return Err(TreeError::MissingCheckpoint {
                pool: "Sapling",
                height,
            });
        }

        let orchard_truncated = self.orchard.truncate_to_checkpoint(&height)?;
        if !orchard_truncated {
            return Err(TreeError::MissingCheckpoint {
                pool: "Orchard",
                height,
            });
        }
        let ironwood_truncated = self.ironwood.truncate_to_checkpoint(&height)?;
        if !ironwood_truncated {
            return Err(TreeError::MissingCheckpoint {
                pool: "Ironwood",
                height,
            });
        }
        let sapling_truncated = self.sapling.truncate_to_checkpoint(&height)?;
        if !sapling_truncated {
            return Err(TreeError::MissingCheckpoint {
                pool: "Sapling",
                height,
            });
        }
        Ok(true)
    }
}
