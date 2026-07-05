use incrementalmerkletree::{Position, Retention};
use shardtree::{store::memory::MemoryShardStore, ShardTree};
use zcash_protocol::consensus::BlockHeight;

pub const COMMITMENT_TREE_DEPTH: u8 = 32;
pub const SHARD_HEIGHT: u8 = 16;
pub const MAX_REORG_ALLOWANCE: usize = 100;

pub type OrchardShardStore = MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>;
pub type SaplingShardStore = MemoryShardStore<sapling::Node, BlockHeight>;

/// In-memory cache of the Orchard and Sapling commitment trees.
/// This allows retroactive witness construction for any position within the reorg allowance.
pub struct ShardTrees {
    orchard: ShardTree<OrchardShardStore, COMMITMENT_TREE_DEPTH, SHARD_HEIGHT>,
    sapling: ShardTree<SaplingShardStore, COMMITMENT_TREE_DEPTH, SHARD_HEIGHT>,
}

impl ShardTrees {
    /// Constructs empty trees with the standard reorg allowance.
    pub fn new() -> Self {
        Self {
            orchard: ShardTree::new(MemoryShardStore::empty(), MAX_REORG_ALLOWANCE),
            sapling: ShardTree::new(MemoryShardStore::empty(), MAX_REORG_ALLOWANCE),
        }
    }

    // --- Orchard ---

    pub fn insert_orchard_frontier(
        &mut self,
        frontier: incrementalmerkletree::frontier::Frontier<orchard::tree::MerkleHashOrchard, 32>,
        height: BlockHeight,
    ) {
        self.orchard
            .insert_frontier(
                frontier,
                Retention::Checkpoint {
                    id: height,
                    marking: incrementalmerkletree::Marking::Reference,
                },
            )
            .expect("in-memory store is infallible");
    }

    pub fn append_orchard(
        &mut self,
        cmx: orchard::tree::MerkleHashOrchard,
        retention: Retention<BlockHeight>,
    ) {
        self.orchard
            .append(cmx, retention)
            .expect("in-memory store is infallible");
    }

    pub fn orchard_witness(
        &mut self,
        position: Position,
        height: BlockHeight,
    ) -> Option<incrementalmerkletree::MerklePath<orchard::tree::MerkleHashOrchard, 32>> {
        self.orchard
            .witness_at_checkpoint_id_caching(position, &height)
            .expect("in-memory store is infallible")
    }

    pub fn orchard_anchor(&mut self, height: BlockHeight) -> Option<orchard::tree::MerkleHashOrchard> {
        self.orchard
            .root_at_checkpoint_id_caching(&height)
            .expect("in-memory store is infallible")
    }

    // --- Sapling ---

    pub fn insert_sapling_frontier(
        &mut self,
        frontier: incrementalmerkletree::frontier::Frontier<sapling::Node, 32>,
        height: BlockHeight,
    ) {
        self.sapling
            .insert_frontier(
                frontier,
                Retention::Checkpoint {
                    id: height,
                    marking: incrementalmerkletree::Marking::Reference,
                },
            )
            .expect("in-memory store is infallible");
    }

    pub fn append_sapling(
        &mut self,
        node: sapling::Node,
        retention: Retention<BlockHeight>,
    ) {
        self.sapling
            .append(node, retention)
            .expect("in-memory store is infallible");
    }

    pub fn sapling_witness(
        &mut self,
        position: Position,
        height: BlockHeight,
    ) -> Option<incrementalmerkletree::MerklePath<sapling::Node, 32>> {
        self.sapling
            .witness_at_checkpoint_id_caching(position, &height)
            .expect("in-memory store is infallible")
    }

    pub fn sapling_anchor(&mut self, height: BlockHeight) -> Option<sapling::Node> {
        self.sapling
            .root_at_checkpoint_id_caching(&height)
            .expect("in-memory store is infallible")
    }

    pub fn sapling_tree_size(&self) -> Option<u32> {
        self.sapling
            .max_leaf_position(None)
            .expect("in-memory store is infallible")
            .map(|p| (u64::from(p) + 1) as u32)
    }

    pub fn orchard_tree_size(&self) -> Option<u32> {
        self.orchard
            .max_leaf_position(None)
            .expect("in-memory store is infallible")
            .map(|p| (u64::from(p) + 1) as u32)
    }

    // --- Reorg Handling ---

    pub fn truncate_to_checkpoint(&mut self, height: BlockHeight) {
        self.orchard
            .truncate_to_checkpoint(&height)
            .expect("in-memory store is infallible");
        self.sapling
            .truncate_to_checkpoint(&height)
            .expect("in-memory store is infallible");
    }
}

impl Default for ShardTrees {
    fn default() -> Self {
        Self::new()
    }
}
