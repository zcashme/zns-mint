//! `WalletCommitmentTrees` over Wallet's direct upstream shard trees, plus
//! the Ironwood witness/anchor reads that bundle construction consumes.

use std::convert::Infallible;

use incrementalmerkletree::{Address, MerklePath, Position};
use shardtree::{
    error::ShardTreeError,
    store::{memory::MemoryShardStore, ShardStore},
    ShardTree,
};
use zcash_client_backend::data_api::{chain::CommitmentTreeRoot, WalletCommitmentTrees};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::write::clone_shard_tree;
use super::{
    TreeError, Wallet, ORCHARD_NOTE_COMMITMENT_TREE_DEPTH, ORCHARD_SHARD_HEIGHT,
    SAPLING_NOTE_COMMITMENT_TREE_DEPTH, SAPLING_SHARD_HEIGHT,
};

impl<P: Parameters> WalletCommitmentTrees for Wallet<P> {
    type Error = Infallible;
    type SaplingShardStore<'a> = MemoryShardStore<sapling::Node, BlockHeight>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                SAPLING_NOTE_COMMITMENT_TREE_DEPTH,
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        callback(&mut self.sapling_tree)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        // All or nothing: a failed batch restores the saved tree; the
        // end-height map fills only on full success.
        let saved_tree = clone_shard_tree(&self.sapling_tree)?;
        if let Err(error) = self.with_sapling_tree_mut(|tree| {
            for (root, index) in roots.iter().zip(start_index..) {
                tree.insert(
                    Address::from_parts(SAPLING_SHARD_HEIGHT.into(), index),
                    *root.root_hash(),
                )?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        }) {
            self.sapling_tree = saved_tree;
            return Err(error);
        }

        for (root, index) in roots.iter().zip(start_index..) {
            self.sapling_tree_shard_end_heights.insert(
                Address::from_parts(SAPLING_SHARD_HEIGHT.into(), index),
                root.subtree_end_height(),
            );
        }
        Ok(())
    }

    fn get_sapling_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<sapling::Node>, ShardTreeError<Self::Error>> {
        self.with_sapling_tree_mut(|tree| {
            let address = Address::from_parts(SAPLING_SHARD_HEIGHT.into(), index);
            Ok(tree
                .store()
                .get_shard(address)
                .map_err(ShardTreeError::Storage)?
                .and_then(|shard| match shard.root() {
                    root if root.is_leaf() => root.leaf_value().copied(),
                    root => root
                        .annotation()
                        .and_then(|annotation| annotation.as_deref().copied()),
                }))
        })
    }

    type OrchardShardStore<'a> = MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>;

    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                ORCHARD_NOTE_COMMITMENT_TREE_DEPTH,
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        callback(&mut self.orchard_tree)
    }

    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        // All or nothing: a failed batch restores the saved tree; the
        // end-height map fills only on full success.
        let saved_tree = clone_shard_tree(&self.orchard_tree)?;
        if let Err(error) = self.with_orchard_tree_mut(|tree| {
            for (root, index) in roots.iter().zip(start_index..) {
                tree.insert(
                    Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index),
                    *root.root_hash(),
                )?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        }) {
            self.orchard_tree = saved_tree;
            return Err(error);
        }

        for (root, index) in roots.iter().zip(start_index..) {
            self.orchard_tree_shard_end_heights.insert(
                Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index),
                root.subtree_end_height(),
            );
        }
        Ok(())
    }

    fn get_orchard_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        self.with_orchard_tree_mut(|tree| {
            let address = Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index);
            Ok(tree
                .store()
                .get_shard(address)
                .map_err(ShardTreeError::Storage)?
                .and_then(|shard| match shard.root() {
                    root if root.is_leaf() => root.leaf_value().copied(),
                    root => root
                        .annotation()
                        .and_then(|annotation| annotation.as_deref().copied()),
                }))
        })
    }

    fn with_ironwood_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<Option<A>, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                ORCHARD_NOTE_COMMITMENT_TREE_DEPTH,
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        callback(&mut self.ironwood_tree).map(Some)
    }

    fn put_ironwood_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        // All or nothing: a failed batch restores the saved tree; the
        // end-height map fills only on full success.
        let saved_tree = clone_shard_tree(&self.ironwood_tree)?;
        if let Err(error) = self.with_ironwood_tree_mut(|tree| {
            for (root, index) in roots.iter().zip(start_index..) {
                tree.insert(
                    Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index),
                    *root.root_hash(),
                )?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        }) {
            self.ironwood_tree = saved_tree;
            return Err(error);
        }

        for (root, index) in roots.iter().zip(start_index..) {
            self.ironwood_tree_shard_end_heights.insert(
                Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index),
                root.subtree_end_height(),
            );
        }
        Ok(())
    }

    fn get_ironwood_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        self.with_ironwood_tree_mut(|tree| {
            let address = Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index);
            Ok(tree
                .store()
                .get_shard(address)
                .map_err(ShardTreeError::Storage)?
                .and_then(|shard| match shard.root() {
                    root if root.is_leaf() => root.leaf_value().copied(),
                    root => root
                        .annotation()
                        .and_then(|annotation| annotation.as_deref().copied()),
                }))
        })
        .map(|result| result.flatten())
    }
}

impl<P: Parameters> Wallet<P> {
    /// The Ironwood witness at `anchor_height` for the note at `position`.
    ///
    /// `Ok(None)` means no witness exists yet at that checkpoint (note not
    /// yet observed under that anchor); errors are tree-structural.
    pub fn ironwood_witness(
        &mut self,
        position: Position,
        anchor_height: BlockHeight,
    ) -> Result<Option<MerklePath<orchard::tree::MerkleHashOrchard, 32>>, TreeError> {
        // with_ironwood_tree_mut wraps the callback's Ok payload in an
        // outer Option; `?` then flatten collapses both layers.
        let witnessed = self.with_ironwood_tree_mut(|tree| {
            tree.witness_at_checkpoint_id_caching(position, &anchor_height)
        })?;
        Ok(witnessed.flatten())
    }

    /// The Ironwood tree root at `anchor_height` as an Orchard-family
    /// anchor for the builder.
    pub fn ironwood_anchor(
        &mut self,
        anchor_height: BlockHeight,
    ) -> Result<Option<orchard::tree::Anchor>, TreeError> {
        let root =
            self.with_ironwood_tree_mut(|tree| tree.root_at_checkpoint_id(&anchor_height))?;
        Ok(root.flatten().map(Into::into))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::frontier::Frontier;
    use incrementalmerkletree::{Hashable, Level};
    use shardtree::error::InsertionError;
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::MainNetwork;

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    fn empty_origin() -> ChainState {
        ChainState::new(
            h(0),
            BlockHash([0; 32]),
            Frontier::empty(),
            Frontier::empty(),
            Frontier::empty(),
        )
    }

    fn sapling_root(end: u32, node: sapling::Node) -> CommitmentTreeRoot<sapling::Node> {
        CommitmentTreeRoot::from_parts(h(end), node)
    }

    /// A conflicting root fails the whole birth; no wallet exists.
    #[test]
    fn new_with_conflicting_root_is_err() {
        // A frontier at the last leaf of shard 0 makes that shard complete
        // — its root is computable, so a differing claimed root conflicts.
        let leaf = sapling::Node::empty_root(Level::from(31));
        let ommers: Vec<sapling::Node> = (0..16u8)
            .map(|k| sapling::Node::empty_root(Level::from(k)))
            .collect();
        let origin = ChainState::new(
            h(0),
            BlockHash([0; 32]),
            Frontier::from_parts(Position::from(65_535), leaf, ommers).unwrap(),
            Frontier::empty(),
            Frontier::empty(),
        );
        let roots = [sapling_root(1, sapling::Node::empty_root(Level::from(7)))];

        assert!(matches!(
            Wallet::new([], &origin, &roots, &[], MainNetwork),
            Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
        ));
    }

    /// A coherent birth seeds trees and end-height bookkeeping together.
    #[test]
    fn new_seeds_roots_and_end_heights_together() {
        let sapling_roots = [sapling_root(10, sapling::Node::empty_root(Level::from(5)))];
        let ironwood_roots = [CommitmentTreeRoot::from_parts(
            h(11),
            orchard::tree::MerkleHashOrchard::empty_root(Level::from(5)),
        )];
        let mut wallet = Wallet::new(
            [],
            &empty_origin(),
            &sapling_roots,
            &ironwood_roots,
            MainNetwork,
        )
        .expect("empty targets cannot conflict");

        assert_eq!(wallet.sapling_tree_shard_end_heights.len(), 1);
        assert_eq!(
            wallet.get_sapling_subtree_root(0).unwrap(),
            Some(sapling::Node::empty_root(Level::from(5)))
        );
        assert_eq!(wallet.ironwood_tree_shard_end_heights.len(), 1);
        assert_eq!(
            wallet.get_ironwood_subtree_root(0).unwrap(),
            Some(orchard::tree::MerkleHashOrchard::empty_root(Level::from(5)))
        );
    }

    /// A failed batch restores the tree; the map keeps only what landed.
    #[test]
    fn put_roots_conflict_restores_the_tree() {
        let mut wallet =
            Wallet::new([], &empty_origin(), &[], &[], MainNetwork).expect("empty birth is valid");
        let a = sapling::Node::empty_root(Level::from(5));
        let d = sapling::Node::empty_root(Level::from(8));
        wallet
            .put_sapling_subtree_roots(0, &[sapling_root(1, a)])
            .expect("an empty shard accepts a root");
        wallet
            .put_sapling_subtree_roots(2, &[sapling_root(2, d)])
            .expect("an empty shard accepts a root");

        // Element 0 lands at index 1 (fresh, live); element 1 lands at
        // index 2 and conflicts with the held root — the whole batch
        // must fail.
        let batch = [
            sapling_root(3, sapling::Node::empty_root(Level::from(6))),
            sapling_root(4, sapling::Node::empty_root(Level::from(7))),
        ];
        assert!(matches!(
            wallet.put_sapling_subtree_roots(1, &batch),
            Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
        ));
        assert_eq!(wallet.get_sapling_subtree_root(0).unwrap(), Some(a));
        assert_eq!(wallet.get_sapling_subtree_root(1).unwrap(), None);
        assert_eq!(wallet.get_sapling_subtree_root(2).unwrap(), Some(d));
        assert_eq!(wallet.sapling_tree_shard_end_heights.len(), 2);
    }
}
