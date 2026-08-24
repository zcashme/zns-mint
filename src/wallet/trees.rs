//! `WalletCommitmentTrees` over Wallet's direct upstream shard trees.

use std::convert::Infallible;

use incrementalmerkletree::Address;
use shardtree::{
    ShardTree,
    error::ShardTreeError,
    store::{ShardStore, memory::MemoryShardStore},
};
use zcash_client_backend::data_api::{WalletCommitmentTrees, chain::CommitmentTreeRoot};
use zcash_protocol::consensus::BlockHeight;

use super::{
    ORCHARD_NOTE_COMMITMENT_TREE_DEPTH, ORCHARD_SHARD_HEIGHT, SAPLING_NOTE_COMMITMENT_TREE_DEPTH,
    SAPLING_SHARD_HEIGHT, Wallet,
};

impl WalletCommitmentTrees for Wallet {
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
        self.with_sapling_tree_mut(|tree| {
            for (root, index) in roots.iter().zip(start_index..) {
                tree.insert(
                    Address::from_parts(SAPLING_SHARD_HEIGHT.into(), index),
                    *root.root_hash(),
                )?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

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
        self.with_orchard_tree_mut(|tree| {
            for (root, index) in roots.iter().zip(start_index..) {
                tree.insert(
                    Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index),
                    *root.root_hash(),
                )?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

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
        self.with_ironwood_tree_mut(|tree| {
            for (root, index) in roots.iter().zip(start_index..) {
                tree.insert(
                    Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index),
                    *root.root_hash(),
                )?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

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
