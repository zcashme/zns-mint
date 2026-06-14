//! Support for driving light client sync against a treasury (or other) WalletDb.
//!
//! The `state` crate is deliberately passive: it owns the WalletDb (notes,
//! shardtree witnesses, scan progress) and exposes `wallet_db_mut()` as an
//! explicit seam. All responsibility for clients, polling, `sync::run` /
//! `scan_cached_blocks`, and block caching (ephemeral is recommended) lives in
//! the orchestrator or here in the chain I/O crate.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Mutex;

use async_trait::async_trait;
use zcash_client_backend::{
    data_api::{
        chain::{error as chain_error, BlockCache, BlockSource},
        scanning::ScanRange,
    },
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::consensus::BlockHeight;

/// A minimal in-memory cache of compact blocks.
///
/// This is the recommended implementation when the WalletDb itself is the
/// source of truth for scan progress (no need to persist raw blocks on disk).
/// Blocks only live for the duration of one `sync::run` call.
///
/// The orchestrator (or a coordinator) owns an instance of this and passes
/// a mutable reference to `sync::run` (or the equivalent helper).
#[derive(Default)]
pub struct EphemeralCompactBlockCache(Mutex<BTreeMap<u64, CompactBlock>>);

fn range_bounds(range: &ScanRange) -> Range<u64> {
    u64::from(u32::from(range.block_range().start))..u64::from(u32::from(range.block_range().end))
}

impl BlockSource for EphemeralCompactBlockCache {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>,
    {
        let blocks = self.0.lock().expect("block cache lock");
        let from = from_height.map(|h| u64::from(u32::from(h))).unwrap_or(0);
        for block in blocks
            .range(from..)
            .map(|(_, b)| b.clone())
            .take(limit.unwrap_or(usize::MAX))
        {
            with_block(block)?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for EphemeralCompactBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let blocks = self.0.lock().expect("block cache lock");
        let tip = match range {
            Some(range) => blocks
                .range(range_bounds(range))
                .next_back()
                .map(|(h, _)| *h),
            None => blocks.keys().next_back().copied(),
        };
        Ok(tip.map(|h| BlockHeight::from_u32(h as u32)))
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let blocks = self.0.lock().expect("block cache lock");
        Ok(blocks
            .range(range_bounds(range))
            .map(|(_, b)| b.clone())
            .collect())
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut blocks = self.0.lock().expect("block cache lock");
        for block in compact_blocks {
            blocks.insert(block.height, block);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let mut blocks = self.0.lock().expect("block cache lock");
        let keys: Vec<u64> = blocks
            .range(range_bounds(&range))
            .map(|(h, _)| *h)
            .collect();
        for key in keys {
            blocks.remove(&key);
        }
        Ok(())
    }
}
