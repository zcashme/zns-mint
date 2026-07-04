//! Zebra-backed best-chain block reads.
//!
//! This module owns chain-tip reads and full-block fetch/parse/verification
//! over a caller-owned Zebra client. It does not track scanning position or
//! model "the chain"; callers own cursors and replay policy.

use zcash_primitives::{
    block::{Block as ZcashBlock, BlockHash},
    transaction::Transaction,
};
use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};
use zebra_indexer_proto::{BlockHashAndHeight, BlockRequest, Empty};

use crate::zcash::zebra;

use std::time::Duration;
use tokio::sync::mpsc;

/// A best-chain block after local parse and integrity checks.
pub struct Block(ZcashBlock);

impl Block {
    pub fn height(&self) -> BlockHeight {
        self.0.claimed_height()
    }

    pub fn hash(&self) -> BlockHash {
        self.0.header().hash()
    }

    pub fn prev_hash(&self) -> BlockHash {
        self.0.header().prev_block
    }

    pub fn transactions(&self) -> impl Iterator<Item = &Transaction> {
        self.0.vtx().iter()
    }

    pub fn as_inner(&self) -> &ZcashBlock {
        &self.0
    }

    pub fn into_inner(self) -> ZcashBlock {
        self.0
    }
}

/// A client for reading the Zebra best-chain state.
pub struct Reader(zebra::ChainClient);

impl Reader {
    /// Connects to the gRPC chain observer.
    pub async fn connect() -> Self {
        Self(zebra::ChainClient::connect().await)
    }

    /// Reads Zebra's current best-chain tip.
    pub async fn tip(&mut self) -> (BlockHeight, BlockHash) {
        let resp = self
            .0
            .client()
            .chain_tip_change(Empty {})
            .await
            .expect("chain_tip_change failed");
        let mut stream = resp.into_inner();
        let tip = stream
            .message()
            .await
            .expect("no chain tip message")
            .expect("stream closed with no tip");

        tip_height_hash(&tip)
    }

    /// Fetches, parses, and locally verifies the best-chain block at `height`.
    pub async fn block(&mut self, height: BlockHeight) -> Block {
        let block_req = BlockRequest {
            hash_or_height: u32::from(height).to_be_bytes().to_vec(),
        };
        let block_resp = self
            .0
            .client()
            .get_block(block_req)
            .await
            .expect("get_block request failed");
        let block_and_hash = block_resp.into_inner();

        let parsed = ZcashBlock::read(&block_and_hash.data[..], &MAIN_NETWORK)
            .expect("get_block returned bytes that do not parse as a mainnet block");

        let getblock_hash = block_hash_from_display(&block_and_hash.hash)
            .expect("get_block returned a malformed 32-byte hash");
        assert_eq!(
            parsed.header().hash(),
            getblock_hash,
            "recomputed header hash != get_block hash"
        );
        assert_eq!(
            parsed.claimed_height(),
            height,
            "parsed block height != requested height"
        );

        Block(parsed)
    }
}

/// Spawns a background task that polls Zebra for new blocks starting at `start_height`.
///
/// Yields parsed and locally-verified blocks to the returned channel. Polling
/// repeats every 10 seconds if the tip has not advanced.
pub fn spawn_poller(start_height: BlockHeight) -> mpsc::Receiver<Block> {
    let (tx, rx) = mpsc::channel(100);

    tokio::spawn(async move {
        let mut reader = Reader::connect().await;
        let mut next_height = u32::from(start_height);

        loop {
            let (tip_height, _) = reader.tip().await;

            if next_height <= u32::from(tip_height) {
                let block = reader.block(BlockHeight::from_u32(next_height)).await;
                if tx.send(block).await.is_err() {
                    break; // Receiver dropped, kill the poller
                }
                next_height += 1;
            } else {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    });

    rx
}

fn tip_height_hash(tip: &BlockHashAndHeight) -> (BlockHeight, BlockHash) {
    (
        BlockHeight::from_u32(tip.height),
        block_hash_from_display(&tip.hash)
            .expect("chain_tip_change returned a malformed 32-byte hash"),
    )
}

fn block_hash_from_display(display: &[u8]) -> Option<BlockHash> {
    let mut bytes: [u8; 32] = BlockHash::try_from_slice(display)?.0;
    bytes.reverse();
    Some(BlockHash(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_hash_from_display_reverses_zebra_display_order() {
        let display: Vec<u8> = (0u8..32).collect();

        let hash = block_hash_from_display(&display).expect("32-byte hash");

        let mut expected = [0u8; 32];
        expected.copy_from_slice(&display);
        expected.reverse();
        assert_eq!(hash, BlockHash(expected));
    }

    #[test]
    fn block_hash_from_display_rejects_wrong_length() {
        assert!(block_hash_from_display(&[0u8; 31]).is_none());
        assert!(block_hash_from_display(&[0u8; 33]).is_none());
    }

    #[test]
    fn tip_height_hash_converts_proto_tip() {
        let display: Vec<u8> = (0u8..32).collect();
        let proto = BlockHashAndHeight {
            hash: display.clone(),
            height: 1_234_567,
        };

        let (height, hash) = tip_height_hash(&proto);

        let mut expected = [0u8; 32];
        expected.copy_from_slice(&display);
        expected.reverse();
        assert_eq!(height, BlockHeight::from_u32(1_234_567));
        assert_eq!(hash, BlockHash(expected));
    }

    /// Manual live-node check for the stateless chain read API. Ignored because
    /// it depends on the public Zebra endpoint.
    #[tokio::test]
    #[ignore]
    async fn zebra_smoke_tip_and_block() {
        let mut chain = Reader::connect().await;
        let (tip_height, tip_hash) = chain.tip().await;

        let block = chain.block(tip_height).await;

        assert_eq!(block.height(), tip_height);
        assert_eq!(block.hash(), tip_hash);
        assert_eq!(block.as_inner().header().hash(), tip_hash);
        assert_eq!(block.as_inner().claimed_height(), tip_height);
        assert_eq!(block.prev_hash(), block.as_inner().header().prev_block);
        assert_eq!(
            block.transactions().count(),
            block.as_inner().vtx().iter().count()
        );
    }
}
