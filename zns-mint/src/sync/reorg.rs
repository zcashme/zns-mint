use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;
use std::collections::VecDeque;

/// Identifies a specific block, acting as the cursor for the scanner.
#[derive(Debug, Clone)]
pub struct BlockCursor {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

/// Tracks the scanner's cursor for reorg detection.
pub struct ReorgBuffer {
    /// Bounded buffer of cursors for the last 100 blocks we've scanned.
    /// Used to linearly reverse and find the common ancestor when a reorg happens.
    pub blocks: VecDeque<BlockCursor>,
}

impl ReorgBuffer {
    /// Constructs a new ReorgBuffer seeded with a starting cursor.
    pub fn new(cursor: BlockCursor) -> Self {
        let mut blocks = VecDeque::with_capacity(100);
        blocks.push_back(cursor);
        Self { blocks }
    }

    /// Pushes a new block onto the buffer, dropping the oldest if we exceed max depth.
    pub fn push(&mut self, meta: BlockCursor) {
        if self.blocks.len() == 100 {
            self.blocks.pop_front();
        }
        self.blocks.push_back(meta);
    }
}
