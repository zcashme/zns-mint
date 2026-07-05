use zcash_protocol::consensus::BlockHeight;
use std::collections::VecDeque;

/// Metadata for a specific block, acting as the cursor for the scanner.
#[derive(Debug, Clone)]
pub struct BlockMetadata {
    pub height: BlockHeight,
    pub hash: [u8; 32],
}

/// Tracks the scanner's cursor for reorg detection.
pub struct ReorgBuffer {
    /// Bounded buffer of metadata for the last 100 blocks we've scanned.
    /// Used to linearly reverse and find the common ancestor when a reorg happens.
    pub blocks: VecDeque<BlockMetadata>,
}

impl ReorgBuffer {
    /// Constructs a new ReorgBuffer seeded with a starting cursor.
    pub fn new(cursor: BlockMetadata) -> Self {
        let mut blocks = VecDeque::with_capacity(100);
        blocks.push_back(cursor);
        Self { blocks }
    }

    /// Pushes a new block onto the buffer, dropping the oldest if we exceed max depth.
    pub fn push(&mut self, meta: BlockMetadata) {
        if self.blocks.len() == 100 {
            self.blocks.pop_front();
        }
        self.blocks.push_back(meta);
    }
}
