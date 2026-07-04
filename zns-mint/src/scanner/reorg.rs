use zcash_protocol::consensus::BlockHeight;
use std::collections::VecDeque;

/// Metadata for a specific block, acting as the cursor for the scanner.
#[derive(Debug, Clone)]
pub struct BlockMetadata {
    pub height: BlockHeight,
    pub hash: [u8; 32],
}

/// Records the state changes introduced by a single block, allowing
/// the scanner to revert them if the block is orphaned in a reorg.
#[derive(Debug, Clone)]
pub struct UndoState {
    pub height: BlockHeight,
    // TODO: add nullifiers, spent notes, prior_tree, etc. from design doc
}

/// Tracks the scanner's cursor and the undo history for reorgs.
pub struct ReorgBuffer {
    /// The cursor tracking where we are synced to.
    pub cursor: BlockMetadata,
    
    /// Bounded buffer (max 100) to allow dragging the cursor backwards on reorg.
    pub undo_blocks: VecDeque<UndoState>,
}

impl ReorgBuffer {
    /// Constructs a new ReorgBuffer seeded with a starting cursor.
    pub fn new(cursor: BlockMetadata) -> Self {
        Self {
            cursor,
            undo_blocks: VecDeque::with_capacity(100),
        }
    }
}
