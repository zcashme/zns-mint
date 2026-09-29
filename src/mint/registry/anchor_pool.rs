//! Claim-anchor lineage pool: the height-checkpointed set of nullifiers
//! that currently confer claim authority.
//!
//! Mint-internal: how the Registry stores its anchor state is its own
//! affair — the cross-repo contract is the canon fixture
//! (`tests/fixtures/canon-vectors-v1.json`), the same rules as events
//! and snapshots, not this type. The pool stays a pure function of
//! chain history either way: the ceremony's zero-value Registry
//! outputs, adopted in canonical scan order, and a successor joins only
//! through the retirement of a live anchor — one-for-one.

use std::collections::{BTreeMap, BTreeSet};

use orchard::note::Nullifier;
use zcash_protocol::consensus::BlockHeight;

/// Standing size of the anchor lineage pool; mirrors keygen's NUM_ANCHORS.
pub const ANCHOR_POOL_SIZE: usize = 40;

/// The set of nullifiers currently conferring claim authority, plus a
/// height-indexed checkpoint stack for reorg-safe rewind.
#[derive(Default, Clone)]
pub struct AnchorPool {
    live: BTreeSet<Nullifier>,
    checkpoints: BTreeMap<BlockHeight, BTreeSet<Nullifier>>,
}

impl AnchorPool {
    /// Whether `nf` is a live claim-anchor nullifier.
    pub fn contains(&self, nf: &Nullifier) -> bool {
        self.live.contains(nf)
    }

    /// The live set of claim-anchor nullifiers.
    pub fn live(&self) -> &BTreeSet<Nullifier> {
        &self.live
    }

    /// Whether the pool has reached standing size.
    pub fn is_full(&self) -> bool {
        self.live.len() >= ANCHOR_POOL_SIZE
    }

    /// Ceremony filling: a zero-value Registry output joins the pool
    /// below standing size.
    ///
    /// Callers must invoke this in canonical scan order — transaction
    /// index within the block, then action index within the transaction —
    /// or two consumers of the same chain diverge on ties when more than
    /// one eligible output arrives at once.
    pub fn adopt(&mut self, height: BlockHeight, nf: Nullifier) {
        if !self.is_full() && self.live.insert(nf) {
            self.checkpoints.insert(height, self.live.clone());
        }
    }

    /// The pool follows one transaction: every live anchor it spent
    /// retires — consumed on chain, gone whatever the verdict — and a
    /// successor joins one-for-one, past standing size, only when
    /// exactly one anchor retired. Authority cannot be minted, only
    /// succeeded.
    pub fn retire_spent(
        &mut self,
        nfs: &[Nullifier],
        successor: Option<Nullifier>,
        height: BlockHeight,
    ) {
        let mut retired = 0;
        for nf in nfs {
            if self.live.remove(nf) {
                retired += 1;
            }
        }

        let mut changed = retired > 0;
        if retired == 1 {
            if let Some(nf) = successor {
                changed |= self.live.insert(nf);
            }
        }

        if changed {
            self.checkpoints.insert(height, self.live.clone());
        }
    }

    /// Rewinds to the pool state at `height`, discarding every
    /// checkpoint above.
    pub fn truncate_to(&mut self, height: BlockHeight) {
        self.checkpoints.retain(|&h, _| h <= height);
        self.live = self
            .checkpoints
            .last_key_value()
            .map(|(_, pool)| pool.clone())
            .unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nullifier(seed: u8) -> Nullifier {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Nullifier::from_bytes(&bytes)
            .into_option()
            .expect("test nullifier fits Pallas base")
    }

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    #[test]
    fn adopt_fills_up_to_standing_size_and_then_ignores() {
        let mut pool = AnchorPool::default();
        for i in 0..ANCHOR_POOL_SIZE {
            pool.adopt(h(i as u32 + 1), nullifier(i as u8 + 1));
        }
        assert_eq!(pool.live().len(), ANCHOR_POOL_SIZE);
        assert!(pool.is_full());

        // Extras past standing size do not enter.
        pool.adopt(h(500), nullifier(u8::MAX));
        assert_eq!(pool.live().len(), ANCHOR_POOL_SIZE);
        assert!(!pool.contains(&nullifier(u8::MAX)));
    }

    #[test]
    fn adopt_ignores_duplicates_and_does_not_checkpoint() {
        let mut pool = AnchorPool::default();
        pool.adopt(h(10), nullifier(1));
        let before = pool.live().clone();

        pool.adopt(h(11), nullifier(1)); // duplicate
        assert_eq!(pool.live(), &before);

        // Truncate above the duplicate's would-be checkpoint: the pool
        // must retain the earlier live set, proving the duplicate did
        // not create a new checkpoint at h(11).
        pool.truncate_to(h(10));
        assert!(pool.contains(&nullifier(1)));
    }

    #[test]
    fn retire_spent_retires_every_spent_anchor_and_checkpoints() {
        let mut pool = AnchorPool::default();
        pool.adopt(h(10), nullifier(1));
        pool.adopt(h(10), nullifier(2));
        pool.adopt(h(10), nullifier(3));
        // A malformed multi-spend retires every spent anchor.
        pool.retire_spent(&[nullifier(1), nullifier(2)], None, h(11));
        assert!(!pool.contains(&nullifier(1)));
        assert!(!pool.contains(&nullifier(2)));
        assert!(pool.contains(&nullifier(3)));
        // The retirement checkpointed at h(11): rewinding restores both.
        pool.truncate_to(h(10));
        assert!(pool.contains(&nullifier(1)));
        assert!(pool.contains(&nullifier(2)));
    }

    #[test]
    fn retire_spent_seats_a_successor_one_for_one() {
        let mut pool = AnchorPool::default();
        pool.adopt(h(10), nullifier(1));
        pool.retire_spent(&[nullifier(1)], Some(nullifier(100)), h(11));
        assert!(!pool.contains(&nullifier(1)));
        assert!(pool.contains(&nullifier(100)));
        // The succession checkpointed at h(11): rewinding undoes it.
        pool.truncate_to(h(10));
        assert!(pool.contains(&nullifier(1)));
        assert!(!pool.contains(&nullifier(100)));
    }

    #[test]
    fn retire_spent_ignores_a_successor_without_a_retired_anchor() {
        let mut pool = AnchorPool::default();
        pool.adopt(h(10), nullifier(1));
        // Nothing live was spent: no seat vacated, none taken.
        pool.retire_spent(&[nullifier(9)], Some(nullifier(100)), h(11));
        assert!(pool.contains(&nullifier(1)));
        assert!(!pool.contains(&nullifier(100)));
        // No checkpoint was written either: rewinding past h(10) is safe.
        pool.truncate_to(h(10));
        assert!(pool.contains(&nullifier(1)));
    }

    #[test]
    fn retire_spent_ignores_a_successor_after_a_multi_spend() {
        let mut pool = AnchorPool::default();
        pool.adopt(h(10), nullifier(1));
        pool.adopt(h(10), nullifier(2));
        // Two seats vacated, one successor offered: not one-for-one.
        pool.retire_spent(&[nullifier(1), nullifier(2)], Some(nullifier(100)), h(11));
        assert!(!pool.contains(&nullifier(1)));
        assert!(!pool.contains(&nullifier(2)));
        assert!(!pool.contains(&nullifier(100)));
    }

    #[test]
    fn retire_spent_successor_joins_past_standing_size() {
        let mut pool = AnchorPool::default();
        for i in 0..ANCHOR_POOL_SIZE {
            pool.adopt(h(10), nullifier(i as u8 + 1));
        }
        pool.retire_spent(&[nullifier(1)], Some(nullifier(200)), h(11));
        assert!(pool.contains(&nullifier(200)));
        assert_eq!(pool.live().len(), ANCHOR_POOL_SIZE);
    }

    #[test]
    fn truncate_to_restores_prior_checkpoint() {
        let mut pool = AnchorPool::default();
        pool.adopt(h(10), nullifier(1));
        pool.adopt(h(10), nullifier(2));
        pool.retire_spent(&[nullifier(1)], Some(nullifier(100)), h(11));
        pool.retire_spent(&[nullifier(2)], Some(nullifier(200)), h(12));

        // Rewind to h(11): the h(12) transition is undone.
        pool.truncate_to(h(11));
        assert!(!pool.contains(&nullifier(1)));
        assert!(pool.contains(&nullifier(2)));
        assert!(pool.contains(&nullifier(100)));
        assert!(!pool.contains(&nullifier(200)));

        // Rewind to h(10): both claim transitions undone.
        pool.truncate_to(h(10));
        assert!(pool.contains(&nullifier(1)));
        assert!(pool.contains(&nullifier(2)));
        assert!(!pool.contains(&nullifier(100)));
        assert!(!pool.contains(&nullifier(200)));

        // Rewind before adoption: pool empties.
        pool.truncate_to(h(0));
        assert_eq!(pool.live().len(), 0);
    }
}
