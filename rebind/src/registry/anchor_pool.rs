//! Claim-anchor lineage pool: the height-checkpointed set of nullifiers
//! that currently confer claim authority.
//!
//! Mint-internal: how the Registry stores its anchor state is its own
//! affair — the cross-repo contract is the canon fixture
//! (`tests/fixtures/canon-vectors-v1.json`), the same rules as events
//! and snapshots, not this type. The pool stays a pure function of
//! chain history either way: the ceremony's zero-value Registry
//! outputs, adopted in canonical scan order until the pool first
//! reaches standing size, and a successor joins only through the
//! retirement of a live anchor — one-for-one.

use std::collections::{BTreeMap, BTreeSet};

use orchard::note::Nullifier;
use zcash_protocol::consensus::BlockHeight;

/// Standing size of the anchor lineage pool; mirrors keygen's NUM_ANCHORS.
pub const ANCHOR_POOL_SIZE: usize = 40;

/// The keygen ceremony is one transaction: the whole standing set of
/// zero-value registry outputs, and no name note. A note outside that
/// transaction does not join the pool.
pub fn is_ceremony_fill(zero_value_outputs: usize, name_notes: usize) -> bool {
    zero_value_outputs == ANCHOR_POOL_SIZE && name_notes == 0
}

/// The set of nullifiers currently conferring claim authority, plus a
/// height-indexed checkpoint stack for reorg-safe rewind.
#[derive(Default, Clone)]
pub struct AnchorPool {
    live: BTreeSet<Nullifier>,
    checkpoints: BTreeMap<BlockHeight, BTreeSet<Nullifier>>,
    /// Block where ceremony adoption first reached standing size.
    /// Later ordinary outputs do not refill a shrunken pool.
    established: Option<BlockHeight>,
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

    /// Whether ceremony adoption has already reached standing size.
    pub fn adoption_closed(&self) -> bool {
        self.established.is_some()
    }

    /// Ceremony filling: a zero-value Registry output joins the pool
    /// until adoption first reaches standing size. A later shrink does
    /// not reopen it.
    ///
    /// Callers must invoke this in canonical scan order — transaction
    /// index within the block, then action index within the transaction —
    /// or two consumers of the same chain diverge on ties when more than
    /// one eligible output arrives at once.
    pub fn adopt(&mut self, height: BlockHeight, nf: Nullifier) {
        if self.adoption_closed() || self.is_full() {
            return;
        }
        if self.live.insert(nf) {
            if self.live.len() == ANCHOR_POOL_SIZE {
                self.established = Some(height);
            }
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
    /// checkpoint above. Ceremony completion clears only when that
    /// block itself is removed.
    pub fn truncate_to(&mut self, height: BlockHeight) {
        if self
            .established
            .is_some_and(|established| established > height)
        {
            self.established = None;
        }
        self.checkpoints.retain(|&h, _| h <= height);
        self.live = self
            .checkpoints
            .last_key_value()
            .map(|(_, pool)| pool.clone())
            .unwrap_or_default();
    }
}
