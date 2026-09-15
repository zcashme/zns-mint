//! Zcash on-chain Median Time Past (MTP).
use std::collections::VecDeque;

use time::Timestamp;
use zcash_protocol::consensus::BlockHeight;

/// The MTP window size. This is a Zcash consensus constant inherited from
/// Bitcoin, not a ZNS protocol parameter — the whitepaper (§4.5) references
/// MTP as Zcash defines it.
const MTP_WINDOW: usize = 11;

/// Tracks up to the last 11 block timestamps and computes their median.
///
/// The window is a ring buffer of `(height, timestamp)` pairs. Entries
/// are pushed in ascending block order during scanning. The median is
/// the 6th value when the window is sorted by timestamp — the middle
/// element of 11, robust against a minority of manipulated timestamps.
#[derive(Clone, Debug, Default)]
pub struct MtpTracker {
    blocktimes: VecDeque<(BlockHeight, u32)>,
}

impl MtpTracker {
    /// Fills the tracker with the `MTP_WINDOW` block timestamps through
    /// `scan_floor`, inclusive, so MTP is available immediately.
    ///
    /// Called during boot (cold start) to fill the window ending at the
    /// origin checkpoint. After a deep reorg the tracker refills the same
    /// way from the rewound tip. `get_block_header` is used because the
    /// blocks themselves have not been fetched yet.
    ///
    /// If `scan_floor` is near genesis and fewer than `MTP_WINDOW` blocks
    /// exist through it, as many as available are fetched. Zcash inherits
    /// Bitcoin's early-chain rule: MTP is the median of every available
    /// ancestor timestamp until the full window exists.
    ///
    /// The `fetch` closure receives a block height and returns its
    /// timestamp (the `time` field from the block header, a `u32` Unix
    /// seconds value).
    pub async fn backfill<F, Fut, E>(
        &mut self,
        scan_floor: BlockHeight,
        mut fetch: F,
    ) -> Result<(), E>
    where
        F: FnMut(BlockHeight) -> Fut,
        Fut: std::future::Future<Output = Result<u32, E>>,
    {
        let floor_u32 = u32::from(scan_floor);
        let start = floor_u32.saturating_sub(MTP_WINDOW as u32 - 1);

        for h in start..=floor_u32 {
            let height = BlockHeight::from_u32(h);
            let timestamp = fetch(height).await?;
            self.update(height, timestamp);
        }

        Ok(())
    }

    /// Records a block's header timestamp.
    ///
    /// Called after each block is scanned. The timestamp comes from the
    /// block header's `time` field (a `u32` Unix-seconds value). If the
    /// window is full, the oldest entry is evicted before the new one is
    /// pushed.
    ///
    /// Heights must be strictly ascending — the scan loop processes
    /// blocks in order. A violation is a programming bug, not a runtime
    /// condition, so it triggers a debug assertion.
    pub fn update(&mut self, height: BlockHeight, timestamp: u32) {
        debug_assert!(
            self.blocktimes
                .back()
                .is_none_or(|(prev_h, _)| height > *prev_h),
            "push out of order: {} after {:?}",
            height,
            self.blocktimes.back().map(|(h, _)| h),
        );

        if self.blocktimes.len() >= MTP_WINDOW {
            self.blocktimes.pop_front();
        }
        self.blocktimes.push_back((height, timestamp));
    }

    /// Returns the current MTP as a [`Timestamp`], or `None` only when no
    /// timestamps have been recorded.
    ///
    /// The median is computed over every available timestamp, up to eleven.
    /// For an even early-chain population this uses the upper middle value,
    /// matching Bitcoin's `GetMedianTimePast` iterator arithmetic.
    ///
    pub fn current(&self) -> Option<Timestamp> {
        if self.blocktimes.is_empty() {
            return None;
        }

        let mut stamps: Vec<_> = self.blocktimes.iter().map(|(_, time)| *time).collect();
        stamps.sort_unstable();
        Some(
            Timestamp::from_seconds(stamps[stamps.len() / 2] as i64)
                .expect("block timestamp is a valid u32, always fits in Timestamp"),
        )
    }

    /// Drops entries above `height` for reorg handling.
    ///
    /// Called alongside `wallet.truncate_to_height` and
    /// `registry.truncate_to_height` when the scan loop detects a
    /// shorter chain. If the reorg is deeper than 11 blocks, the tracker
    /// empties entirely and refills naturally as blocks are re-scanned.
    /// During the gap, [`current`](Self::current) returns `None`.
    pub fn truncate_to(&mut self, height: BlockHeight) {
        self.blocktimes.retain(|(h, _)| *h <= height);
    }
}
