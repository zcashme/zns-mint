//! Canonical-chain Median Time Past (MTP).
//!
//! The whitepaper (§4.5) designates MTP as the sole authoritative time
//! source for protocol-defined lifecycle periods: name expiration, OTP
//! validity, and liveness enforcement. MTP is the median of the last 11
//! block timestamps — manipulation-resistant because an attacker needs 6
//! of 11 blocks to shift it, and deterministic because every node reading
//! the same chain derives the same value.
//!
//! The tracker is populated during the scan loop: after each block is
//! processed, [`push`](MtpTracker::push) records its header time. Once 11
//! entries are present, [`current`](MtpTracker::current) returns
//! the median. For cold start, [`backfill`](MtpTracker::backfill) fetches
//! the 10 headers below the scan floor via `get_block_header` so MTP is
//! available from the first scanned block.
//!
//! MTP is chain state, not mint state. The tracker lives as a local in
//! the run loop alongside `wallet` and `registry`.

use std::collections::VecDeque;

use time::Timestamp;
use zcash_protocol::consensus::BlockHeight;

/// Type-erased error for the `backfill` fetch closure, matching Zebra's
/// `BoxError` pattern. The only concrete error in production is
/// `TransportError`; the boxing lets `mint::mtp` stay free of RPC
/// type dependencies.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The MTP window size. This is a Zcash consensus constant inherited from
/// Bitcoin, not a ZNS protocol parameter — the whitepaper (§4.5) references
/// MTP as Zcash defines it.
const MTP_WINDOW: usize = 11;

/// Tracks the last 11 block timestamps and computes their median.
///
/// The window is a ring buffer of `(height, timestamp)` pairs. Entries
/// are pushed in ascending block order during scanning. The median is
/// the 6th value when the window is sorted by timestamp — the middle
/// element of 11, robust against a minority of manipulated timestamps.
#[derive(Debug, Default)]
pub struct MtpTracker {
    blocktimes: VecDeque<(BlockHeight, u32)>,
}

impl MtpTracker {
    /// Fills the tracker with block timestamps below `scan_floor` so MTP
    /// is available after the first scanned block.
    ///
    /// Called during cold start (`MtpTracker::default()` then `backfill`)
    /// and after a deep reorg (`truncate_to` then `backfill`). The first
    /// scanned block provides the 11th timestamp; `get_block_header` is
    /// used because the blocks themselves have not been fetched yet.
    ///
    /// If `scan_floor` is near genesis and fewer than 10 predecessors
    /// exist, as many as available are fetched. The tracker will return
    /// `None` from [`current`](Self::current) until enough blocks
    /// are scanned to fill the window.
    ///
    /// The `fetch` closure receives a block height and returns its
    /// timestamp (the `time` field from the block header, a `u32` Unix
    /// seconds value).
    pub async fn backfill<F, Fut>(
        &mut self,
        scan_floor: BlockHeight,
        mut fetch: F,
    ) -> Result<(), BoxError>
    where
        F: FnMut(BlockHeight) -> Fut,
        Fut: std::future::Future<Output = Result<u32, BoxError>>,
    {
        let floor_u32 = u32::from(scan_floor);
        let start = floor_u32.saturating_sub(MTP_WINDOW as u32 - 1);

        for h in start..floor_u32 {
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

    /// Returns the current MTP as a [`Timestamp`], or `None` if fewer
    /// than 11 timestamps have been recorded.
    ///
    /// The median is computed by copying the timestamps into a stack
    /// array, sorting, and taking the middle element (index 5 of 11).
    /// Cheap: 11 `u32` values, no heap allocation.
    ///
    /// Returns `None` during cold start before the window is full, or
    /// after a deep reorg empties the tracker. Callers should skip
    /// time-dependent processing until MTP is available — all protocol
    /// time checks are comparison-based (`mtp >= expires_at`), so
    /// delayed detection is correct, just deferred.
    pub fn current(&self) -> Option<Timestamp> {
        if self.blocktimes.len() < MTP_WINDOW {
            return None;
        }

        let mut stamps: [u32; MTP_WINDOW] = [0; MTP_WINDOW];
        for ((_, ts), slot) in self.blocktimes.iter().zip(stamps.iter_mut()) {
            *slot = *ts;
        }
        stamps.sort_unstable();
        // 6th element (0-indexed: 5) is the median of 11.
        Some(
            Timestamp::from_seconds(stamps[MTP_WINDOW / 2] as i64)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    #[test]
    fn fewer_than_11_returns_none() {
        let mut tracker = MtpTracker::default();
        for i in 0..10 {
            tracker.update(h(i), 1000 + i);
        }
        assert!(tracker.current().is_none());
    }

    #[test]
    fn exactly_11_returns_median() {
        let mut tracker = MtpTracker::default();
        // 11 timestamps: 1000..1010
        for i in 0..11 {
            tracker.update(h(i), 1000 + i);
        }
        // Sorted: [1000, 1001, ..., 1010], median = 1005
        let mtp = tracker.current().unwrap();
        assert_eq!(mtp.as_seconds(), 1005);
    }

    #[test]
    fn median_is_robust_against_outliers() {
        let mut tracker = MtpTracker::default();
        // 9 normal timestamps, 2 extreme outliers
        let stamps = [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 99999, 0];
        for (i, &ts) in stamps.iter().enumerate() {
            tracker.update(h(i as u32), ts);
        }
        // Sorted: [0, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 99999]
        // Median (index 5) = 1004
        let mtp = tracker.current().unwrap();
        assert_eq!(mtp.as_seconds(), 1004);
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let mut tracker = MtpTracker::default();
        for i in 0..15 {
            tracker.update(h(i), 1000 + i);
        }
        // Should have kept entries 4..=14 (11 entries)
        // Sorted: [1004, 1005, ..., 1014], median = 1009
        let mtp = tracker.current().unwrap();
        assert_eq!(mtp.as_seconds(), 1009);
    }

    #[test]
    fn median_updates_as_new_blocks_arrive() {
        let mut tracker = MtpTracker::default();
        for i in 0..11 {
            tracker.update(h(i), 2000 + i * 10);
        }
        // Sorted: [2000, 2010, ..., 2100], median = 2050
        assert_eq!(tracker.current().unwrap().as_seconds(), 2050);

        tracker.update(h(11), 5000);
        // Now window is 2010..2100, 5000. Sorted: [2010, 2020, ..., 2100, 5000]
        // Median (index 5) = 2060
        assert_eq!(tracker.current().unwrap().as_seconds(), 2060);
    }

    #[test]
    fn truncate_to_drops_entries_above_height() {
        let mut tracker = MtpTracker::default();
        for i in 0..11 {
            tracker.update(h(i), 1000 + i);
        }
        assert!(tracker.current().is_some());

        // Reorg to height 7: drops entries for heights 8, 9, 10
        tracker.truncate_to(h(7));
        assert!(tracker.current().is_none()); // only 8 entries left

        // Re-scan refills
        for i in 8..11 {
            tracker.update(h(i), 1000 + i);
        }
        assert!(tracker.current().is_some());
    }

    #[tokio::test]
    async fn backfill_after_truncate_refills() -> Result<(), BoxError> {
        let mut tracker = MtpTracker::default();
        for i in 90..101 {
            tracker.update(h(i), 2000 + i);
        }
        assert!(tracker.current().is_some());

        // Deep reorg to height 50: all entries dropped
        tracker.truncate_to(h(50));
        assert!(tracker.current().is_none());

        // Backfill refills from the chain
        tracker
            .backfill(h(50), |height| {
                async move { Ok(3000 + u32::from(height)) }
            })
            .await?;

        // Still not enough (backfill adds 10, need 11)
        assert!(tracker.current().is_none());

        // First re-scanned block provides the 11th
        tracker.update(h(50), 3000 + 50);
        assert!(tracker.current().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn backfill_populates_10_entries() -> Result<(), BoxError> {
        let mut tracker = MtpTracker::default();
        tracker
            .backfill(h(100), |height| {
                let h_val = u32::from(height);
                async move { Ok(1_700_000_000 + h_val) }
            })
            .await?;

        // Should have entries for heights 90..=99 (10 entries)
        assert!(tracker.current().is_none()); // need 11

        // First scanned block provides the 11th
        tracker.update(h(100), 1_700_000_100);
        assert!(tracker.current().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn backfill_near_genesis_fetches_fewer() -> Result<(), BoxError> {
        let mut tracker = MtpTracker::default();
        tracker
            .backfill(h(3), |height| {
                async move { Ok(1_700_000_000 + u32::from(height)) }
            })
            .await?;

        // Only 3 entries (heights 0, 1, 2), not enough for MTP
        assert!(tracker.current().is_none());
        Ok(())
    }
}