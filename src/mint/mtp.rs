//! Zcash on-chain Median Time Past (MTP).
use std::collections::VecDeque;
use std::sync::OnceLock;

use time::Timestamp;
use zcash_protocol::consensus::BlockHeight;

/// The MTP window size, a Zcash consensus constant
const MTP_WINDOW: usize = 11;

/// The mint's birthday: the MTP of the birthday block, set once at
/// boot by [`MtpTracker::born`] and never changed after.
static BIRTHDAY: OnceLock<Timestamp> = OnceLock::new();

/// Median Time Past Tracker.
/// Tracks up to the last 11 block timestamps and computes their median
/// Follows the Zcash consensus definition of MTP.
#[derive(Clone, Debug, Default)]
pub struct MtpTracker {
    blocktimes: VecDeque<(BlockHeight, u32)>,
}

impl MtpTracker {
    /// Born at the mint's birthday: registers the day-zero anchor and
    /// returns an empty tracker. Idempotent — born twice with the same
    /// birthday is the same mint; a different one is a bug.
    pub fn born(birthday: Timestamp) -> Self {
        // `set` bounces the rejected value back, not the incumbent, so
        // read the incumbent for the comparison.
        if BIRTHDAY.set(birthday).is_err() {
            assert_eq!(
                BIRTHDAY.get(),
                Some(&birthday),
                "FATAL: the mint cannot be born twice with different birthdays"
            );
        }
        Self::default()
    }

    /// Days since the mint's birthday. `None` when [`Self::current`] is.
    pub fn current_day(&self) -> Option<i64> {
        let birthday = BIRTHDAY.get().expect("FATAL: the mint was never born");
        self.current().map(|mtp| (mtp - *birthday).whole_days())
    }

    /// Fills the tracker with the block timestamps ending at `till`, so
    /// MTP is available immediately at boot and after reorgs.
    pub async fn backfill<F, Fut, E>(&mut self, till: BlockHeight, mut fetch: F) -> Result<(), E>
    where
        F: FnMut(BlockHeight) -> Fut,
        Fut: std::future::Future<Output = Result<u32, E>>,
    {
        let till_u32 = u32::from(till);
        let start = till_u32.saturating_sub(MTP_WINDOW as u32 - 1);

        for h in start..=till_u32 {
            let height = BlockHeight::from_u32(h);
            let timestamp = fetch(height).await?;
            self.update(height, timestamp);
        }

        Ok(())
    }

    /// Records a block's header timestamp.
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

    /// Returns the current MTP as a [`Timestamp`], or `None` when no
    /// timestamps have been recorded.
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

    /// Reorg Handler to drops entries above `height`
    pub fn truncate_to(&mut self, height: BlockHeight) {
        self.blocktimes.retain(|(h, _)| *h <= height);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::convert::Infallible;

    use super::*;

    const DAY: i64 = 86_400;

    /// Every test is born at the same moment, so the write-once
    /// `BIRTHDAY` static is idempotent across parallel test threads.
    const BIRTHDAY_SECS: i64 = 1_000 * DAY;

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_seconds(secs).unwrap()
    }

    fn born() -> MtpTracker {
        MtpTracker::born(t(BIRTHDAY_SECS))
    }

    /// A plausible header time for each height.
    fn stamp(height: u32) -> u32 {
        10 * height
    }

    /// Backfills with mock headers, returning the heights the fetch saw.
    async fn backfill_mock(tracker: &mut MtpTracker, till: BlockHeight) -> Vec<u32> {
        let requested = RefCell::new(Vec::new());
        tracker
            .backfill(till, |height| {
                requested.borrow_mut().push(u32::from(height));
                let value = stamp(u32::from(height));
                async move { Ok::<_, Infallible>(value) }
            })
            .await
            .unwrap();
        requested.into_inner()
    }

    #[test]
    fn current_day_counts_whole_days_from_the_birthday() {
        for (offset, day) in [(0, 0), (DAY - 1, 0), (DAY, 1), (100 * DAY + 7, 100)] {
            let mut tracker = born();
            tracker.update(h(1), u32::try_from(BIRTHDAY_SECS + offset).unwrap());
            assert_eq!(tracker.current_day(), Some(day), "offset {offset}");
        }
    }

    #[test]
    fn current_day_is_none_until_a_block_is_seen() {
        assert_eq!(born().current_day(), None);
    }

    #[test]
    fn a_reorg_below_the_birthday_stays_day_zero() {
        // `whole_days` truncates toward zero: a rewound MTP below the
        // birthday never reports a negative day.
        let mut tracker = born();
        tracker.update(h(1), u32::try_from(BIRTHDAY_SECS - 500).unwrap());
        assert_eq!(tracker.current_day(), Some(0));
    }

    #[test]
    fn the_median_of_a_full_window_flips_the_day() {
        // 11 entries, 6 above the midnight: the 6th smallest — the
        // median — is above it, so the day is 1.
        let mut tracker = born();
        for i in 0..5 {
            tracker.update(h(i), u32::try_from(BIRTHDAY_SECS - 100).unwrap());
        }
        for i in 5..11 {
            tracker.update(h(i), u32::try_from(BIRTHDAY_SECS + DAY).unwrap());
        }
        assert_eq!(tracker.current_day(), Some(1));

        // 5 above instead: the median stays below the midnight.
        let mut tracker = born();
        for i in 0..6 {
            tracker.update(h(i), u32::try_from(BIRTHDAY_SECS - 100).unwrap());
        }
        for i in 6..11 {
            tracker.update(h(i), u32::try_from(BIRTHDAY_SECS + DAY).unwrap());
        }
        assert_eq!(tracker.current_day(), Some(0));
    }

    #[test]
    fn the_day_rewinds_when_a_truncate_recrosses_midnight() {
        let mut tracker = born();
        for i in 0..5 {
            tracker.update(h(i), u32::try_from(BIRTHDAY_SECS - 100).unwrap());
        }
        for i in 5..11 {
            tracker.update(h(i), u32::try_from(BIRTHDAY_SECS + DAY).unwrap());
        }
        assert_eq!(tracker.current_day(), Some(1));

        tracker.truncate_to(h(4));
        assert_eq!(tracker.current_day(), Some(0));
    }

    #[tokio::test]
    async fn backfill_fetches_the_window_ending_at_till() {
        let mut tracker = born();
        let requested = backfill_mock(&mut tracker, h(20)).await;
        assert_eq!(requested, (10..=20).collect::<Vec<u32>>());
        assert_eq!(tracker.current(), Some(t(150))); // median of 100..=200
    }

    #[tokio::test]
    async fn backfill_saturates_near_genesis() {
        let mut tracker = born();
        let requested = backfill_mock(&mut tracker, h(4)).await;
        assert_eq!(requested, (0..=4).collect::<Vec<u32>>());
        assert_eq!(tracker.current(), Some(t(20))); // median of 0..=40
    }

    #[tokio::test]
    async fn after_backfill_the_next_block_pushes_the_window_forward() {
        // The boot flow: window ends at the origin, the first scanned
        // block enters without touching the ascending order.
        let mut tracker = born();
        backfill_mock(&mut tracker, h(10)).await;
        tracker.update(h(11), stamp(11));
        assert_eq!(tracker.current(), Some(t(60))); // median of 10..=110
    }

    #[test]
    fn born_twice_with_the_same_birthday_is_idempotent() {
        let mut tracker = born();
        let _again = born();
        tracker.update(h(1), u32::try_from(BIRTHDAY_SECS).unwrap());
        assert_eq!(tracker.current_day(), Some(0));
    }

    #[test]
    #[should_panic(expected = "cannot be born twice")]
    fn born_twice_with_a_different_birthday_is_fatal() {
        born();
        MtpTracker::born(t(BIRTHDAY_SECS + 1));
    }

    #[test]
    #[should_panic(expected = "push out of order")]
    fn an_out_of_order_height_is_a_checked_bug() {
        let mut tracker = born();
        tracker.update(h(10), 1);
        tracker.update(h(5), 2);
    }
}
