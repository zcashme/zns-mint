//! Zcash on-chain Median Time Past (MTP).
use std::collections::VecDeque;
use std::sync::OnceLock;

use time::Timestamp;
use zcash_protocol::consensus::BlockHeight;

/// The MTP window size, a Zcash consensus constant
const MTP_WINDOW: usize = 11;
/// Consensus upper bound on a header's time relative to its preceding median.
const MAX_TIME_SINCE_MEDIAN: i64 = 90 * 60;

/// The mint's birthday: the MTP of the birthday block, set once at
/// boot by [`MtpTracker::born`] and never changed after.
static BIRTHDAY: OnceLock<Timestamp> = OnceLock::new();

/// Median Time Past Tracker: the last 11 block timestamps.
///
/// A block's MTP is the median of the 11 blocks before it, not counting
/// the block itself (protocol spec §7.6), as Zebra and Zakura take it.
/// [`Self::admit`] gives a block its MTP; [`Self::next`] is the MTP of
/// the block after the last one recorded.
#[derive(Clone, Debug, Default)]
pub struct MtpTracker {
    blocktimes: VecDeque<(BlockHeight, u32)>,
}

impl MtpTracker {
    /// Registers the day-zero anchor: the MTP of the mint's birthday block.
    pub fn born(birthday: Timestamp) {
        // `set` bounces the rejected value back, not the incumbent, so
        // read the incumbent for the comparison.
        if BIRTHDAY.set(birthday).is_err() {
            assert_eq!(
                BIRTHDAY.get(),
                Some(&birthday),
                "FATAL: the mint cannot be born twice with different birthdays"
            );
        }
    }

    /// Days since the mint's birthday. `None` when [`Self::next`] is.
    pub fn current_day(&self) -> Option<i64> {
        let birthday = BIRTHDAY.get().expect("FATAL: the mint was never born");
        self.next().map(|mtp| (mtp - *birthday).whole_days())
    }

    /// Fills the tracker with the block timestamps ending at `till`, so
    /// MTP is available immediately at boot and after reorgs.
    /// These seed headers do not include their preceding windows; Zebra
    /// validates them. Subsequent blocks are checked by [`Self::admit`].
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
    fn update(&mut self, height: BlockHeight, timestamp: u32) {
        if self.blocktimes.len() >= MTP_WINDOW {
            self.blocktimes.pop_front();
        }
        self.blocktimes.push_back((height, timestamp));
    }

    /// Admits block `height`, the one after the last recorded: its header
    /// time must be after the block's MTP and at most 90 minutes past it,
    /// as consensus requires. Records the time and returns the block's MTP.
    pub fn admit(
        &mut self,
        height: BlockHeight,
        timestamp: u32,
    ) -> Result<Timestamp, &'static str> {
        let mtp = self.next().ok_or("preceding median unavailable")?;
        if self.blocktimes.back().map(|(last, _)| *last + 1) != Some(height) {
            return Err("block height does not follow the last recorded");
        }
        let time = i64::from(timestamp);
        if time <= mtp.as_seconds() {
            return Err("block time is not after the previous median");
        }
        if time > mtp.as_seconds() + MAX_TIME_SINCE_MEDIAN {
            return Err("block time is more than 90 minutes past the previous median");
        }
        self.update(height, timestamp);
        Ok(mtp)
    }

    /// The MTP of the block after the last one recorded: the median of
    /// the recorded times. `None` when none are recorded.
    pub fn next(&self) -> Option<Timestamp> {
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
        MtpTracker::born(t(BIRTHDAY_SECS));
        MtpTracker::default()
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
    fn header_time_is_checked_against_the_preceding_median() {
        let mut tracker = born();
        // Deliberately unordered times: the previous header can be later
        // than the new one, provided the new time exceeds the median.
        for (height, time) in [100, 90, 140, 120, 110, 130, 160, 150, 180, 170, 200]
            .into_iter()
            .enumerate()
        {
            tracker.update(h(height as u32), time);
        }
        assert_eq!(tracker.next(), Some(t(140)));
        let admits = |time| tracker.clone().admit(h(11), time).is_ok();
        assert!(admits(141));
        assert!(!admits(140));
        assert!(!admits(139));
        assert!(admits(140 + 90 * 60));
        assert!(!admits(140 + 90 * 60 + 1));
    }

    #[test]
    fn a_block_s_mtp_is_the_median_of_the_11_before_it() {
        let mut tracker = born();
        for i in 0..11 {
            tracker.update(h(i), 100 + 10 * i);
        }
        // The 11 before block 11 are 100..=200: their median is 150.
        // Counting block 11's own time (500) would make it 160, the
        // next block's MTP.
        assert_eq!(tracker.admit(h(11), 500), Ok(t(150)));
        assert_eq!(tracker.next(), Some(t(160)));
        // A time not after the block's MTP is refused, and not recorded.
        assert!(tracker.admit(h(12), 160).is_err());
        assert_eq!(tracker.next(), Some(t(160)));
        // A height that skips or repeats one is refused, and not recorded.
        assert!(tracker.admit(h(13), 500).is_err());
        assert!(tracker.admit(h(11), 500).is_err());
        assert_eq!(tracker.next(), Some(t(160)));
    }

    #[test]
    fn header_validation_has_no_machine_clock_bound() {
        let mut tracker = born();
        for i in 0..11 {
            tracker.update(h(i), u32::MAX - 1);
        }
        assert!(tracker.admit(h(11), u32::MAX).is_ok());
    }

    #[tokio::test]
    async fn backfill_seeds_times_without_checking_missing_predecessor_context() {
        let mut tracker = born();
        tracker
            .backfill(h(20), |_| async { Ok::<_, Infallible>(u32::MAX) })
            .await
            .unwrap();
        assert_eq!(tracker.next(), Some(t(i64::from(u32::MAX))));
    }

    #[tokio::test]
    async fn backfill_fetches_the_window_ending_at_till() {
        let mut tracker = born();
        let requested = backfill_mock(&mut tracker, h(20)).await;
        assert_eq!(requested, (10..=20).collect::<Vec<u32>>());
        assert_eq!(tracker.next(), Some(t(150))); // median of 100..=200
    }

    #[tokio::test]
    async fn backfill_saturates_near_genesis() {
        let mut tracker = born();
        let requested = backfill_mock(&mut tracker, h(4)).await;
        assert_eq!(requested, (0..=4).collect::<Vec<u32>>());
        assert_eq!(tracker.next(), Some(t(20))); // median of 0..=40
    }

    #[tokio::test]
    async fn after_backfill_the_next_block_pushes_the_window_forward() {
        // The boot flow: the window ends at the origin, and the first
        // scanned block is admitted after it.
        let mut tracker = born();
        backfill_mock(&mut tracker, h(10)).await;
        assert_eq!(tracker.admit(h(11), stamp(11)), Ok(t(50))); // median of 0..=100
        assert_eq!(tracker.next(), Some(t(60))); // median of 10..=110
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
}
