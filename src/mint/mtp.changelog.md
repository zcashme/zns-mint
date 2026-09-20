# Mtp design record

## The day-zero clamp test is gone (#108)

- `a_reorg_below_the_birthday_stays_day_zero` is deleted with its
  comment: the `whole_days` truncation clamp it pinned is observable
  only below the birthday MTP, a state the mint cannot reach. Positive-
  offset truncation stays pinned by
  `current_day_counts_whole_days_from_the_birthday`.

## The tracker is the mint's day clock (#80)

- `born(birthday)` registers the birthday block's MTP in a write-once
  process static: idempotent for the same value, FATAL for a different
  one. The struct stays a pure window — the reorg reset path is
  untouched and the anchor survives because it is not in the window.
- `current_day()` is the chain-clock answer to "what day is it": whole
  days between the current MTP and the birthday, `None` exactly when
  `current()` is. Rewinds with the chain like `current()` — MTP reaches
  back only the 11-block window, so a reorg can step the day back
  across at most one midnight. Consumers needing a monotonic day (the
  oracle's publication cadence) track their own maximum.
- Boot measures the anchor from headers: a throwaway window through
  `MINT_BIRTHDAY`, whose median is the birthday block's MTP. Never
  transcribed by a human, never machine time, one path for every
  network.
- `backfill`'s window-end parameter is `till` (was `scan_floor`): the
  block timestamps ending at `till`, inclusive — the 11 at most, fewer
  near genesis.
- `OnceLock::set` bounces the rejected value back, not the incumbent,
  so the double-birth guard reads the static for the comparison.