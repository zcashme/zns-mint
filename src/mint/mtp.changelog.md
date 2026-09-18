# Mtp design record

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