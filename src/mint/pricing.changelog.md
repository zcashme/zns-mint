# Pricing changelog

## The oracle stops computing days (#85)

- The day is not the oracle's to compute: `new` and `accumulate` take
  `today: i64` from the run loop, which reads `MtpTracker::current_day`
  (#80). The private `SECONDS_PER_DAY` grid, both `div_euclid` sites,
  and the midnight-boundary billing are deleted; the rollover is a
  plain `today > current_day` compare, still monotonic across reorg
  rewinds. The two-branch rollover body collapses to one flat fold.
- A day runs to its last observation: the interval crossing the
  boundary is billed into the new day, so the published average sits
  one observation (~75 s) behind exact midnight — MTP is the boundary,
  not UTC.
- An empty day carries the rate: with nothing accumulated the rollover
  publishes nothing, so an outage freezes the last published rate
  rather than drifting to a stale spot.

## 2026-09-18 — One quote, priced by term (#30)

- `Oracle::quote(name, term)` is the only public registration quote:
  `N` annuals for `Years(n)`, three annuals for `Forever`. The former
  `quote_annual`/`quote_forever` pair is gone from the surface — a year
  is `Term::Years(1)`, and the upgrade lane asks
  `quote(&name, Term::Forever)`.
- Ownership stays separated: the name schedule (`ANNUAL_USD`,
  `MINIMUM_USD`, `annual_usd`, `FOREVER_MULTIPLE`) is module-level
  product law — repricing names changes the schedule and never touches
  the oracle. The oracle owns the rate (`new`, `accumulate`,
  `current`) and the composition, because the rate lives there;
  nothing else computes a price.
- Restores the term-priced law the run-loop join (`9112558`) flattened
  to a flat forever quote ("Term-as-years in subsequent task").
- The rate layer is unchanged: fail-closed at birth, fail-open in
  life.