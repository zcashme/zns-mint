# Pricing changelog

## 2026-09-23 — Challenge fee grid step is a checked multiply

- `challenge_fee` rounds one dollar up to the 100_000-zat grid with
  `checked_mul`. An in-range rate yields the same fee. A product that
  does not fit `u64` fails closed instead of wrapping.

## 2026-09-22 — Median at N ≥ 3, Gemini alone below, no mean

- `aggregate` returns the median of survivors at N ≥ 3, and Gemini's
  own quote (unaveraged) at N ∈ {1, 2} if Gemini is a survivor —
  otherwise `None` and the last published rate stays in effect.
- A day publishes its TWAP only when at least half of that day's
  fetch attempts landed a price; thinner days keep yesterday's rate.
- The 2-quote unauthenticated mean is deleted: one honest + one
  malicious quote produced a 50%-corrupted price with no divergence
  bound.

## The challenge fee (#18)

- `Oracle::challenge_fee()` prices the trigger of a controller
  challenge: one dollar at the current published rate, rounded up to
  the next 100_000-zat increment. At the issue's example rate
  (120k zats per dollar) the fee is 200_000 zats; the grid floor is
  100_000 zats. The rate already rounds up so a quote never lands
  below its USD tariff; the fee grid rounds up on top of it.
  Anti-spam pricing, not revenue — the drain refuses underpaid relay
  requests outright, with no queue memory, the claim lane's
  "dead and silent" precedent.

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
- `last_ts` keeps `current_day`'s rewind policy: a round arriving with
  MTP behind the last one bills nothing and moves nothing — the old
  fold clamped the elapsed seconds to zero but still stamped `last_ts`
  backward, billing the rewound span a second time on every reorg.

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