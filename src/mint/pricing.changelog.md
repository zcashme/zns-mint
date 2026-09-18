# Pricing changelog

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