# Treasury pricing changelog

## 2026-08-16 — Evaluation-time USD pricing; no rate history exists

- Added `src/treasury/pricing.rs`: `RateOracle` holds exactly one rate and
  its fetch tip — the only pricing state in the system. No historical rate
  is stored, fetched, or rebuilt by any settlement decision. Crash recovery
  is rescan plus one fetch; a payment is always priced against the rate
  current at evaluation, and the atomic claim's refund leg returns any
  excess in the same transaction.
- Rate aggregation ported from `zcash_client_backend` 0.24.0-rc.7
  `tor::http::cryptex` (MIT OR Apache-2.0): nine exchange ticker endpoints;
  per-source bid/ask midpoint; Gemini trusted; ≥3 usable quotes required;
  random eviction to an odd count; median. Divergences, all deliberate:
  - Transport is one-shot rustls HTTPS (upstream `tor/http.rs
    make_http_request` connection shape) over the repo's existing hyper
    stack — upstream's aggregator is welded to `tor::Client` and enabling
    the `tor` feature would compile arti into the attested binary.
  - Fixed-point `MicroUsd` (USD × 10⁻⁶) replaces `rust_decimal`; tokio
    `JoinSet` replaces `futures-util`. No new numeric or futures deps.
  - The Kraken arm follows Kraken's documented `result.XZECZUSD` envelope;
    upstream's typed struct appears not to match it. Value-based parsing
    degrades a malformed source to `None` (dropped from the median) rather
    than failing the round.
- Claim schedule is decadal USD, compiled in-binary (no env, no config):
  $100M / $10M / $1M / $100k / $10k / $1k for 1–6 characters, $100 floor
  for 7+ (`Name::parse` caps names at 63).
- `price = ceil(schedule_usd / rate)` in `u128` zatoshis; the micro scales
  cancel exactly. Rounding is up — the Treasury never undercharges on a
  division remainder.
- Fail-closed doctrine: fewer than three usable quotes keeps the previous
  rate; a rate older than `RATE_GRACE_BLOCKS` (40 blocks ≈ 50 min) makes
  `price` return `None`. Callers must pause claims, never guess.
- Trust model: a corrupted median needs ≥5 of 9 venues held during the
  fetch round; TLS with webpki roots denies forgery; there is no operator
  input into the rate. ZEC/USDT sources are pooled with ZEC/USD as upstream
  pools them (bps-level basis under a median).
