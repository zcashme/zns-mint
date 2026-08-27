//! Daily USD/ZEC claim pricing.
//!
//! The mint publishes **one ZEC/USD rate per UTC day**. All claims filed
//! during a given day are priced against that day's fixed rate — no
//! intra-day fluctuation, no spot pricing, no surprises for users. The
//! daily rate is a **time-weighted average price (TWAP)** of the per-block
//! median-of-odd fetches accumulated throughout the *previous* day. So
//! today's rate = yesterday's full-day average.
//!
//! On cold start the first successful fetch seeds a temporary spot rate so
//! the mint can operate immediately; at the next UTC midnight the rate
//! switches to a full-day TWAP and never looks back.
//!
//! # Rate aggregation
//!
//! The aggregation is ported from `zcash_client_backend` 0.24.0-rc.7
//! `tor::http::cryptex` (MIT OR Apache-2.0):
//!
//! - nine public exchange ticker endpoints, quoted per source;
//! - each source contributes the midpoint of its best bid/ask (cryptex.rs
//!   `ExchangeData::exchange_rate`);
//! - Gemini (a NYDFS-regulated exchange) is trusted: its quote always counts
//!   when obtained;
//! - with two or more other sources configured — always true here — at least
//!   three usable quotes are required, else the round fails (cryptex.rs
//!   "never go to sea with two chronometers" rule);
//! - one quote is evicted at random if needed to leave an odd count, and the
//!   median is taken.
//!
//! Upstream routes every request through Tor (`tor::Client` is welded into
//! the adapter trait and the aggregator method); this port swaps the
//! transport for a one-shot rustls HTTPS connection (upstream
//! `tor/http.rs::make_http_request` shape) against the repo's existing hyper
//! stack. No arti, no `rust_decimal` (fixed-point `MicroUsd`), no
//! `futures-util` (tokio fan-out).
//!
//! # Trust model
//!
//! A corrupted daily TWAP requires sustained manipulation of the median
//! across a large fraction of a full day's ~1152 fetch rounds — an attacker
//! must control ≥5 of 9 venues (or Gemini plus four) for hours, not seconds.
//! DNS or network interception cannot forge the webpki-validated
//! certificates. There is no operator input channel into the rate: no env
//! var, no config file, no RPC parameter. When no rate has ever been
//! published, pricing returns `None` and callers must pause claims — fail
//! closed, never misprice.
//!
//! Six sources quote ZEC/USDT rather than ZEC/USD; upstream pools them and
//! so does this port. The USDT basis is bps-level noise under a median.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use rand::seq::IteratorRandom;
use rand::rngs::OsRng;
use time::Timestamp;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{COIN, Zatoshis};

use crate::mint::Name;

// ===========================================================================
// Fixed-point USD
// ===========================================================================

/// A USD amount in millionths (USD × 10⁻⁶) as an exact integer.
///
/// Every exchange in the source set emits at most six fraction digits, so
/// ingest is lossless and every later operation (midpoint, median, price
/// conversion) is exact integer arithmetic. Replaces cryptex's
/// `rust_decimal` with no new dependency and no allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MicroUsd(u64);

impl MicroUsd {
    /// Parses a decimal string such as `"41"`, `"41.5"`, `"41.234567"`.
    ///
    /// Accepts at most six fraction digits (everything the source set can
    /// emit); rejects signs, empty parts, and any non-digit. Returns `None`
    /// on anything else — a malformed quote drops its source from the
    /// median rather than erroring the round.
    pub fn parse(s: &str) -> Option<Self> {
        let (int_part, frac_part) = match s.split_once('.') {
            Some((i, f)) => (i, Some(f)),
            None => (s, None),
        };
        if int_part.is_empty() {
            return None;
        }
        let frac = match frac_part {
            Some(f) if f.is_empty() || f.len() > 6 => return None,
            Some(f) => f,
            None => "",
        };

        let mut micros: u64 = 0;
        for b in int_part.bytes().chain(frac.bytes()) {
            let d = (b as char).to_digit(10)? as u64;
            micros = micros.checked_mul(10)?.checked_add(d)?;
        }
        // Scale the fraction digits up to micros.
        for _ in 0..(6 - frac.len()) {
            micros = micros.checked_mul(10)?;
        }
        Some(Self(micros))
    }

    /// The exact midpoint of a bid/ask pair, floored on a half-micro.
    /// Port of cryptex `ExchangeData::exchange_rate`.
    pub fn midpoint(self, other: Self) -> Option<Self> {
        Some(Self(self.0.checked_add(other.0)? / 2))
    }

    /// The raw micro-USD value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

// ===========================================================================
// Claim schedule
// ===========================================================================

/// The USD claim price for a name of `len` characters: decadal, 10× per
/// character, with 7+ characters at $100.
///
/// `Name::parse` admits only `a-z`, `0-9`, `-` (1–63 chars), so `len` is a
/// byte length equal to the character count. Compiled into the binary —
/// pricing policy follows the no-env, no-config doctrine.
pub fn schedule_usd(len: usize) -> MicroUsd {
    MicroUsd(match len {
        1 => 100_000_000_000_000, // $100,000,000
        2 => 10_000_000_000_000,  // $10,000,000
        3 => 1_000_000_000_000,   // $1,000,000
        4 => 100_000_000_000,     // $100,000
        5 => 10_000_000_000,      // $10,000
        6 => 1_000_000_000,       // $1,000
        _ => 100_000_000,         // 7+ = $100
    })
}

// ===========================================================================
// Sources
// ===========================================================================

/// The fixed source set. Entry 0 (Gemini) is the trusted source; the
/// aggregator requires at least three usable quotes total.
///
/// Each entry cites its ported upstream adapter under
/// `zcash_client_backend/src/tor/http/cryptex/`.
const TICKERS: [(&str, &str); 9] = [
    // gemini.rs — ZEC/USD, NYDFS-regulated; trusted.
    ("gemini", "https://api.gemini.com/v2/ticker/zecusd"),
    // kraken.rs — ZEC/USD. Upstream's typed struct does not match Kraken's
    // documented `{"error":[],"result":{...}}` envelope; this arm follows
    // the documented nesting and drops the source on mismatch.
    ("kraken", "https://api.kraken.com/0/public/Ticker?pair=XZECZUSD"),
    // coinbase.rs — ZEC/USD.
    ("coinbase", "https://api.exchange.coinbase.com/products/ZEC-USD/ticker"),
    // binance.rs — ZEC/USDT.
    ("binance", "https://api.binance.com/api/v3/ticker/24hr?symbol=ZECUSDT"),
    // mexc.rs — ZEC/USDT.
    ("mexc", "https://api.mexc.com/api/v3/ticker/24hr?symbol=ZECUSDT"),
    // ku_coin.rs — ZEC/USDT.
    ("kucoin", "https://api.kucoin.com/api/v1/market/stats?symbol=ZEC-USDT"),
    // coin_ex.rs — ZEC/USDT (best book level).
    ("coinex", "https://api.coinex.com/v2/spot/depth?market=ZECUSDT&limit=5&interval=0"),
    // digi_finex.rs — ZEC/USDT.
    ("digifinex", "https://openapi.digifinex.com/v3/ticker?symbol=zec_usdt"),
    // xt.rs — ZEC/USDT (best book level).
    ("xt", "https://sapi.xt.com/v4/public/ticker/book?symbol=zec_usdt"),
];

/// Extracts `(bid, ask)` from a source's ticker JSON.
///
/// Each arm mirrors the field selection of its upstream adapter. All nine
/// sources emit prices as JSON strings; anything absent, null, or
/// non-numeric yields `None` and the source is dropped from the round.
fn parse_quote(source: &str, v: &serde_json::Value) -> Option<(MicroUsd, MicroUsd)> {
    let field = |v: &serde_json::Value, key: &str| -> Option<MicroUsd> {
        MicroUsd::parse(v.get(key)?.as_str()?)
    };
    let (bid, ask) = match source {
        // gemini.rs: `ExchangeData { bid: data.bid, ask: data.ask }`
        "gemini" => (field(v, "bid")?, field(v, "ask")?),
        // kraken.rs: `bid: data.b.0, ask: data.a.0` under result.XZECZUSD.
        "kraken" => {
            let r = v.get("result")?.get("XZECZUSD")?;
            (
                MicroUsd::parse(r.get("b")?.get(0)?.as_str()?)?,
                MicroUsd::parse(r.get("a")?.get(0)?.as_str()?)?,
            )
        }
        // coinbase.rs: `bid: data.bid, ask: data.ask`.
        "coinbase" => (field(v, "bid")?, field(v, "ask")?),
        // binance.rs: `bid: data.bidPrice, ask: data.askPrice`.
        "binance" => (field(v, "bidPrice")?, field(v, "askPrice")?),
        // mexc.rs: `bid: data.bidPrice, ask: data.askPrice`.
        "mexc" => (field(v, "bidPrice")?, field(v, "askPrice")?),
        // ku_coin.rs: `bid: data.buy, ask: data.sell` under `data`.
        "kucoin" => {
            let d = v.get("data")?;
            (field(d, "buy")?, field(d, "sell")?)
        }
        // coin_ex.rs: first bid / first ask price under `data.depth`.
        "coinex" => {
            let d = v.get("data")?.get("depth")?;
            (
                MicroUsd::parse(d.get("bids")?.get(0)?.get(0)?.as_str()?)?,
                MicroUsd::parse(d.get("asks")?.get(0)?.get(0)?.as_str()?)?,
            )
        }
        // digi_finex.rs: `bid: ticker[0].buy, ask: ticker[0].sell`.
        "digifinex" => {
            let t = v.get("ticker")?.get(0)?;
            (field(t, "buy")?, field(t, "sell")?)
        }
        // xt.rs: `bid: result[0].bp, ask: result[0].ap`.
        "xt" => {
            let r = v.get("result")?.get(0)?;
            (field(r, "bp")?, field(r, "ap")?)
        }
        _ => return None,
    };
    Some((bid, ask))
}

// ===========================================================================
// Transport
// ===========================================================================

/// One-shot rustls HTTPS: webpki root store, no client auth. This is the
/// entire trust anchor for egress — a network interceptor can drop or stall
/// a quote (the median and timeouts absorb that) but cannot forge it.
static TLS: LazyLock<tokio_rustls::TlsConnector> = LazyLock::new(|| {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    tokio_rustls::TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
});

/// Deadline for one source end-to-end (connect + request + body). A slow
/// source is a dropped source; the round does not wait for stragglers.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Fetches one source's midpoint quote. Every failure mode — DNS, TCP, TLS,
/// HTTP status, JSON shape, malformed decimal — collapses to `None`.
///
/// One-shot connection per fetch, mirroring upstream
/// `tor/http.rs::make_http_request`: handshake, spawn the connection driver,
/// one request, drop everything. At one round per block there is nothing to
/// pool.
async fn fetch_one(name: &'static str, url: &'static str) -> Option<MicroUsd> {
    let uri: Uri = url.parse().ok()?;
    let host = uri.host()?.to_string();
    let port = uri.port_u16().unwrap_or(443);

    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.ok()?;
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host).ok()?;
    let stream = TLS.connect(server_name, tcp).await.ok()?;

    let (mut sender, connection) = http1::handshake::<_, http_body_util::Empty<hyper::body::Bytes>>(TokioIo::new(stream))
        .await
        .ok()?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("accept", "application/json")
        .body(http_body_util::Empty::default())
        .ok()?;
    let response = sender.send_request(request).await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let bytes = response
        .into_body()
        .collect()
        .await
        .ok()?
        .to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let (bid, ask) = parse_quote(name, &v)?;
    bid.midpoint(ask)
}

/// Runs one fetch round over the whole source set.
///
/// Returns the trusted (Gemini) quote separately from the others — the
/// aggregation weights them differently. Sources resolve concurrently; the
/// round takes as long as its fastest stragglers, bounded by
/// [`FETCH_TIMEOUT`] per source.
async fn fetch_round() -> (Option<MicroUsd>, Vec<MicroUsd>) {
    let mut set = tokio::task::JoinSet::new();
    for (name, url) in TICKERS {
        set.spawn(async move {
            let mid = tokio::time::timeout(FETCH_TIMEOUT, fetch_one(name, url))
                .await
                .ok()
                .flatten();
            (name, mid)
        });
    }

    let mut trusted = None;
    let mut others = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((name, mid)) = joined {
            if name == TICKERS[0].0 {
                trusted = mid;
            } else if let Some(m) = mid {
                others.push(m);
            }
        }
    }
    (trusted, others)
}

// ===========================================================================
// Aggregation
// ===========================================================================

/// Median-of-odd over the round's quotes. Port of the aggregation in
/// cryptex `Client::get_latest_zec_to_usd_rate` (cryptex.rs 0.24.0-rc.7):
///
/// - at least three usable quotes are required whenever two or more
///   non-trusted sources are configured (always true for this source set);
/// - the trusted quote is always counted when obtained;
/// - one other quote is evicted at random when needed to leave an odd
///   count; the median of the odd set is the round's rate.
fn median_of_odd(trusted: Option<MicroUsd>, mut others: Vec<MicroUsd>) -> Option<MicroUsd> {
    // cryptex guards on the configured source count; the set is fixed here,
    // so the "≥3 usable" rule is unconditional.
    if others.len() + usize::from(trusted.is_some()) < 3 {
        return None;
    }

    let mut evict_random = |s: &mut Vec<MicroUsd>| {
        if let Some(index) = (0..s.len()).choose(&mut OsRng) {
            s.remove(index);
        }
    };
    match trusted {
        Some(t) => {
            if !others.len().is_multiple_of(2) {
                evict_random(&mut others);
            }
            others.push(t);
        }
        None => {
            if others.len().is_multiple_of(2) {
                evict_random(&mut others);
            }
        }
    }

    if others.is_empty() {
        return None;
    }
    assert!(!others.len().is_multiple_of(2));
    others.sort_unstable();
    Some(others[others.len() / 2])
}

// ===========================================================================
// Oracle
// ===========================================================================

/// Minimum samples required to publish a daily TWAP. With per-block sampling
/// (~1152 blocks/day at Zcash's 75-second cadence), this threshold is met
/// within minutes. It only matters if the mint was down for most of the day —
/// in that case the previous day's rate is retained rather than publishing a
/// rate from a handful of samples.
const MIN_SAMPLES: u32 = 10;

/// Seconds per UTC day.
const SECONDS_PER_DAY: i64 = 86_400;

/// The mint's daily USD/ZEC rate oracle.
///
/// One price per UTC day, published at midnight, fixed for 24 hours. The
/// rate is a **time-weighted average price (TWAP)** of the per-block
/// median-of-odd fetches accumulated throughout the previous day. Today's
/// claims are always priced against yesterday's full-day average — never a
/// spot price, never an intra-day fluctuation.
///
/// On cold start the first successful fetch seeds a temporary spot rate so
/// the mint can operate immediately. At the next UTC midnight the rate
/// switches to a full-day TWAP and from then on every day is an average of
/// the previous day.
///
/// If fewer than [`MIN_SAMPLES`] samples were collected during a day (a
/// sustained outage), the previous day's rate is retained — fail safe, not
/// fail random. If no rate has ever been published, `None` is returned and
/// callers must pause claims — fail closed.
#[derive(Default)]
pub struct RateOracle {
    /// The published daily rate — yesterday's TWAP. Valid for all of today.
    daily_rate: Option<MicroUsd>,

    /// TWAP accumulator: Σ(price × seconds) for the current day so far.
    acc_sum: u128,
    /// TWAP accumulator: Σ(seconds) for the current day so far.
    acc_seconds: u64,
    /// The price of the most recent sample, carried forward between samples
    /// for time-weighting (the price is assumed constant between samples).
    last_price: Option<MicroUsd>,
    /// The Unix timestamp (seconds) of the most recent sample.
    last_ts: i64,
    /// The UTC day number (`floor(unix_seconds / 86400)`) of the current
    /// accumulation.
    current_day: i64,
    /// Successful samples collected during the current day.
    sample_count: u32,
}

impl RateOracle {
    /// Runs one fetch round and accumulates the result into today's TWAP.
    ///
    /// Called once per block. A failed round (fewer than three usable quotes)
    /// is skipped — the accumulator simply doesn't advance. If a UTC day
    /// boundary has been crossed since the last sample, the previous day's
    /// TWAP is finalized and published as the new daily rate.
    pub async fn refresh(&mut self, _tip: BlockHeight) {
        let (trusted, others) = fetch_round().await;
        let median = match median_of_odd(trusted, others) {
            Some(m) => m,
            None => {
                tracing::warn!("pricing round failed; accumulator unchanged");
                return;
            }
        };
        self.accumulate(median, Timestamp::now());
    }

    /// Incorporates one sample into the daily TWAP accumulator.
    ///
    /// Separated from [`refresh`](Self::refresh) so it can be tested without
    /// network I/O. Handles UTC day-boundary rollover: when a new sample
    /// arrives after midnight, the previous day's TWAP is finalized and
    /// published as the daily rate (if enough samples were collected), and
    /// the accumulator resets for the new day.
    ///
    /// # TWAP mechanics
    ///
    /// Between two consecutive samples the price is assumed constant at
    /// the earlier sample's value (the standard Uniswap-style accumulator).
    /// Each interval contributes `price_old × elapsed_seconds` to a running
    /// sum; the day's TWAP is `sum / total_seconds`.
    ///
    /// At a day boundary the interval is split: the portion before midnight
    /// closes the old day; the portion after midnight starts the new day
    /// with the same carry-forward price.
    fn accumulate(&mut self, price: MicroUsd, now: Timestamp) {
        let now_secs = now.as_seconds();
        let today = now_secs.div_euclid(SECONDS_PER_DAY);

        // First ever sample: seed the accumulator and set a temporary spot
        // rate so the mint can operate immediately on cold start.
        if self.last_price.is_none() {
            self.current_day = today;
            self.last_price = Some(price);
            self.last_ts = now_secs;
            self.sample_count = 1;
            if self.daily_rate.is_none() {
                self.daily_rate = Some(price);
            }
            return;
        }

        let prev_price = self.last_price.unwrap();

        if today > self.current_day {
            // ── Day boundary: finalize yesterday, publish, reset ─────────
            let midnight = today * SECONDS_PER_DAY;
            let before_midnight = (midnight - self.last_ts) as u64;

            // Close the old day with the carry-forward price active up to midnight.
            self.acc_sum += u128::from(prev_price.as_u64()) * u128::from(before_midnight);
            self.acc_seconds += before_midnight;

            // Publish if we have enough data; otherwise keep the old rate.
            if self.sample_count >= MIN_SAMPLES && self.acc_seconds > 0 {
                let twap = self.acc_sum / u128::from(self.acc_seconds);
                self.daily_rate = Some(MicroUsd(twap as u64));
            }

            // Start the new day: carry-forward price is active from midnight.
            let after_midnight = (now_secs - midnight) as u64;
            self.acc_sum = u128::from(prev_price.as_u64()) * u128::from(after_midnight);
            self.acc_seconds = after_midnight;
            self.current_day = today;
            self.sample_count = 0;
        } else {
            // ── Same day: accumulate the interval ────────────────────────
            let elapsed = (now_secs - self.last_ts) as u64;
            self.acc_sum += u128::from(prev_price.as_u64()) * u128::from(elapsed);
            self.acc_seconds += elapsed;
        }

        // The new sample takes over as the carry-forward price.
        self.last_price = Some(price);
        self.last_ts = now_secs;
        self.sample_count += 1;
    }

    /// The published daily rate, or `None` if no rate has ever been published.
    pub fn rate(&self) -> Option<MicroUsd> {
        self.daily_rate
    }

    /// The claim price in zatoshis:
    ///
    /// ```text
    /// price = ceil( schedule_usd(len) / rate )
    /// ```
    ///
    /// The micro-USD scales cancel exactly, so this is
    /// `ceil(usd_micros × COIN / rate_micros)` in `u128`, rounded up — the
    /// Treasury never undercharges on a division remainder. `None` means no
    /// usable rate: the caller must skip, not guess.
    pub fn price_zat(&self, name: &Name) -> Option<Zatoshis> {
        let usd = schedule_usd(name.as_str().len());
        let rate = self.rate()?.as_u64().max(1);
        let numer = u128::from(usd.as_u64()) * u128::from(COIN);
        let price = numer.div_ceil(u128::from(rate));
        u64::try_from(price)
            .ok()
            .and_then(|price| Zatoshis::from_u64(price).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_usd_parse_exact_and_rejected() {
        assert_eq!(MicroUsd::parse("41"), Some(MicroUsd(41_000_000)));
        assert_eq!(MicroUsd::parse("41.5"), Some(MicroUsd(41_500_000)));
        assert_eq!(
            MicroUsd::parse("41.234567"),
            Some(MicroUsd(41_234_567))
        );
        // Seven fraction digits exceed source precision: reject, don't round.
        assert_eq!(MicroUsd::parse("41.1234567"), None);
        for bad in ["", ".5", "41.", "-1", "+1", "4x", "1e2", "41.2.3"] {
            assert_eq!(MicroUsd::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn midpoint_floors_half_micro() {
        assert_eq!(
            MicroUsd(100).midpoint(MicroUsd(101)),
            Some(MicroUsd(100))
        );
        assert_eq!(
            MicroUsd(100).midpoint(MicroUsd(102)),
            Some(MicroUsd(101))
        );
    }

    #[test]
    fn schedule_is_decadal_with_100_floor() {
        assert_eq!(schedule_usd(1).as_u64(), 100_000_000_000_000);
        assert_eq!(schedule_usd(6).as_u64(), 1_000_000_000);
        assert_eq!(schedule_usd(7).as_u64(), 100_000_000);
        // Name::parse caps at 63; every 7+ length is the $100 floor.
        assert_eq!(schedule_usd(63).as_u64(), 100_000_000);
    }

    #[test]
    fn median_requires_three_usable_quotes() {
        let q = |v: u64| MicroUsd(v);
        // Trusted + one other: below the floor.
        assert_eq!(median_of_odd(Some(q(40)), vec![q(41)]), None);
        // One usable other, no trusted: below the floor.
        assert_eq!(median_of_odd(None, vec![q(40)]), None);
        // Trusted + two others: true median of three.
        assert_eq!(
            median_of_odd(Some(q(40)), vec![q(30), q(50)]),
            Some(q(40))
        );
        // No trusted, three others: median survives the eviction rule.
        assert_eq!(
            median_of_odd(None, vec![q(30), q(40), q(50)]),
            Some(q(40))
        );
    }

    /// Helper: create a `Timestamp` at the given Unix seconds.
    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_seconds(secs).unwrap()
    }

    #[test]
    fn cold_start_seeds_spot_rate() {
        let mut oracle = RateOracle::default();
        // No rate before first sample.
        assert!(oracle.rate().is_none());

        // First sample seeds a temporary spot rate.
        oracle.accumulate(MicroUsd(40_000_000), ts(1_000_000));
        assert_eq!(oracle.rate(), Some(MicroUsd(40_000_000)));
    }

    #[test]
    fn same_day_accumulation_does_not_publish() {
        let mut oracle = RateOracle::default();
        let day_start = 1_000_000; // arbitrary, well past epoch

        // First sample.
        oracle.accumulate(MicroUsd(40_000_000), ts(day_start));
        assert_eq!(oracle.rate(), Some(MicroUsd(40_000_000)));

        // More samples same day: rate unchanged (still the cold-start spot).
        oracle.accumulate(MicroUsd(50_000_000), ts(day_start + 60));
        oracle.accumulate(MicroUsd(45_000_000), ts(day_start + 120));
        assert_eq!(oracle.rate(), Some(MicroUsd(40_000_000)));
    }

    #[test]
    fn day_boundary_publishes_twap() {
        let mut oracle = RateOracle::default();
        // Pick a timestamp at 00:00:30 UTC on some day.
        let day_0 = 1_725_148_830; // 2024-09-01 00:00:30 UTC
        let day_0_midnight = 1_725_148_800;
        let day_1_midnight = day_0_midnight + SECONDS_PER_DAY;

        // Seed with first sample.
        oracle.accumulate(MicroUsd(40_000_000), ts(day_0));
        assert_eq!(oracle.rate(), Some(MicroUsd(40_000_000)));

        // Accumulate 14 more samples (total 15 ≥ MIN_SAMPLES) at $50.
        for i in 1..=14 {
            oracle.accumulate(
                MicroUsd(50_000_000),
                ts(day_0 + i * 60),
            );
        }
        // Rate still the cold-start spot.
        assert_eq!(oracle.rate(), Some(MicroUsd(40_000_000)));

        // Cross midnight: the TWAP of day 0 should be published.
        // The accumulator covers day_0 to day_0+14*60 = day_0+840s.
        // Intervals: 30s@40, 60s@40, 60s@50, 60s@50, ... 60s@50 (13 times)
        // Before midnight: from day_0+840 to midnight = (86400-840-30) = 85530s @ $50
        // Total sum = 30*40M + 60*40M + 13*60*50M + 85530*50M (all in micros)
        // = 1.2B + 2.4B + 39B + 4276.5B = 4319.1B
        // Total seconds = 30 + 60 + 13*60 + 85530 = 86400
        // TWAP = 4319.1B / 86400 ≈ 49989.58 micros ≈ $49.99
        // But with integer division: let's just check it's between 40 and 50,
        // closer to 50 since most of the day was at $50.
        oracle.accumulate(MicroUsd(45_000_000), ts(day_1_midnight + 30));
        let published = oracle.rate().unwrap();
        assert!(
            published.as_u64() > MicroUsd(49_000_000).as_u64(),
            "TWAP should be ~$50, got {}",
            published.as_u64()
        );
        assert!(
            published.as_u64() < MicroUsd(50_000_000).as_u64(),
            "TWAP should be < $50, got {}",
            published.as_u64()
        );
    }

    #[test]
    fn day_boundary_with_few_samples_keeps_old_rate() {
        let mut oracle = RateOracle::default();
        let day_0 = 1_725_148_830;
        let day_1_midnight = 1_725_148_800 + SECONDS_PER_DAY;

        // Seed and add just 2 samples (below MIN_SAMPLES).
        oracle.accumulate(MicroUsd(40_000_000), ts(day_0));
        oracle.accumulate(MicroUsd(60_000_000), ts(day_0 + 60));
        assert_eq!(oracle.rate(), Some(MicroUsd(40_000_000)));

        // Cross midnight: not enough samples, keep old rate.
        oracle.accumulate(MicroUsd(45_000_000), ts(day_1_midnight + 30));
        assert_eq!(oracle.rate(), Some(MicroUsd(40_000_000)));
    }

    #[test]
    fn price_converts_usd_to_zatoshis_with_ceil() {
        let mut oracle = RateOracle::default();
        oracle.daily_rate = Some(MicroUsd(40_000_000)); // $40/ZEC

        // $100 at $40 = exactly 2.5 ZEC — no rounding.
        let seven = Name::parse("abcdefg").unwrap();
        assert_eq!(
            oracle.price_zat(&seven),
            Some(Zatoshis::const_from_u64(250_000_000))
        );

        // $1000 at $40 = 25 ZEC exactly.
        let six = Name::parse("abcdef").unwrap();
        assert_eq!(
            oracle.price_zat(&six),
            Some(Zatoshis::const_from_u64(2_500_000_000))
        );

        // Non-divisible: $100 at $30 = 333.333… ZEC rounds up.
        oracle.daily_rate = Some(MicroUsd(30_000_000));
        assert_eq!(
            oracle.price_zat(&seven),
            Some(Zatoshis::const_from_u64(333_333_334))
        );

        // No rate: fail closed.
        let cold = RateOracle::default();
        assert_eq!(cold.price_zat(&seven), None);
    }
}
