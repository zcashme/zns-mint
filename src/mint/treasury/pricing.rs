//! Evaluation-time USD/ZEC claim pricing.
//!
//! The mint prices every claim against the USD/ZEC rate observed at the
//! moment the claim is evaluated — never a past rate. This is a deliberate
//! design constraint, not an implementation shortcut: no settlement decision
//! consults history, so no historical rate is ever stored, fetched, or
//! rebuilt. Crash recovery is rescan plus one fetch; nothing to reconcile.
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
//! A corrupted median requires holding ≥5 of 9 venues (or Gemini plus four)
//! during the fetch round. DNS or network interception cannot forge the
//! webpki-validated certificates. There is no operator input channel into
//! the rate: no env var, no config file, no RPC parameter. When a round
//! fails or the last success is older than [`RATE_GRACE_BLOCKS`], pricing
//! returns `None` and callers must pause claims — fail closed, never
//! misprice.
//!
//! Six sources quote ZEC/USDT rather than ZEC/USD; upstream pools them and
//! so does this port. The USDT basis is bps-level noise under a median.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use rand::seq::IteratorRandom;
use rand::rngs::OsRng;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::COIN;

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

/// How many blocks a successful rate may outlive its fetch. Roughly fifty
/// minutes at Zcash's nominal 75-second cadence: a transient fetch failure
/// (network blip, one bad round) does not pause claims, but a sustained
/// outage fails pricing closed within the hour.
pub const RATE_GRACE_BLOCKS: u32 = 40;

/// The mint's live USD/ZEC rate: one number, refreshed once per block, and
/// the only pricing state in the system.
///
/// There is no history here by design — `rate`/`fetched_at` are the whole
/// state, `Default` is a cold oracle, and a reboot re-derives everything
/// with one fetch. Claims must never be settled against a `None` rate.
#[derive(Default)]
pub struct RateOracle {
    /// The median-of-odd USD/ZEC rate from the last successful round.
    rate: Option<MicroUsd>,
    /// The chain tip the successful rate was fetched against.
    fetched_at: Option<BlockHeight>,
}

impl RateOracle {
    /// Runs one fetch round for `tip` and stores the result.
    ///
    /// A failed round (fewer than three usable quotes) keeps the previous
    /// rate; [`Self::rate`] enforces the grace window, so repeated failures
    /// age the rate out and pricing fails closed.
    pub async fn refresh(&mut self, tip: BlockHeight) {
        let (trusted, others) = fetch_round().await;
        match median_of_odd(trusted, others) {
            Some(median) => {
                self.rate = Some(median);
                self.fetched_at = Some(tip);
            }
            None => {
                tracing::warn!("pricing round failed; retaining previous rate under grace");
            }
        }
    }

    /// The live rate, or `None` if no round has ever succeeded or the last
    /// success is older than [`RATE_GRACE_BLOCKS`].
    pub fn rate(&self, tip: BlockHeight) -> Option<MicroUsd> {
        let fetched = self.fetched_at?;
        let age = u32::from(tip).saturating_sub(u32::from(fetched));
        (age <= RATE_GRACE_BLOCKS).then_some(self.rate)?
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
    pub fn price_zat(&self, name: &Name, tip: BlockHeight) -> Option<u64> {
        let usd = schedule_usd(name.as_str().len());
        let rate = self.rate(tip)?.as_u64().max(1);
        let numer = u128::from(usd.as_u64()) * u128::from(COIN);
        let price = numer.div_ceil(u128::from(rate));
        u64::try_from(price).ok()
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

    #[test]
    fn rate_is_grace_bounded_and_fail_closed() {
        let mut oracle = RateOracle::default;
        oracle.rate = Some(MicroUsd(40_000_000));
        oracle.fetched_at = Some(BlockHeight::from_u32(100));

        let at = |h: u32| BlockHeight::from_u32(h);
        assert!(oracle.rate(at(100)).is_some());
        assert!(oracle.rate(at(140)).is_some()); // exactly the grace bound
        assert!(oracle.rate(at(141)).is_none()); // one block past: fail closed
        // Cold oracle never prices.
        assert!(RateOracle::default().rate(at(141)).is_none());
    }

    #[test]
    fn price_converts_usd_to_zatoshis_with_ceil() {
        let mut oracle = RateOracle::default();
        oracle.rate = Some(MicroUsd(40_000_000)); // $40/ZEC
        oracle.fetched_at = Some(BlockHeight::from_u32(1));
        let tip = BlockHeight::from_u32(2);

        // $100 at $40 = exactly 2.5 ZEC — no rounding.
        let seven = Name::parse("abcdefg").unwrap();
        assert_eq!(oracle.price_zat(&seven, tip), Some(250_000_000));

        // $1000 at $40 = 25 ZEC exactly.
        let six = Name::parse("abcdef").unwrap();
        assert_eq!(oracle.price_zat(&six, tip), Some(2_500_000_000));

        // Non-divisible: $100 at $30 = 333.333… ZEC rounds up.
        oracle.rate = Some(MicroUsd(30_000_000));
        assert_eq!(oracle.price_zat(&seven, tip), Some(333_333_334));

        // Stale rate prices nothing.
        oracle.fetched_at = Some(BlockHeight::from_u32(1));
        let far = BlockHeight::from_u32(1 + RATE_GRACE_BLOCKS + 1);
        assert_eq!(oracle.price_zat(&seven, far), None);
    }
}
