//! Daily USD/ZEC pricing.
//!

use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rust_decimal::Decimal;
use time::Timestamp;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tower_service::Service as TowerService;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{Zatoshis, COIN};

use crate::mint::Name;

// ===========================================================================
// Venues — the entire per-exchange configuration is data, one line each
// ===========================================================================

/// One ZEC spot venue: where to fetch and how to read the last price.
struct Exchange {
    /// Identity for logs and errors.
    name: &'static str,
    /// This venue's quote is always counted in the median (trusted anchor).
    trusted: bool,
    /// Ticker endpoint returning JSON.
    url: &'static str,
    /// RFC 6901 JSON pointer to the last-price value.
    pointer: &'static str,
}

const EXCHANGES: [Exchange; 9] = [
    Exchange {
        name: "gemini",
        trusted: true,
        url: "https://api.gemini.com/v2/ticker/zecusd",
        pointer: "/close",
    },
    Exchange {
        name: "kraken",
        trusted: false,
        url: "https://api.kraken.com/0/public/Ticker?pair=XZECZUSD",
        pointer: "/result/XZECZUSD/c/0",
    },
    Exchange {
        name: "coinbase",
        trusted: false,
        url: "https://api.exchange.coinbase.com/products/ZEC-USD/ticker",
        pointer: "/price",
    },
    Exchange {
        name: "bitstamp",
        trusted: false,
        url: "https://www.bitstamp.net/api/v2/ticker/zecusd/",
        pointer: "/last",
    },
    Exchange {
        name: "bitfinex",
        trusted: false,
        url: "https://api-pub.bitfinex.com/v2/ticker/tZECUSD",
        pointer: "/6",
    },
    Exchange {
        name: "okx",
        trusted: false,
        url: "https://www.okx.com/api/v5/market/ticker?instId=ZEC-USDT",
        pointer: "/data/0/last",
    },
    Exchange {
        name: "binance",
        trusted: false,
        url: "https://api.binance.com/api/v3/ticker/24hr?symbol=ZECUSDT",
        pointer: "/lastPrice",
    },
    Exchange {
        name: "kucoin",
        trusted: false,
        url: "https://api.kucoin.com/api/v1/market/stats?symbol=ZEC-USDT",
        pointer: "/data/last",
    },
    Exchange {
        name: "mexc",
        trusted: false,
        url: "https://api.mexc.com/api/v3/ticker/24hr?symbol=ZECUSDT",
        pointer: "/lastPrice",
    },
];

/// The trusted anchor venue: NYDFS-regulated Gemini.
const TRUSTED: usize = 0;

// ===========================================================================
// Fetch
// ===========================================================================

/// Deadline for one source end-to-end (connect + request + body). A slow
/// source is a dropped source; the round does not wait for stragglers.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// The webpki root store, no client auth. This is the entire trust anchor
/// for egress — a network interceptor can drop or stall a quote (the median
/// and timeouts absorb that) but cannot forge it.
fn tls_connector() -> TlsConnector {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// A TLS-wrapped TCP stream, presented to the pooled HTTP client.
#[derive(Debug)]
struct TlsConnection(TokioIo<TlsStream<tokio::net::TcpStream>>);

impl hyper_util::client::legacy::connect::Connection for TlsConnection {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl hyper::rt::Read for TlsConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        hyper::rt::Read::poll_read(std::pin::Pin::new(&mut self.0), cx, buf)
    }
}

impl hyper::rt::Write for TlsConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        hyper::rt::Write::poll_write(std::pin::Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        hyper::rt::Write::poll_flush(std::pin::Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        hyper::rt::Write::poll_shutdown(std::pin::Pin::new(&mut self.0), cx)
    }
}

/// DNS + TCP + TLS: the connector the pooled HTTP client uses to open
/// HTTPS connections. `Uri` in, TLS connection out.
#[derive(Clone)]
struct HttpsConnector {
    tls: TlsConnector,
}

impl TowerService<Uri> for HttpsConnector {
    type Response = TlsConnection;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls = self.tls.clone();
        Box::pin(async move {
            let host = uri.host().ok_or("uri has no host")?.to_string();
            let port = uri.port_u16().unwrap_or(443);
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            let server_name = ServerName::try_from(host)?;
            let stream = tls.connect(server_name, tcp).await?;
            Ok(TlsConnection(TokioIo::new(stream)))
        })
    }
}

type HttpsClient = Client<HttpsConnector, Empty<Bytes>>;

fn https_client(tls: TlsConnector) -> HttpsClient {
    Client::builder(TokioExecutor::new()).build(HttpsConnector { tls })
}

/// Fetches one venue's last price. Every failure mode — DNS, TCP, TLS, HTTP
/// status, JSON shape, pointer miss, malformed decimal — collapses to `None`
/// and the venue is dropped from the round.
async fn fetch_last(client: &HttpsClient, exchange: &Exchange) -> Option<Decimal> {
    let uri: Uri = exchange.url.parse().ok()?;
    let request = Request::builder()
        .uri(uri)
        .header("accept", "application/json")
        .body(Empty::<Bytes>::default())
        .ok()?;
    let response = tokio::time::timeout(FETCH_TIMEOUT, client.request(request))
        .await
        .ok()?
        .ok()?;
    if !response.status().is_success() {
        tracing::warn!(
            exchange = exchange.name,
            status = %response.status(),
            "pricing fetch rejected"
        );
        return None;
    }
    let bytes = response.into_body().collect().await.ok()?.to_bytes();
    let body: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(exchange = exchange.name, error = %e, "pricing JSON parse failed");
            return None;
        }
    };
    match body.pointer(exchange.pointer) {
        Some(v) => match serde_json::from_value::<Decimal>(v.clone()) {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::warn!(exchange = exchange.name, error = %e, "price value invalid");
                None
            }
        },
        None => {
            tracing::warn!(
                exchange = exchange.name,
                pointer = exchange.pointer,
                "pricing pointer missed"
            );
            None
        }
    }
}

// ===========================================================================
// Aggregation
// ===========================================================================

/// Median over the round's quotes.
///
/// - the trusted quote (Gemini) is always counted when obtained;
/// - at least three usable quotes are required;
/// - odd count: the middle element; even count: the mean of the middle
///   two. No eviction, no randomness — the same quote set always produces
///   the same rate, so a published day-price is reproducible from its
///   inputs.
///
/// An attacker must control half the venues to move the published rate.
fn median(trusted: Option<Decimal>, mut quotes: Vec<Decimal>) -> Option<Decimal> {
    if let Some(t) = trusted {
        quotes.push(t);
    }
    if quotes.len() < 3 {
        return None;
    }
    quotes.sort_unstable();
    let mid = quotes.len() / 2;
    Some(if quotes.len() % 2 == 1 {
        quotes[mid]
    } else {
        (quotes[mid - 1] + quotes[mid]) / Decimal::TWO
    })
}

/// Queries all nine venues concurrently and returns the median last price.
///
/// The trusted venue is aggregated separately per the upstream rule. All
/// failures collapse to dropped venues; `None` means fewer than three
/// venues responded and the round failed.
async fn fetch_round() -> Option<Decimal> {
    let client = https_client(tls_connector());
    let mut set = tokio::task::JoinSet::new();
    for (index, exchange) in EXCHANGES.iter().enumerate() {
        let client = client.clone();
        set.spawn(async move {
            (index, tokio::time::timeout(FETCH_TIMEOUT, fetch_last(&client, exchange)).await.ok().flatten())
        });
    }

    let mut trusted = None;
    let mut others = Vec::new();
    while let Some(joined) = set.join_next().await {
        let (index, quote) = match joined {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "pricing task panicked");
                continue;
            }
        };
        if index == TRUSTED {
            trusted = quote;
            if quote.is_none() {
                tracing::warn!("trusted pricing source (gemini) failed");
            }
        } else if let Some(q) = quote {
            others.push(q);
        }
    }

    match median(trusted, others) {
        Some(m) => Some(m),
        None => {
            tracing::warn!("pricing round failed: fewer than three venues responded");
            None
        }
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
pub fn schedule_usd(len: usize) -> Decimal {
    Decimal::from(match len {
        1 => 100_000_000, // $100,000,000
        2 => 10_000_000,  // $10,000,000
        3 => 1_000_000,   // $1,000,000
        4 => 100_000,     // $100,000
        5 => 10_000,      // $10,000
        6 => 1_000,       // $1,000
        _ => 100,         // 7+ = $100
    })
}

// ===========================================================================
// Oracle
// ===========================================================================

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
/// If the mint is down for an entire day, every round fails, the accumulator
/// never advances, and the previous day's rate is retained. If no rate has
/// ever been published, [`RateOracle::rate`] returns `None` and callers must
/// pause claims — fail closed.
#[derive(Default)]
pub struct RateOracle {
    /// The published daily rate — yesterday's TWAP. Valid for all of today.
    daily_rate: Option<Decimal>,

    /// TWAP accumulator: Σ(price × seconds) for the current day so far.
    /// `Decimal` has ample range for a day's accumulation.
    acc_sum: Decimal,
    /// TWAP accumulator: Σ(seconds) for the current day so far.
    acc_seconds: u64,
    /// The price of the most recent sample, carried forward between samples
    /// for time-weighting (the price is assumed constant between samples).
    last_price: Option<Decimal>,
    /// The Unix timestamp (seconds) of the most recent sample.
    last_ts: i64,
    /// The UTC day number (`floor(unix_seconds / 86400)`) of the current
    /// accumulation.
    current_day: i64,
}

impl RateOracle {
    /// Runs one fetch round and accumulates the result into today's TWAP.
    ///
    /// Called once per block. A failed round (fewer than three usable quotes)
    /// is skipped — the accumulator simply doesn't advance. If a UTC day
    /// boundary has been crossed since the last sample, the previous day's
    /// TWAP is finalized and published as the new daily rate.
    pub async fn refresh(&mut self, _tip: BlockHeight) {
        let median = match fetch_round().await {
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
    /// published as the daily rate, and the accumulator resets for the new
    /// day.
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
    fn accumulate(&mut self, price: Decimal, now: Timestamp) {
        let now_secs = now.as_seconds();
        let today = now_secs.div_euclid(SECONDS_PER_DAY);

        // First ever sample: seed the accumulator and set a temporary spot
        // rate so the mint can operate immediately on cold start.
        if self.last_price.is_none() {
            self.current_day = today;
            self.last_price = Some(price);
            self.last_ts = now_secs;
            if self.daily_rate.is_none() {
                self.daily_rate = Some(price);
            }
            return;
        }

        let prev_price = self.last_price.unwrap();

        if today > self.current_day {
            // ── Day boundary: finalize yesterday, publish, reset ─────────
            let midnight = today * SECONDS_PER_DAY;
            let before_midnight = u64::try_from(midnight - self.last_ts).unwrap_or_default();

            // Close the old day with the carry-forward price active up to midnight.
            self.acc_sum += prev_price * Decimal::from(before_midnight);
            self.acc_seconds += before_midnight;

            // Publish yesterday's TWAP. The previous sample strictly predates
            // midnight, so `acc_seconds` is at least one — no zero division.
            self.daily_rate = Some(self.acc_sum / Decimal::from(self.acc_seconds));

            // Start the new day: carry-forward price is active from midnight.
            let after_midnight = u64::try_from(now_secs - midnight).unwrap_or_default();
            self.acc_sum = prev_price * Decimal::from(after_midnight);
            self.acc_seconds = after_midnight;
            self.current_day = today;
        } else {
            // ── Same day: accumulate the interval ────────────────────────
            let elapsed = u64::try_from(now_secs - self.last_ts).unwrap_or_default();
            self.acc_sum += prev_price * Decimal::from(elapsed);
            self.acc_seconds += elapsed;
        }

        // The new sample takes over as the carry-forward price.
        self.last_price = Some(price);
        self.last_ts = now_secs;
    }

    /// The published daily rate, or `None` if no rate has ever been published.
    pub fn rate(&self) -> Option<Decimal> {
        self.daily_rate
    }

    /// The claim price in zatoshis:
    ///
    /// ```text
    /// price = ceil( schedule_usd(len) × COIN / rate )
    /// ```
    ///
    /// Rounded up — the Treasury never undercharges on a division remainder.
    /// `None` means no usable rate: the caller must skip, not guess.
    pub fn price_zat(&self, name: &Name) -> Option<Zatoshis> {
        let usd = schedule_usd(name.as_str().len());
        let rate = self.rate()?.max(Decimal::ONE);
        let price = ((usd * Decimal::from(COIN)) / rate).ceil();
        u64::try_from(price)
            .ok()
            .and_then(|p| Zatoshis::from_u64(p).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(v: i64) -> Decimal {
        Decimal::from(v)
    }

    #[test]
    fn median_requires_three_usable_quotes() {
        // Trusted + one other: below the floor.
        assert_eq!(median(Some(d(40)), vec![d(41)]), None);
        // One usable other, no trusted: below the floor.
        assert_eq!(median(None, vec![d(40)]), None);
        // Trusted + two others: true median of three.
        assert_eq!(median(Some(d(40)), vec![d(30), d(50)]), Some(d(40)));
    }

    #[test]
    fn median_is_deterministic_for_even_counts() {
        // Four quotes: mean of the two middle values.
        assert_eq!(median(None, vec![d(30), d(40), d(50), d(60)]), Some(d(45)));
    }

    /// Helper: create a `Timestamp` at the given Unix seconds.
    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_seconds(secs).unwrap()
    }

    #[test]
    fn day_boundary_publishes_twap() {
        let mut oracle = RateOracle::default();
        let midnight = 1_725_148_800; // 2024-09-01 00:00:00 UTC

        // 12h @ $40, then 12h @ $50 → TWAP of the day is exactly $45.
        oracle.accumulate(d(40), ts(midnight));
        oracle.accumulate(d(50), ts(midnight + 43_200));
        assert_eq!(oracle.rate(), Some(d(40)));

        oracle.accumulate(d(45), ts(midnight + SECONDS_PER_DAY as i64 + 30));
        assert_eq!(oracle.rate(), Some(d(45)));
    }

    #[test]
    fn day_boundary_with_few_samples_still_publishes() {
        let mut oracle = RateOracle::default();
        let midnight = 1_725_148_800;

        // 12h @ $40, then 12h @ $60 (mint down in between is indistinguishable
        // — carry-forward fills the gap). Thin day still publishes: $50.
        oracle.accumulate(d(40), ts(midnight));
        oracle.accumulate(d(60), ts(midnight + 43_200));
        assert_eq!(oracle.rate(), Some(d(40)));

        oracle.accumulate(d(50), ts(midnight + SECONDS_PER_DAY as i64));
        assert_eq!(oracle.rate(), Some(d(50)));
    }

    #[test]
    fn price_converts_usd_to_zatoshis_with_ceil() {
        let mut oracle = RateOracle::default();
        oracle.daily_rate = Some(d(40)); // $40/ZEC

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
        oracle.daily_rate = Some(d(30));
        assert_eq!(
            oracle.price_zat(&seven),
            Some(Zatoshis::const_from_u64(333_333_334))
        );

        // No rate: fail closed.
        let cold = RateOracle::default();
        assert_eq!(cold.price_zat(&seven), None);
    }

    // ── Venue fixtures: every pointer asserted against a recorded body ──
    //
    // A typo'd pointer silently drops a venue at runtime; these fixtures
    // make pointer mistakes a test failure instead.
    #[test]
    fn venue_pointers_resolve_in_recorded_bodies() {
        let gemini = r#"{"symbol":"ZECUSD","open":"809.23","high":"849.22","low":"790.19","close":"831.43","changes":["798.91"],"bid":"832.15","ask":"832.16"}"#;
        let kraken = r#"{"error":[],"result":{"XZECZUSD":{"a":["831.60","1","1.000"],"b":["831.36","3","3.000"],"c":["833.37","0.05999736"],"v":["1792.18","17113.67"],"p":["836.08","828.17"],"t":[1411,13438],"l":["830.05","789.86"],"h":["843.67","847.96"],"o":"841.80"}}}"#;
        let coinbase = r#"{"ask":"833.5","bid":"833.49","volume":"95.7","trade_id":123,"price":"833.07","size":"0.05","time":"2026-08-30T03:00:00Z"}"#;
        let bitstamp = r#"{"timestamp":"1788058797","open":"839.00","high":"846.00","low":"789.95","last":"832.45","volume":"180.15","vwap":"815.35","bid":"831.23","ask":"845.00","side":"0","open_24":"807.71","percent_change_24":"3.06","market_type":"SPOT"}"#;
        let bitfinex =
            r#"[825.51,150.59,826.43,59.06,23.52,0.0292,826.51,535.94,839.8,783.12,1477726786000]"#;
        let okx = r#"{"code":"0","data":[{"instType":"SPOT","instId":"ZEC-USDT","last":"832.94","askPx":"832.97","bidPx":"832.96"}],"msg":""}"#;
        let binance = r#"{"symbol":"ZECUSDT","priceChange":"23.75","lastPrice":"832.98","bidPrice":"832.97","askPrice":"832.98"}"#;
        let kucoin = r#"{"code":"200000","data":{"time":1788058819905,"symbol":"ZEC-USDT","buy":"831.455","sell":"831.508","last":"831.49"}}"#;
        let mexc = r#"{"symbol":"ZECUSDT","high":"852","low":"789","lastPrice":"833","bidPrice":"832.9","askPrice":"833"}"#;

        let bodies: [(&str, &str); 9] = [
            ("gemini", gemini),
            ("kraken", kraken),
            ("coinbase", coinbase),
            ("bitstamp", bitstamp),
            ("bitfinex", bitfinex),
            ("okx", okx),
            ("binance", binance),
            ("kucoin", kucoin),
            ("mexc", mexc),
        ];

        for exchange in &EXCHANGES {
            let (name, body) = bodies
                .iter()
                .find(|(n, _)| *n == exchange.name)
                .unwrap_or_else(|| panic!("no fixture for venue {}", exchange.name));
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
            let price: Decimal = serde_json::from_value(parsed.pointer(exchange.pointer).unwrap())
                .unwrap_or_else(|e| panic!("{}.pointer({}) failed: {e}", name, exchange.pointer));
            assert!(
                price > Decimal::ONE && price < Decimal::from(1_000_000),
                "{name} price {price} outside plausible range"
            );
        }
    }
}
