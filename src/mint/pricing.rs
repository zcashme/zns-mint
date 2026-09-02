//! Daily USD/ZEC pricing.
//!

use std::time::Duration;

use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use rust_decimal::Decimal;
use time::Timestamp;
use zcash_protocol::value::{Zatoshis, COIN};

use crate::mint::Name;

/// ZEC spot-price provider
struct Exchange {
    name: &'static str,
    /// Ticker endpoint
    url: &'static str,
    /// RFC 6901 JSON pointer to the last-price value.
    pointer: &'static str,
}

const EXCHANGES: [Exchange; 9] = [
    Exchange {
        name: "gemini",
        url: "https://api.gemini.com/v2/ticker/zecusd",
        pointer: "/close",
    },
    Exchange {
        name: "kraken",
        url: "https://api.kraken.com/0/public/Ticker?pair=XZECZUSD",
        pointer: "/result/XZECZUSD/c/0",
    },
    Exchange {
        name: "coinbase",
        url: "https://api.exchange.coinbase.com/products/ZEC-USD/ticker",
        pointer: "/price",
    },
    Exchange {
        name: "bitstamp",
        url: "https://www.bitstamp.net/api/v2/ticker/zecusd/",
        pointer: "/last",
    },
    Exchange {
        name: "bitfinex",
        url: "https://api-pub.bitfinex.com/v2/ticker/tZECUSD",
        pointer: "/6",
    },
    Exchange {
        name: "okx",
        url: "https://www.okx.com/api/v5/market/ticker?instId=ZEC-USDT",
        pointer: "/data/0/last",
    },
    Exchange {
        name: "binance",
        url: "https://api.binance.com/api/v3/ticker/24hr?symbol=ZECUSDT",
        pointer: "/lastPrice",
    },
    Exchange {
        name: "kucoin",
        url: "https://api.kucoin.com/api/v1/market/stats?symbol=ZEC-USDT",
        pointer: "/data/last",
    },
    Exchange {
        name: "mexc",
        url: "https://api.mexc.com/api/v3/ticker/24hr?symbol=ZECUSDT",
        pointer: "/lastPrice",
    },
];

/// The trusted anchor venue: NYDFS-regulated Gemini.
const TRUSTED: &str = "gemini";

/// Timeout duration for one source end-to-end (connect + request + body).
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

fn https_client() -> HttpsClient {
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
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

fn aggregate(quotes: Vec<(&'static str, Decimal)>) -> Option<Decimal> {
    match quotes.len() {
        0 => None,
        1 => (quotes[0].0 == TRUSTED).then(|| quotes[0].1),
        2 => Some((quotes[0].1 + quotes[1].1) / Decimal::TWO),
        _ => {
            let mut rates: Vec<Decimal> = quotes.into_iter().map(|(_, rate)| rate).collect();
            rates.sort_unstable();
            let mid = rates.len() / 2;
            Some(if rates.len() % 2 == 1 {
                rates[mid]
            } else {
                (rates[mid - 1] + rates[mid]) / Decimal::TWO
            })
        }
    }
}

async fn fetch_round() -> Option<Decimal> {
    let client = https_client();
    let mut set = tokio::task::JoinSet::new();
    for exchange in EXCHANGES.iter() {
        let client = client.clone();
        set.spawn(async move {
            let name = exchange.name;
            (
                name,
                tokio::time::timeout(FETCH_TIMEOUT, fetch_last(&client, exchange))
                    .await
                    .ok()
                    .flatten(),
            )
        });
    }

    let mut quotes = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((name, Some(rate))) => quotes.push((name, rate)),
            Ok((_, None)) => {}
            Err(e) => {
                tracing::warn!(error = %e, "pricing task panicked");
            }
        }
    }

    aggregate(quotes)
}

// ===========================================================================
// Name schedule
// ===========================================================================

const TIERED_LENGTHS: usize = 5;
const ANNUAL_USD: [u32; TIERED_LENGTHS] = [10_000, 2_500, 800, 400, 100];
const MINIMUM_USD: u32 = 20;
const FOREVER_MULTIPLE: u32 = 3;

fn annual_usd(name: &Name) -> Decimal {
    let len = name.as_str().len();
    if len <= TIERED_LENGTHS {
        Decimal::from(ANNUAL_USD[len - 1])
    } else {
        Decimal::from(MINIMUM_USD)
    }
}

fn forever_usd(name: &Name) -> Decimal {
    annual_usd(name) * Decimal::from(FOREVER_MULTIPLE)
}

// ===========================================================================
// Oracle
// ===========================================================================

const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Default)]
pub struct Oracle {
    daily_rate: Option<Zatoshis>,

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

fn to_factor(avg: Decimal) -> Option<Zatoshis> {
    if avg <= Decimal::ZERO {
        tracing::warn!("pricing publish refused: non-positive daily average");
        return None;
    }
    let factor = u64::try_from((Decimal::from(COIN) / avg).ceil()).ok()?;
    Zatoshis::from_u64(factor).ok()
}

impl Oracle {
    pub fn ingest(&mut self, sample: Option<Decimal>, now: Timestamp) {
        let Some(sample) = sample else { return; };

        if sample <= Decimal::ZERO {
            tracing::warn!(sample = %sample, "pricing observation dropped: non-positive");
            return;
        }

        let now_secs = now.as_seconds();
        let today = now_secs.div_euclid(SECONDS_PER_DAY);

        let Some(prev_price) = self.last_price else {
            self.current_day = today;
            self.last_ts = now_secs;
            if let Some(factor) = to_factor(sample) {
                self.daily_rate = Some(factor);
            }
            self.last_price = Some(sample);
            return;
        };

        if today > self.current_day {
            let old_day_end = (self.current_day + 1) * SECONDS_PER_DAY;
            let boundary = old_day_end.min(now_secs);
            let billed = u64::try_from(boundary - self.last_ts).unwrap_or_default();
            self.acc_sum += prev_price * Decimal::from(billed);
            self.acc_seconds += billed;

            if let Some(factor) = to_factor(self.acc_sum / Decimal::from(self.acc_seconds)) {
                self.daily_rate = Some(factor);
            }

            self.acc_sum = prev_price * Decimal::from(now_secs - today * SECONDS_PER_DAY);
            self.acc_seconds =
                u64::try_from(now_secs - today * SECONDS_PER_DAY).unwrap_or_default();
            self.current_day = today;
        } else {
            let elapsed = u64::try_from((now_secs - self.last_ts).max(0)).unwrap_or_default();
            self.acc_sum += prev_price * Decimal::from(elapsed);
            self.acc_seconds += elapsed;
        }

        self.last_price = Some(sample);
        self.last_ts = now_secs;
    }

    pub fn quote(&self, name: &Name) -> Option<Zatoshis> {
        let usd = u64::try_from(forever_usd(name)).ok()?;
        let factor = self.daily_rate?.into_u64();
        let total = usd.checked_mul(factor)?;
        Zatoshis::from_u64(total).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn trusted_anchor_matches_exactly_one_venue() {
        let matches: Vec<_> = EXCHANGES
            .iter()
            .filter(|e| e.name == TRUSTED)
            .map(|e| e.name)
            .collect();
        assert_eq!(
            matches,
            [TRUSTED],
            "trusted name must match exactly one venue"
        );
    }
}
