//! USD/ZEC pricing.
//!

use std::collections::VecDeque;
use std::time::Duration;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::{Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use rust_decimal::Decimal;
use zcash_protocol::value::{Zatoshis, COIN};

use crate::mint::{Name, Term};

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

/// The trusted anchor venue: NYDFS-regulated Gemini. Below the
/// median quorum (N < 3), only Gemini's own quote publishes; no
/// two-source mean is ever taken.
const TRUSTED: &str = "gemini";

/// Timeout duration for one source end-to-end (connect + request + body).
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on one venue response body. Ticker payloads are a few hundred
/// bytes; anything larger is hostile or broken and is dropped before it
/// can spend the mint's memory.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// The plausible ZEC/USD price band, enforced per exchange before the round
/// aggregates. A value outside it is a bug or an attack, and either way it poisons the rate.
const MAX_USD_PRICE: u64 = 1_000_000;

/// The HTTP client to fetch pricing from exchanges.
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
/// status, JSON shape, pointer miss, malformed decimal, oversized body,
/// implausible price — collapses to `None` and the venue is dropped from
/// the round.
async fn fetch_last(client: &HttpsClient, exchange: &Exchange) -> Option<Decimal> {
    let uri: Uri = match exchange.url.parse() {
        Ok(uri) => uri,
        Err(error) => {
            tracing::warn!(exchange = exchange.name, %error, "pricing URL invalid");
            return None;
        }
    };
    let request = match Request::builder()
        .uri(uri)
        .header("accept", "application/json")
        .body(Empty::<Bytes>::default())
    {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(exchange = exchange.name, %error, "pricing request invalid");
            return None;
        }
    };
    let response = match tokio::time::timeout(FETCH_TIMEOUT, client.request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::warn!(exchange = exchange.name, %error, "pricing fetch failed");
            return None;
        }
        Err(_) => {
            tracing::warn!(exchange = exchange.name, "pricing fetch timed out");
            return None;
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            exchange = exchange.name,
            status = %response.status(),
            "pricing fetch rejected"
        );
        return None;
    }
    let bytes = match Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            tracing::warn!(exchange = exchange.name, %error, "pricing body unreadable");
            return None;
        }
    };
    let body: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(exchange = exchange.name, error = %e, "pricing JSON parse failed");
            return None;
        }
    };
    match body.pointer(exchange.pointer) {
        Some(v) => match serde_json::from_value::<Decimal>(v.clone()) {
            Ok(price) if price > Decimal::ONE && price < Decimal::from(MAX_USD_PRICE) => {
                Some(price)
            }
            Ok(price) => {
                tracing::warn!(
                    exchange = exchange.name,
                    price = %price,
                    "price out of plausible range"
                );
                None
            }
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
        // Below the median quorum, Gemini's own quote publishes alone
        // if present; the two-source mean is deliberately never taken.
        1 | 2 => quotes
            .iter()
            .find(|(name, _)| *name == TRUSTED)
            .map(|(_, rate)| *rate),
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

pub async fn fetch_round() -> Option<Decimal> {
    let client = https_client();
    let mut set = tokio::task::JoinSet::new();
    for exchange in EXCHANGES.iter() {
        let client = client.clone();
        set.spawn(async move {
            let name = exchange.name;
            (
                name,
                match tokio::time::timeout(FETCH_TIMEOUT, fetch_last(&client, exchange)).await {
                    Ok(price) => price,
                    Err(_) => {
                        tracing::warn!(exchange = name, "pricing venue timed out");
                        None
                    }
                },
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
// Name schedule — the product's pricing law, independent of the rate
// ===========================================================================

/// Annual USD price by name length: the five tiers cover 1–5 character
/// names and longer names pay the established minimum.
const ANNUAL_USD: [u64; 5] = [10_000, 2_500, 800, 400, 100];
const MINIMUM_USD: u64 = 20;

/// Forever registration of names costs three annual prices.
const FOREVER_MULTIPLE: u64 = 3;

fn annual_usd(name: &Name) -> u64 {
    let len = name.as_str().len();
    if len <= ANNUAL_USD.len() {
        ANNUAL_USD[len - 1]
    } else {
        MINIMUM_USD
    }
}

fn forever_usd(name: &Name) -> u64 {
    annual_usd(name) * FOREVER_MULTIPLE
}

// ===========================================================================
// Oracle
// ===========================================================================

/// The rounds the rate is taken over. A buyer who pays the spot price of
/// any of them pays enough.
const WINDOW: usize = 120;

/// The zats-per-USD rate: the lowest of the last [`WINDOW`] rounds that
/// returned a price.
pub struct Oracle {
    /// Never empty: a round with no price leaves the window as it is.
    rates: VecDeque<Zatoshis>,
}

/// ZEC price (USD per ZEC) → rate (zats per USD): 10^8 zats over the
/// price, rounded up so a quote never lands below its USD tariff.
fn zats_per_usd(usd_per_zec: Decimal) -> Option<Zatoshis> {
    if usd_per_zec <= Decimal::ZERO {
        tracing::warn!(price = %usd_per_zec, "pricing round dropped: non-positive");
        return None;
    }
    u64::try_from((Decimal::from(COIN) / usd_per_zec).ceil())
        .ok()
        .and_then(|zats| Zatoshis::from_u64(zats).ok())
}

impl Oracle {
    /// Creates the oracle from the first successful pricing round.
    pub fn new(initial_price: Decimal) -> Self {
        let rate =
            zats_per_usd(initial_price).expect("an in-range price always yields a positive rate");
        Self {
            rates: VecDeque::from([rate]),
        }
    }

    /// The rate in zats per USD.
    pub fn current(&self) -> Zatoshis {
        *self.rates.iter().min().expect("the window is never empty")
    }

    /// Adds one round to the window, dropping the oldest past [`WINDOW`].
    pub fn record(&mut self, price: Option<Decimal>) {
        let Some(rate) = price.and_then(zats_per_usd) else {
            return;
        };
        self.rates.push_back(rate);
        if self.rates.len() > WINDOW {
            self.rates.pop_front();
        }
    }

    /// Registration quote in zats at the published rate. `None` when the
    /// product does not fit a zat amount.
    pub fn quote(&self, name: &Name, term: Term) -> Option<Zatoshis> {
        Self::quote_at(self.current(), name, term)
    }

    /// Registration quote in zats at `rate` zats per USD. `None` when
    /// the product does not fit a zat amount.
    pub fn quote_at(rate: Zatoshis, name: &Name, term: Term) -> Option<Zatoshis> {
        let usd = match term {
            Term::Forever => forever_usd(name),
            Term::Years(years) => annual_usd(name) * years,
        };
        let zats = usd.checked_mul(rate.into_u64())?;
        Zatoshis::from_u64(zats).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted(oracle: &Oracle, name: &Name, term: Term) -> u64 {
        oracle.quote(name, term).expect("quote fits").into_u64()
    }

    /// Most venues quote a string; Bitfinex quotes a number.
    #[test]
    fn a_price_reads_from_a_string_or_a_number() {
        let price = Decimal::new(4153, 2);
        let string = serde_json::json!("41.53");
        let number = serde_json::json!(41.53);
        assert_eq!(serde_json::from_value::<Decimal>(string).unwrap(), price);
        assert_eq!(serde_json::from_value::<Decimal>(number).unwrap(), price);
    }

    #[test]
    fn construction_publishes_spot_and_quotes() {
        // $1,000/ZEC ⇒ rate 100,000 zats per dollar, from the first round.
        let oracle = Oracle::new(Decimal::from(1_000));
        assert_eq!(oracle.current().into_u64(), 100_000);

        let short = Name::parse("a").unwrap();
        // A year is the annual tier price; forever is three of them.
        assert_eq!(quoted(&oracle, &short, Term::Years(1)), 1_000_000_000);
        assert_eq!(quoted(&oracle, &short, Term::Forever), 3_000_000_000);

        // Six-character names pay the flat minimum tier.
        let long = Name::parse("purple").unwrap();
        assert_eq!(quoted(&oracle, &long, Term::Years(1)), 2_000_000);
        assert_eq!(quoted(&oracle, &long, Term::Forever), 6_000_000);
    }

    /// `quote_at` prices at the rate given; `quote` passes the published one.
    #[test]
    fn a_quote_at_a_given_rate() {
        let oracle = Oracle::new(Decimal::from(1_000));
        let name = Name::parse("purple").unwrap();
        let rate = Zatoshis::const_from_u64(200_000);
        let quote = Oracle::quote_at(rate, &name, Term::Years(1)).unwrap();
        assert_eq!(quote.into_u64(), 4_000_000);
        assert_eq!(
            oracle.quote(&name, Term::Years(1)),
            Oracle::quote_at(oracle.current(), &name, Term::Years(1))
        );
    }

    /// The registration quote follows the term: N annuals for `Ny`, three
    /// for `forever` — the pricing law the run-loop join flattened to a
    /// flat forever quote (issue #30). Every tariff tier, priced by term.
    #[test]
    fn quote_prices_claims_by_term() {
        // $1,000/ZEC ⇒ rate 100,000 zats per dollar, from the first round.
        let oracle = Oracle::new(Decimal::from(1_000));

        // Every tariff tier: lengths 1–5 pay the annual schedule, longer
        // names the flat minimum. The one-year quote is the tier's base.
        for (name, annual) in [
            ("a", 1_000_000_000u64),
            ("ab", 250_000_000),
            ("abc", 80_000_000),
            ("abcd", 40_000_000),
            ("abcde", 10_000_000),
            ("purple", 2_000_000),
        ] {
            let name = Name::parse(name).unwrap();
            assert_eq!(
                quoted(&oracle, &name, Term::Years(1)),
                annual,
                "{name:?} 1y"
            );
            for years in [1u64, 2, 12, 99] {
                assert_eq!(
                    quoted(&oracle, &name, Term::Years(years)),
                    annual * years,
                    "{name:?} {years}y"
                );
            }
            // Forever keeps its three-annual multiple, not years-capped.
            assert_eq!(
                quoted(&oracle, &name, Term::Forever),
                annual * 3,
                "{name:?} forever"
            );
        }
    }

    /// A buyer who paid the spot price of any round in the window pays
    /// enough: the rate is the window's lowest.
    #[test]
    fn the_rate_is_the_lowest_in_the_window() {
        let mut oracle = Oracle::new(Decimal::from(1_000));
        oracle.record(Some(Decimal::from(1_250)));
        assert_eq!(oracle.current().into_u64(), 80_000);
        oracle.record(Some(Decimal::from(900)));
        assert_eq!(oracle.current().into_u64(), 80_000);
    }

    #[test]
    fn a_round_leaves_the_window_after_window_more() {
        let mut oracle = Oracle::new(Decimal::from(1_250));
        for _ in 1..WINDOW {
            oracle.record(Some(Decimal::from(1_000)));
        }
        assert_eq!(oracle.current().into_u64(), 80_000);
        oracle.record(Some(Decimal::from(1_000)));
        assert_eq!(oracle.current().into_u64(), 100_000);
    }

    /// An outage keeps the window it had, so the rate never goes empty.
    #[test]
    fn a_round_with_no_price_keeps_the_window() {
        let mut oracle = Oracle::new(Decimal::from(1_000));
        for _ in 0..2 * WINDOW {
            oracle.record(None);
        }
        assert_eq!(oracle.current().into_u64(), 100_000);
    }

    #[test]
    fn aggregate_empty_is_none() {
        assert_eq!(aggregate(vec![]), None);
    }

    #[test]
    fn aggregate_below_quorum_without_gemini_is_none() {
        assert_eq!(aggregate(vec![("binance", Decimal::from(1_000))]), None);
        assert_eq!(
            aggregate(vec![
                ("binance", Decimal::from(1_000)),
                ("kucoin", Decimal::from(1_000)),
            ]),
            None
        );
    }

    #[test]
    fn aggregate_below_quorum_takes_gemini_alone() {
        // N = 1: Gemini publishes on its own.
        assert_eq!(
            aggregate(vec![("gemini", Decimal::from(1_000))]),
            Some(Decimal::from(1_000))
        );

        // N = 2 with Gemini: Gemini's quote — not the mean.
        assert_eq!(
            aggregate(vec![
                ("gemini", Decimal::from(1_000)),
                ("binance", Decimal::from(2_000)),
            ]),
            Some(Decimal::from(1_000))
        );
    }

    #[test]
    fn aggregate_odd_quorum_picks_middle() {
        let q = vec![
            ("a", Decimal::from(900)),
            ("b", Decimal::from(1_000)),
            ("c", Decimal::from(1_100)),
        ];
        assert_eq!(aggregate(q), Some(Decimal::from(1_000)));
    }

    #[test]
    fn aggregate_even_quorum_averages_middle_pair() {
        let q = vec![
            ("a", Decimal::from(900)),
            ("b", Decimal::from(1_000)),
            ("c", Decimal::from(1_100)),
            ("d", Decimal::from(1_200)),
        ];
        // (1_000 + 1_100) / 2 = 1_050
        assert_eq!(aggregate(q), Some(Decimal::from(1_050)));
    }

    /// One outlier sorts to min or max; the median is honest
    /// regardless of insertion order.
    #[test]
    fn aggregate_bounds_single_outlier() {
        let q = vec![
            ("a", Decimal::from(1_000)),
            ("b", Decimal::from(1_010)),
            ("attacker", Decimal::from(999_999)),
        ];
        assert_eq!(aggregate(q), Some(Decimal::from(1_010)));
    }
}
