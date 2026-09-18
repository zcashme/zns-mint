//! Daily USD/ZEC pricing.
//!

use std::time::Duration;

use http::Uri;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use rust_decimal::Decimal;
use time::Timestamp;
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

/// The trusted anchor venue: NYDFS-regulated Gemini.
const TRUSTED: &str = "gemini";

/// Timeout duration for one source end-to-end (connect + request + body).
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on one venue response body. Ticker payloads are a few hundred
/// bytes; anything larger is hostile or broken and is dropped before it
/// can spend the mint's memory.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// The plausible ZEC/USD price band, enforced per venue before the round
/// aggregates. The same predicate the venue fixtures assert: a print
/// outside it is a bug or an attack, and either way it poisons the rate.
const MAX_USD_PRICE: u64 = 1_000_000;

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
    let bytes = Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .ok()?
        .to_bytes();
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

pub async fn fetch_round() -> Option<Decimal> {
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
// Name schedule — the product's pricing law, independent of the rate
// ===========================================================================

/// Annual USD price by name length: the five tiers cover 1–5 character
/// names and longer names pay the flat minimum. All names are ASCII, so
/// byte length is character length. Repricing names changes this
/// schedule; it never touches the oracle.
const ANNUAL_USD: [u64; 5] = [10_000, 2_500, 800, 400, 100];
const MINIMUM_USD: u64 = 20;

/// Forever registration costs three annual prices.
const FOREVER_MULTIPLE: u64 = 3;

fn annual_usd(name: &Name) -> u64 {
    let len = name.as_str().len();
    if len <= ANNUAL_USD.len() {
        ANNUAL_USD[len - 1]
    } else {
        MINIMUM_USD
    }
}

// ===========================================================================
// Oracle
// ===========================================================================

/// The daily-rate oracle: a fold over pricing rounds. Rounds arrive as
/// `(price, MTP)` pairs and are accumulated into a time-weighted average
/// that publishes once per day. The day is not the oracle's to compute:
/// it arrives as a number from the run loop, which reads the chain
/// clock (#80, #85).
///
/// The rate is never optional. It is set at construction — boot fetches
/// the first round or the node does not start — and [`accumulate`]
/// can only replace it, never clear it: a failed round carries the
/// standing rate forward. Pricing is therefore fail-closed at birth and
/// fail-open in life; every reader of the rate is total.
///
/// [`accumulate`]: Oracle::accumulate
pub struct Oracle {
    /// Zats per USD, published daily. Set at construction, never cleared.
    daily_rate: Zatoshis,
    /// The current pricing day — days since the mint's birthday, handed
    /// in by the run loop. Stored, not derived from `last_ts`: after a
    /// reorg rewind the two diverge, and the stored day prevents a
    /// spurious publish when the scan returns to the present.
    current_day: i64,
    /// TWAP accumulator: Σ(price × seconds) for the current day so far.
    /// `Decimal` has ample range for a day's accumulation.
    acc_sum: Decimal,
    /// TWAP accumulator: Σ(seconds) for the current day so far.
    acc_seconds: u64,
    /// The price of the most recent round, carried forward between rounds
    /// for time-weighting (the price is assumed constant between rounds).
    /// USD per ZEC.
    last_price: Decimal,
    /// The Unix timestamp (seconds, MTP) of the most recent round.
    last_ts: i64,
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
    /// Creates the oracle from the first successful pricing round.
    /// Boot fetches a price or the node does not start; the rate is set
    /// here and only ever replaced by [`accumulate`](Self::accumulate).
    /// `today` is days since the mint's birthday, from the chain clock.
    pub fn new(initial_price: Decimal, today: i64, now: Timestamp) -> Self {
        let now_secs = now.as_seconds();
        Self {
            daily_rate: to_factor(initial_price)
                .expect("an in-range price always yields a positive rate"),
            current_day: today,
            acc_sum: Decimal::ZERO,
            acc_seconds: 0,
            last_price: initial_price,
            last_ts: now_secs,
        }
    }

    /// Folds one pricing round into the TWAP: the carried price is
    /// weighted by elapsed MTP time, and a completed day is published
    /// as the new daily rate. A failed round (`None`) accumulates
    /// nothing — and cannot even roll the day over; publication happens
    /// only on rounds that land.
    ///
    /// `price` is the round's ZEC/USD median, in USD per ZEC; `today`
    /// is days since the mint's birthday, told by the run loop. The
    /// boundary is wherever that says it is: the day runs to its last
    /// observation, and the interval crossing it is billed into the
    /// new day. A day with nothing accumulated carries the rate.
    pub fn accumulate(&mut self, price: Option<Decimal>, today: i64, now: Timestamp) {
        let Some(price) = price else {
            return;
        };

        if price <= Decimal::ZERO {
            tracing::warn!(price = %price, "pricing observation dropped: non-positive");
            return;
        }

        let now_secs = now.as_seconds();

        if today > self.current_day {
            if self.acc_seconds > 0 {
                if let Some(factor) = to_factor(self.acc_sum / Decimal::from(self.acc_seconds)) {
                    self.daily_rate = factor;
                }
            }
            self.acc_sum = Decimal::ZERO;
            self.acc_seconds = 0;
            self.current_day = today;
        }

        let elapsed = u64::try_from((now_secs - self.last_ts).max(0)).unwrap_or_default();
        self.acc_sum += self.last_price * Decimal::from(elapsed);
        self.acc_seconds += elapsed;

        self.last_price = price;
        self.last_ts = now_secs;
    }

    /// The published daily conversion: zats per USD. Present from
    /// construction, never absent.
    pub fn current(&self) -> Zatoshis {
        self.daily_rate
    }

    /// The binding registration quote: `N` annuals for an `Ny` term,
    /// `FOREVER_MULTIPLE` annuals for `forever` — the one pricing question
    /// the mint asks (issue #30). The schedule supplies the annual USD
    /// price, the oracle supplies the rate, the term supplies the
    /// multiple; composition lives here because the rate does. A year is
    /// `Term::Years(1)`; nothing else computes a price.
    pub fn quote(&self, name: &Name, term: Term) -> Zatoshis {
        let multiple = match term {
            Term::Forever => FOREVER_MULTIPLE,
            Term::Years(years) => years,
        };
        // The tier (USD) at the published rate (zats per USD) is the annual
        // price; schedule ≤ 30,000 USD and rate ≤ 10^8 zats/USD keep it
        // inside u64, and the capped term keeps the product in range.
        let annual = annual_usd(name) * self.current().into_u64();
        Zatoshis::from_u64(
            annual
                .checked_mul(multiple)
                .expect("registration quote fits u64"),
        )
        .expect("registration quote fits the Zcash monetary range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_publishes_spot_and_quotes() {
        // $1,000/ZEC ⇒ rate 100,000 zats per dollar, from the first round.
        let oracle = Oracle::new(Decimal::from(1_000), 0, Timestamp::from_seconds(0).unwrap());
        assert_eq!(oracle.current().into_u64(), 100_000);

        let short = Name::parse("a").unwrap();
        // A year is the annual tier price; forever is three of them.
        assert_eq!(
            oracle.quote(&short, Term::Years(1)).into_u64(),
            1_000_000_000
        );
        assert_eq!(
            oracle.quote(&short, Term::Forever).into_u64(),
            3_000_000_000
        );

        // Six-character names pay the flat minimum tier.
        let long = Name::parse("purple").unwrap();
        assert_eq!(oracle.quote(&long, Term::Years(1)).into_u64(), 2_000_000);
        assert_eq!(oracle.quote(&long, Term::Forever).into_u64(), 6_000_000);
    }

    /// The registration quote follows the term: N annuals for `Ny`, three
    /// for `forever` — the pricing law the run-loop join flattened to a
    /// flat forever quote (issue #30). Every tariff tier, priced by term.
    #[test]
    fn quote_prices_claims_by_term() {
        // $1,000/ZEC ⇒ rate 100,000 zats per dollar, from the first round.
        let oracle = Oracle::new(Decimal::from(1_000), 0, Timestamp::from_seconds(0).unwrap());

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
                oracle.quote(&name, Term::Years(1)).into_u64(),
                annual,
                "{name:?} 1y"
            );
            for years in [1u64, 2, 12, 99] {
                assert_eq!(
                    oracle.quote(&name, Term::Years(years)).into_u64(),
                    annual * years,
                    "{name:?} {years}y"
                );
            }
            // Forever keeps its three-annual multiple, not years-capped.
            assert_eq!(
                oracle.quote(&name, Term::Forever).into_u64(),
                annual * 3,
                "{name:?} forever"
            );
        }
    }

    #[test]
    fn accumulate_weights_the_day_and_publishes_on_rollover() {
        let mut oracle = Oracle::new(Decimal::from(800), 0, Timestamp::from_seconds(0).unwrap());
        assert_eq!(oracle.current().into_u64(), 125_000);

        // A day runs to its last observation: day 0 holds only the price
        // standing before 43,200 s, and the interval crossing the
        // boundary is billed into the new day. Same-day rounds never
        // publish.
        oracle.accumulate(
            Some(Decimal::from(900)),
            0,
            Timestamp::from_seconds(43_200).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 125_000);
        oracle.accumulate(
            Some(Decimal::from(900)),
            1,
            Timestamp::from_seconds(86_400).unwrap(),
        );
        // Rollover publishes day 0's average — 800, not 850: the 900
        // never weighed into the day it was seen in.
        assert_eq!(oracle.current().into_u64(), 125_000);

        // Day 1 held 900 across both halves; the day-2 rollover
        // publishes it: ceil(100,000,000 / 900) = 111,112.
        oracle.accumulate(
            Some(Decimal::from(800)),
            1,
            Timestamp::from_seconds(129_600).unwrap(),
        );
        oracle.accumulate(
            Some(Decimal::from(800)),
            2,
            Timestamp::from_seconds(172_800).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 111_112);
    }

    #[test]
    fn an_empty_day_carries_the_rate() {
        // No round lands in day 1; at day 2's first successful round the
        // rollover finds an empty day and yesterday's rate stands — the
        // rate never drifts toward a stale spot.
        let mut oracle = Oracle::new(Decimal::from(800), 0, Timestamp::from_seconds(0).unwrap());
        oracle.accumulate(None, 1, Timestamp::from_seconds(90_000).unwrap());
        oracle.accumulate(
            Some(Decimal::from(50)),
            2,
            Timestamp::from_seconds(200_000).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 125_000);
    }

    #[test]
    fn failed_rounds_carry_the_rate_until_a_round_lands() {
        let mut oracle = Oracle::new(Decimal::from(800), 0, Timestamp::from_seconds(0).unwrap());
        // Day 0→1: day 0 accumulated nothing, so the rollover publishes
        // nothing and the rate carries; the boundary-crossing interval
        // bills the carried price into day 1.
        oracle.accumulate(
            Some(Decimal::from(900)),
            1,
            Timestamp::from_seconds(86_400).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 125_000);

        // Two dead rounds — nothing moves, not even the day.
        oracle.accumulate(None, 1, Timestamp::from_seconds(86_401).unwrap());
        oracle.accumulate(None, 2, Timestamp::from_seconds(172_800).unwrap());
        assert_eq!(oracle.current().into_u64(), 125_000);

        // Recovery publishes day 1's carried average (800): the rate that
        // stood through the outage stands after it.
        oracle.accumulate(
            Some(Decimal::from(850)),
            2,
            Timestamp::from_seconds(172_860).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 125_000);
    }

    #[test]
    fn reorg_rewind_never_publishes() {
        let mut oracle = Oracle::new(Decimal::from(1_000), 0, Timestamp::from_seconds(0).unwrap());
        oracle.accumulate(
            Some(Decimal::from(1_000)),
            0,
            Timestamp::from_seconds(90_000).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 100_000);

        // A reorg rewinds MTP back into day 0.
        oracle.accumulate(
            Some(Decimal::from(1_000)),
            0,
            Timestamp::from_seconds(80_000).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 100_000);

        // The scan returns to the present: still no publish — the stored
        // current_day prevents a spurious rollover.
        oracle.accumulate(
            Some(Decimal::from(1_000)),
            0,
            Timestamp::from_seconds(95_000).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 100_000);

        // The genuine day-1 rollover publishes the day's average — every
        // price was 1,000, so the same rate.
        oracle.accumulate(
            Some(Decimal::from(1_000)),
            1,
            Timestamp::from_seconds(172_800).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 100_000);
    }
}
