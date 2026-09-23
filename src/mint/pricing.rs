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

/// The trusted anchor venue: NYDFS-regulated Gemini. Below the
/// median quorum (N < 3), only Gemini's own quote publishes; no
/// two-source mean is ever taken.
const TRUSTED: &str = "gemini";

/// A day publishes only when at least this share of its fetch attempts
/// landed a price.
const MIN_DAY_SUCCESS_PERCENT: u64 = 50;

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

/// The daily-rate oracle: the zats-per-USD rate, republished daily as
/// a time-weighted average of that day's pricing rounds.
pub struct Oracle {
    /// Zats per USD, published daily. Set at construction, never cleared.
    daily_rate: Zatoshis,
    /// Days passed since the mint's birthday.
    current_day: i64,
    /// Accumulated sum of TWAP accumulator: Σ(price × seconds) for the current day so far.
    acc_sum: Decimal,
    /// Accumulated seconds of TWAP accumulator: Σ(seconds) for the current day so far.
    acc_seconds: u64,
    /// The USD per ZEC price of the most recent round, stored for time-weighting
    last_price: Decimal,
    /// The Unix timestamp (seconds, MTP) of the most recent accumulation round.
    last_ts: i64,
    /// Fetch attempts counted toward the current day, success or fail.
    rounds_attempted: u32,
    /// Attempts that produced a usable price.
    rounds_seen: u32,
}

/// ZEC price (USD per ZEC) → rate (zats per USD): 10^8 zats over the
/// price, rounded up so a quote never lands below its USD tariff.
fn zats_per_usd(usd_per_zec: Decimal) -> Option<Zatoshis> {
    if usd_per_zec <= Decimal::ZERO {
        tracing::warn!("pricing publish refused: non-positive daily average");
        return None;
    }
    u64::try_from((Decimal::from(COIN) / usd_per_zec).ceil())
        .ok()
        .and_then(|zats| Zatoshis::from_u64(zats).ok())
}

impl Oracle {
    /// Creates the oracle from the first successful pricing round: the
    /// spot price is the rate until the first rollover publishes a day.
    pub fn new(initial_price: Decimal, today: i64, now: Timestamp) -> Self {
        let now_secs = now.as_seconds();
        Self {
            daily_rate: zats_per_usd(initial_price)
                .expect("an in-range price always yields a positive rate"),
            current_day: today,
            acc_sum: Decimal::ZERO,
            acc_seconds: 0,
            last_price: initial_price,
            last_ts: now_secs,
            rounds_attempted: 0,
            rounds_seen: 0,
        }
    }

    /// The current published rate of ZEC in zats per USD.
    pub fn current(&self) -> Zatoshis {
        self.daily_rate
    }

    /// Folds one round into the day's TWAP. A new day publishes only when
    /// at least half of that day's fetches landed; thinner days keep their rate.
    pub fn accumulate(&mut self, price: Option<Decimal>, today: i64, now: Timestamp) {
        let now_secs = now.as_seconds();

        if now_secs < self.last_ts {
            // A reorg rewound MTP behind the last round: those seconds
            // are already billed — the round lands when the scan returns.
            return;
        }

        if today > self.current_day {
            if self.acc_seconds > 0
                && u64::from(self.rounds_seen).saturating_mul(100)
                    >= u64::from(self.rounds_attempted).saturating_mul(MIN_DAY_SUCCESS_PERCENT)
            {
                if let Some(rate) = zats_per_usd(self.acc_sum / Decimal::from(self.acc_seconds)) {
                    self.daily_rate = rate;
                }
            }
            self.acc_sum = Decimal::ZERO;
            self.acc_seconds = 0;
            self.rounds_attempted = 0;
            self.rounds_seen = 0;
            self.current_day = today;
        }

        self.rounds_attempted = self.rounds_attempted.saturating_add(1);

        let Some(price) = price else {
            return;
        };

        if price <= Decimal::ZERO {
            tracing::warn!(price = %price, "pricing observation dropped: non-positive");
            return;
        }

        let elapsed = (now_secs - self.last_ts) as u64;
        self.acc_sum += self.last_price * Decimal::from(elapsed);
        self.acc_seconds += elapsed;

        self.last_price = price;
        self.last_ts = now_secs;
        self.rounds_seen = self.rounds_seen.saturating_add(1);
    }

    /// Registration quote in zats at the published rate. `None` when the
    /// product does not fit a zat amount.
    pub fn quote(&self, name: &Name, term: Term) -> Option<Zatoshis> {
        let usd = match term {
            Term::Forever => forever_usd(name),
            Term::Years(years) => annual_usd(name) * years,
        };
        let zats = usd.checked_mul(self.current().into_u64())?;
        Zatoshis::from_u64(zats).ok()
    }

    /// The challenge fee (issue #18): the minimum payment that triggers a
    /// controller challenge — one dollar at the current published rate,
    /// rounded up to the next 100_000-zat increment. Anti-spam pricing,
    /// not revenue: the drain refuses underpaid relay requests outright.
    pub fn challenge_fee(&self) -> Zatoshis {
        const GRID: u64 = 100_000;
        let rate = self.current().into_u64();
        // Checked so the grid step cannot wrap.
        let zats = rate
            .div_ceil(GRID)
            .checked_mul(GRID)
            .expect("challenge fee fits u64");
        Zatoshis::from_u64(zats).expect("challenge fee fits the Zcash monetary range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted(oracle: &Oracle, name: &Name, term: Term) -> u64 {
        oracle.quote(name, term).expect("quote fits").into_u64()
    }

    #[test]
    fn challenge_fee_rounds_one_dollar_up_to_the_grid() {
        // $1,000/ZEC ⇒ $1 = 100_000 zats: exactly on the grid.
        let oracle = Oracle::new(Decimal::from(1_000), 0, Timestamp::from_seconds(0).unwrap());
        assert_eq!(oracle.challenge_fee().into_u64(), 100_000);

        // $800/ZEC ⇒ $1 = 125_000 zats, the issue-#18 rounding: one grid
        // step up, to 200_000.
        let oracle = Oracle::new(Decimal::from(800), 0, Timestamp::from_seconds(0).unwrap());
        assert_eq!(oracle.challenge_fee().into_u64(), 200_000);

        // $400/ZEC ⇒ $1 = 250_000 zats, mid-grid: up to 300_000.
        let oracle = Oracle::new(Decimal::from(400), 0, Timestamp::from_seconds(0).unwrap());
        assert_eq!(oracle.challenge_fee().into_u64(), 300_000);

        // $10,000/ZEC ⇒ $1 = 10_000 zats, below the grid: the 100_000
        // floor holds.
        let oracle = Oracle::new(
            Decimal::from(10_000),
            0,
            Timestamp::from_seconds(0).unwrap(),
        );
        assert_eq!(oracle.challenge_fee().into_u64(), 100_000);
    }

    #[test]
    fn construction_publishes_spot_and_quotes() {
        // $1,000/ZEC ⇒ rate 100,000 zats per dollar, from the first round.
        let oracle = Oracle::new(Decimal::from(1_000), 0, Timestamp::from_seconds(0).unwrap());
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
    fn a_thin_day_keeps_yesterdays_rate() {
        let mut oracle = Oracle::new(Decimal::from(800), 0, Timestamp::from_seconds(0).unwrap());
        // Close day 0 at 800 and open day 1 weighting 900.
        oracle.accumulate(
            Some(Decimal::from(900)),
            0,
            Timestamp::from_seconds(43_200).unwrap(),
        );
        oracle.accumulate(
            Some(Decimal::from(900)),
            1,
            Timestamp::from_seconds(86_400).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 125_000);

        // Day 1: one success and two misses (1/3). Rollover refuses the
        // 900 TWAP and yesterday's 800 rate stands.
        oracle.accumulate(None, 1, Timestamp::from_seconds(86_401).unwrap());
        oracle.accumulate(None, 1, Timestamp::from_seconds(86_402).unwrap());
        oracle.accumulate(
            Some(Decimal::from(800)),
            2,
            Timestamp::from_seconds(172_800).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 125_000);
    }

    #[test]
    fn a_half_successful_day_publishes() {
        let mut oracle = Oracle::new(Decimal::from(800), 0, Timestamp::from_seconds(0).unwrap());
        oracle.accumulate(
            Some(Decimal::from(900)),
            0,
            Timestamp::from_seconds(43_200).unwrap(),
        );
        oracle.accumulate(
            Some(Decimal::from(900)),
            1,
            Timestamp::from_seconds(86_400).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 125_000);

        // Day 1: one success and one miss (1/2). Rollover publishes 900.
        oracle.accumulate(None, 1, Timestamp::from_seconds(86_401).unwrap());
        oracle.accumulate(
            Some(Decimal::from(800)),
            2,
            Timestamp::from_seconds(172_800).unwrap(),
        );
        assert_eq!(oracle.current().into_u64(), 111_112);
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
