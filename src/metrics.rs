use std::sync::LazyLock;

use prometheus::{
    register_int_counter, register_int_counter_vec, register_int_gauge, Encoder, IntCounter,
    IntCounterVec, IntGauge,
};

/// The bind address of the Prometheus exposition endpoint.
///
/// Hardcoded, not configurable: no env vars, no config files (AGENTS.md).
const METRICS_BIND: (&str, u16) = ("0.0.0.0", 9090);

/// Runs the Prometheus exposition HTTP server.
///
/// Serves `GET /metrics` returning the default registry in text format.
/// Intended to be spawned as a background task from `main.rs`:
///
/// ```ignore
/// tokio::spawn(metrics::serve());
/// ```
pub async fn serve() {
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(|| async {
            let encoder = prometheus::TextEncoder::new();
            let mut buffer = vec![];
            let metric_families = prometheus::gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            String::from_utf8(buffer).unwrap()
        }),
    );

    let addr = format!("{}:{}", METRICS_BIND.0, METRICS_BIND.1);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("metrics server: failed to bind");
    tracing::info!("Metrics server listening on http://{}/metrics", addr);
    axum::serve(listener, app)
        .await
        .expect("metrics server: axum::serve failed");
}

// ---------------------------------------------------------------------------
// Metric definitions (14 total: 8 counters, 6 gauges)
//
// Counters — events that happen. Watch their rate.
// Gauges   — state that exists right now. Watch the value.
// ---------------------------------------------------------------------------

// --- Gauges: state ---

static BOOT_SUCCESS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "zns_mint_boot_success",
        "Boot success, 1 for success and 0 for failure"
    )
    .expect("metric zns_mint_boot_success registration")
});

static CHAIN_HEIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "zns_mint_chain_height",
        "The highest block height the scanner has processed"
    )
    .expect("metric zns_mint_chain_height registration")
});

static TIP_HEIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "zns_mint_tip_height",
        "The current chain tip height from Zebra"
    )
    .expect("metric zns_mint_tip_height registration")
});

static TREASURY_BALANCE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "zns_mint_treasury_balance_zatoshis",
        "Current unspent balance of the Treasury account in zatoshis"
    )
    .expect("metric zns_mint_treasury_balance_zatoshis registration")
});

static REGISTRY_FEE_NOTES: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "zns_mint_registry_fee_notes",
        "Current number of unspent UTXOs held by the Registry for fees"
    )
    .expect("metric zns_mint_registry_fee_notes registration")
});

static TX_PENDING: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "zns_mint_transactions_pending",
        "Current number of submitted but unconfirmed transactions"
    )
    .expect("metric zns_mint_transactions_pending registration")
});

// --- Counters: events ---

static REORGS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "zns_mint_reorgs_total",
        "Total number of chain reorganizations detected by the scanner"
    )
    .expect("metric zns_mint_reorgs_total registration")
});

static REQUESTS_RECEIVED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zns_mint_requests_received_total",
        "Total number of valid request memos received",
        &["action"] // claim, update, release
    )
    .expect("metric zns_mint_requests_received_total registration")
});

static REQUESTS_INVALID: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zns_mint_requests_invalid_total",
        "Total number of invalid request memos rejected",
        &["reason"]
    )
    .expect("metric zns_mint_requests_invalid_total registration")
});

static TX_SUBMITTED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zns_mint_transactions_submitted_total",
        "Total number of transactions submitted to Zebra",
        &["kind"] // claim, update, release, otp_relay, replenish, sweep
    )
    .expect("metric zns_mint_transactions_submitted_total registration")
});

static TX_CONFIRMED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zns_mint_transactions_confirmed_total",
        "Total number of transactions confirmed in a block",
        &["kind"]
    )
    .expect("metric zns_mint_transactions_confirmed_total registration")
});

static TX_EXPIRED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zns_mint_transactions_expired_total",
        "Total number of transactions that expired without confirmation",
        &["kind"]
    )
    .expect("metric zns_mint_transactions_expired_total registration")
});

static RPC_ERRORS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zns_mint_rpc_errors_total",
        "Total number of Zebra RPC connection or request errors",
        &["endpoint"]
    )
    .expect("metric zns_mint_rpc_errors_total registration")
});

static SPEND_ERRORS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zns_mint_spend_errors_total",
        "Total number of transaction spend/assembly errors",
        &["reason"]
    )
    .expect("metric zns_mint_spend_errors_total registration")
});

// ---------------------------------------------------------------------------
// Strongly-typed accessors
// ---------------------------------------------------------------------------

pub fn set_boot_success(success: bool) {
    BOOT_SUCCESS.set(if success { 1 } else { 0 });
}

pub fn set_chain_height(height: u32) {
    CHAIN_HEIGHT.set(height as i64);
}

pub fn set_tip_height(height: u32) {
    TIP_HEIGHT.set(height as i64);
}

pub fn set_treasury_balance(zatoshis: u64) {
    TREASURY_BALANCE.set(zatoshis as i64);
}

pub fn set_registry_fee_notes(count: u64) {
    REGISTRY_FEE_NOTES.set(count as i64);
}

pub fn inc_reorg() {
    REORGS_TOTAL.inc();
}

pub fn inc_request_received(action: &str) {
    REQUESTS_RECEIVED.with_label_values(&[action]).inc();
}

pub fn inc_request_invalid(reason: &str) {
    REQUESTS_INVALID.with_label_values(&[reason]).inc();
}

pub fn inc_tx_submitted(kind: &str) {
    TX_SUBMITTED.with_label_values(&[kind]).inc();
    TX_PENDING.inc();
}

pub fn inc_tx_confirmed(kind: &str) {
    TX_CONFIRMED.with_label_values(&[kind]).inc();
    TX_PENDING.dec();
}

pub fn inc_tx_expired(kind: &str) {
    TX_EXPIRED.with_label_values(&[kind]).inc();
    TX_PENDING.dec();
}

pub fn inc_rpc_error(endpoint: &str) {
    RPC_ERRORS.with_label_values(&[endpoint]).inc();
}

pub fn inc_spend_error(reason: &str) {
    SPEND_ERRORS.with_label_values(&[reason]).inc();
}

// ---------------------------------------------------------------------------
// Composite gauge publishing
// ---------------------------------------------------------------------------

/// Publishes all wallet-derived canonical-state gauges.
///
/// Called once at boot and then on every live-phase cycle (when the cursor
/// is at the canonical tip) to refresh observability with post-sync state.
pub fn publish_wallet_gauges(
    wallet: &crate::wallet::Wallet,
    height: zcash_protocol::consensus::BlockHeight,
) {
    use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
    use crate::registry::{classify_registry_ironwood_note, RegistryNoteClass};

    set_chain_height(u32::from(height));
    set_treasury_balance(wallet.balance(TREASURY_ACCOUNT).into_u64());
    set_registry_fee_notes(
        wallet
            .ironwood_notes_for(REGISTRY_ACCOUNT)
            .filter(|note| classify_registry_ironwood_note(note) == RegistryNoteClass::Fee)
            .count() as u64,
    );
}
