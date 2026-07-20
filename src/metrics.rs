use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    Encoder, Histogram, IntCounter, IntCounterVec, IntGauge,
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

lazy_static! {
    // --- 1. Liveness & Progress ---
    pub static ref BOOT_SUCCESS: IntGauge = register_int_gauge!(
        "zns_mint_boot_success",
        "Boot success, 1 for success and 0 for failure"
    )
    .unwrap();
    pub static ref CHAIN_HEIGHT: IntGauge = register_int_gauge!(
        "zns_mint_chain_height",
        "The highest block height the scanner has processed"
    )
    .unwrap();
    pub static ref BLOCKS_SCANNED: IntCounter = register_int_counter!(
        "zns_mint_blocks_scanned_total",
        "Total number of blocks fully applied by the scanner"
    )
    .unwrap();

    // --- 2. Authentication (OTPs) ---
    pub static ref OTPS_ISSUED: IntCounter = register_int_counter!(
        "zns_mint_otps_issued_total",
        "Total number of OTP challenges issued to current controllers"
    )
    .unwrap();
    pub static ref OTPS_IN_FLIGHT: IntGauge = register_int_gauge!(
        "zns_mint_otps_in_flight",
        "Current number of pending OTP challenges awaiting user response"
    )
    .unwrap();
    pub static ref OTPS_VERIFIED: IntCounter = register_int_counter!(
        "zns_mint_otps_verified_total",
        "Total number of OTP challenges successfully verified and burned"
    )
    .unwrap();
    pub static ref OTPS_NEVER_RETURNED: IntCounter = register_int_counter!(
        "zns_mint_otps_never_returned_total",
        "Total number of OTP challenges pruned due to expiration without response"
    )
    .unwrap();

    // --- 3. Treasury & Requests ---
    pub static ref REQUESTS_RECEIVED: IntCounterVec = register_int_counter_vec!(
        "zns_mint_requests_received_total",
        "Total number of valid request memos received",
        &["action"] // claim, update, release
    )
    .unwrap();
    pub static ref REQUESTS_INVALID: IntCounterVec = register_int_counter_vec!(
        "zns_mint_requests_invalid_total",
        "Total number of invalid request memos rejected",
        &["reason"] // parse_error, invalid_state, bad_otp
    )
    .unwrap();
    pub static ref TREASURY_BALANCE: IntGauge = register_int_gauge!(
        "zns_mint_treasury_balance_zatoshis",
        "Current unspent balance of the Treasury account in zatoshis"
    )
    .unwrap();

    // --- 4. Registry & Names ---
    pub static ref NAMES_CLAIMED: IntCounter = register_int_counter!(
        "zns_mint_names_claimed_total",
        "Total number of new names successfully claimed"
    )
    .unwrap();
    pub static ref NAMES_UPDATED: IntCounter = register_int_counter!(
        "zns_mint_names_updated_total",
        "Total number of names successfully updated"
    )
    .unwrap();
    pub static ref NAMES_RELEASED: IntCounter = register_int_counter!(
        "zns_mint_names_released_total",
        "Total number of names successfully released"
    )
    .unwrap();
    pub static ref REGISTRY_FEE_NOTES: IntGauge = register_int_gauge!(
        "zns_mint_registry_fee_notes",
        "Current number of unspent UTXOs held by the Registry for fees"
    )
    .unwrap();

    // --- 5. Errors & Performance ---
    pub static ref RPC_ERRORS: IntCounterVec = register_int_counter_vec!(
        "zns_mint_rpc_errors_total",
        "Total number of Zebra RPC connection or request errors",
        &["endpoint"] // getblockchaininfo, chain_tip_change, etc.
    )
    .unwrap();
    pub static ref SPEND_ERRORS: IntCounterVec = register_int_counter_vec!(
        "zns_mint_spend_errors_total",
        "Total number of transaction spend/assembly errors",
        &["reason"]
    )
    .unwrap();
    pub static ref TRANSACTION_ASSEMBLY_SECONDS: Histogram = register_histogram!(
        "zns_mint_transaction_assembly_seconds",
        "Time spent building and proving Orchard/ZNS transactions"
    )
    .unwrap();
    pub static ref NO_FEE_LIQUIDITY_BLOCKS: IntCounter = register_int_counter!(
        "zns_mint_no_fee_liquidity_blocks_total",
        "Total number of blocks where operations were blocked due to unspendable/insufficient fee notes"
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Strongly-typed accessors
// ---------------------------------------------------------------------------

pub fn set_boot_success(success: bool) {
    BOOT_SUCCESS.set(if success { 1 } else { 0 });
}

pub fn set_chain_height(height: u32) {
    CHAIN_HEIGHT.set(height as i64);
}

pub fn inc_blocks_scanned() {
    BLOCKS_SCANNED.inc();
}

pub fn inc_otps_issued() {
    OTPS_ISSUED.inc();
    OTPS_IN_FLIGHT.inc();
}

pub fn inc_otps_verified() {
    OTPS_VERIFIED.inc();
    OTPS_IN_FLIGHT.dec();
}

pub fn inc_otps_never_returned(count: u64) {
    OTPS_NEVER_RETURNED.inc_by(count);
    OTPS_IN_FLIGHT.sub(count as i64);
}

pub fn inc_request_received(action: &str) {
    REQUESTS_RECEIVED.with_label_values(&[action]).inc();
}

pub fn inc_request_invalid(reason: &str) {
    REQUESTS_INVALID.with_label_values(&[reason]).inc();
}

pub fn set_treasury_balance(zatoshis: u64) {
    TREASURY_BALANCE.set(zatoshis as i64);
}

pub fn inc_names_claimed() {
    NAMES_CLAIMED.inc();
}

pub fn inc_names_updated() {
    NAMES_UPDATED.inc();
}

pub fn inc_names_released() {
    NAMES_RELEASED.inc();
}

pub fn set_registry_fee_notes(count: u64) {
    REGISTRY_FEE_NOTES.set(count as i64);
}

pub fn inc_rpc_error(endpoint: &str) {
    RPC_ERRORS.with_label_values(&[endpoint]).inc();
}

pub fn inc_spend_error(reason: &str) {
    SPEND_ERRORS.with_label_values(&[reason]).inc();
}

pub fn observe_transaction_assembly_seconds(seconds: f64) {
    TRANSACTION_ASSEMBLY_SECONDS.observe(seconds);
}

pub fn inc_no_fee_liquidity_blocks() {
    NO_FEE_LIQUIDITY_BLOCKS.inc();
}

