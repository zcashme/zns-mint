use lazy_static::lazy_static;
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

lazy_static! {
    pub static ref BOOT_SUCCESS: IntGauge = register_int_gauge!(
        "zns_mint_boot_success",
        "Boot success, 1 for success and 0 for failure"
    ).unwrap();

    pub static ref CHAIN_HEIGHT: IntGauge = register_int_gauge!(
        "zns_mint_chain_height",
        "The highest block height the scanner has processed"
    ).unwrap();

    pub static ref NAMES_REGISTERED: IntCounter = register_int_counter!(
        "zns_mint_names_registered_total",
        "Total number of names successfully registered"
    ).unwrap();

    pub static ref SPEND_ERRORS: IntCounterVec = register_int_counter_vec!(
        "zns_mint_spend_errors_total",
        "Total number of transaction spend errors",
        &["reason"]
    ).unwrap();
}

pub fn set_boot_success(success: bool) {
    BOOT_SUCCESS.set(if success { 1 } else { 0 });
}

pub fn set_chain_height(height: u32) {
    CHAIN_HEIGHT.set(height as i64);
}

pub fn inc_names_registered() {
    NAMES_REGISTERED.inc();
}

pub fn inc_spend_error(reason: &str) {
    SPEND_ERRORS.with_label_values(&[reason]).inc();
}
