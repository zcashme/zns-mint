//! The mint's Prometheus surface: three gauges and a scrape listener.
//!
//! Zebra's pattern, minus the knobs: the `metrics` facade resolves
//! every call site through the globally installed recorder, so there is
//! no registration plumbing anywhere else in the binary. The endpoint
//! binds loopback only — scrape it over the operator's SSH tunnel.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Loopback-only scrape endpoint.
pub const METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9464);

/// Installs the global recorder and HTTP listener. Must be called inside
/// the tokio runtime; `install` spawns the listener and upkeep tasks.
/// Panics on bind failure: an unmonitored mint should not boot.
pub fn install() {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(METRICS_ADDR)
        .install()
        .expect("FATAL: metrics endpoint bind failed");
    tracing::info!(addr = %METRICS_ADDR, "metrics endpoint listening");
}

/// Snapshots the three gauges. Called once per applied tip.
pub fn snapshot(
    tip: zcash_protocol::consensus::BlockHeight,
    treasury_zats: u64,
    oracle_zats_per_usd: u64,
) {
    metrics::gauge!("zns_mint_chain_tip_height").set(u32::from(tip) as f64);
    metrics::gauge!("zns_mint_treasury_zec").set(treasury_zats as f64 / 1e8);
    metrics::gauge!("zns_mint_oracle_zats_per_usd").set(oracle_zats_per_usd as f64);
}
