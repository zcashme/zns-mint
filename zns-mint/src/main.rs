mod boot;
mod key;
mod metrics;

use zcash_protocol::consensus::TEST_NETWORK;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");

    let accounts = boot::boot().await;
    metrics::set_boot_success(true);

    tracing::info!("zns-mint: boot complete");
    tracing::info!(treasury_fvk = %accounts.treasury_fvk().encode(&TEST_NETWORK), "zns-mint: ready");
    tracing::info!(registry_fvk = %accounts.registry_fvk().encode(&TEST_NETWORK), "zns-mint: ready");
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("zns-mint shutting down");
}
