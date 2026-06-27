mod boot;
mod key;
mod metrics;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");
    metrics::serve_metrics();
    tracing::info!("zns-mint: metrics listening on 127.0.0.1:9898");

    let boot = boot::boot().await;
    metrics::set_boot_success(true);

    tracing::info!("zns-mint: boot complete");
    tracing::info!(treasury_fvk = %boot.treasury_fvk_string(), "zns-mint: ready");
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("zns-mint shutting down");
}
