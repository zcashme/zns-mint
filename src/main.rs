use zns_mint::{boot, metrics};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");

    tokio::spawn(metrics::serve());

    let boot = boot::Boot::run().await;

    metrics::set_boot_success(true);
    tracing::info!(
        height = u32::from(boot.height()),
        "zns-mint: boot complete; waiting for shutdown"
    );

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    tracing::info!("zns-mint: received ctrl-c, shutting down");
}
