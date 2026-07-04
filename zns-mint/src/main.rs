use zns_mint::{boot, metrics, registry::Registry};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");

    // Start the metrics server in a background task immediately, so we can
    // monitor the boot and sync processes via Prometheus.
    tokio::spawn(metrics::serve());

    // Boot Sequence
    let (mut chain, _keys, mut wallet, tip_height) = boot::boot().await;

    // Registry owns the name-chain state; Wallet owns note/tree state.
    // They are peers: the scanner borrows both per block, nothing owns both.
    let mut registry = Registry::new();

    // Bootstrap scanner state (injects Birthday Checkpoint if needed)
    let mut reorg_buffer = zns_mint::scanner::scan::bootstrap(&mut wallet).await;

    // Scan to tip
    zns_mint::scanner::scan::scan_to_tip(
        &mut chain,
        &mut wallet,
        &mut registry,
        &mut reorg_buffer,
        tip_height,
    )
    .await;

    metrics::set_boot_success(true);
    tracing::info!(height = u32::from(tip_height), "zns-mint: boot complete");
    tracing::info!("zns-mint: ready");

    //why is this here?
    std::future::pending::<()>().await;
}