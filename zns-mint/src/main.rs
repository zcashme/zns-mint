mod boot;
mod key;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");

    let _keys = boot::boot().await;

    tracing::info!("zns-mint: boot complete (keys derived)");
}
