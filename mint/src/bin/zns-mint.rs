//! `zns-mint` binary — boots the orchestrator and runs forever.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mint = zns_registry::Mint::boot(Default::default()).await?;
    mint.run().await?;

    Ok(())
}