//! `zns-mint` binary — boot, poll loop, JSON-RPC.

use zns_registry::{
    boot, new_shared_status, record_tick_status, serve, wait_for_shutdown, MintConfig, RpcContext,
    POLL_INTERVAL,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .map_err(|e| format!("tracing subscriber: {e}"))?;

    let config = MintConfig::default();
    let mint = boot(config.clone()).await?;

    tracing::info!(
        lwd = %config.lwd_url,
        registry_db = %config.registry_db,
        birthday = config.birthday,
        treasury = mint.has_treasury(),
        rpc = %config.rpc_bind,
        "zns-mint started (scan-ahead / single-lane spend)"
    );

    let status = new_shared_status();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    let rpc_task = tokio::spawn({
        let registry = mint.registry();
        let status = status.clone();
        let addr = config.rpc_bind.clone();
        let rpc_shutdown_rx = shutdown_rx.clone();
        async move {
            let ctx = RpcContext { registry, status };
            if let Err(e) = serve(addr, ctx, rpc_shutdown_rx).await {
                tracing::error!(%e, "control plane stopped");
            }
        }
    });

    let mut stop_after_tick = false;
    loop {
        let chain_tip = mint.tick().await?;
        record_tick_status(&status, &mint, chain_tip).await;

        if stop_after_tick {
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = wait_for_shutdown() => {
                tracing::info!("shutdown requested — finishing current tick");
                stop_after_tick = true;
            }
        }
    }

    drop(shutdown_tx);
    let _ = rpc_task.await;
    tracing::info!("zns-mint stopped");
    Ok(())
}