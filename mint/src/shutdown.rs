//! Graceful shutdown on Ctrl-C (all platforms) and SIGTERM (Unix).

/// Block until the process receives a shutdown signal.
pub async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
            _ = sigint.recv() => tracing::info!("received SIGINT"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to register Ctrl-C handler");
        tracing::info!("received Ctrl-C");
    }
}