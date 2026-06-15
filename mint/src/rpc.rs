//! Read-only JSON-RPC control plane for operators (health + status).

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use serde::Serialize;

use crate::registry::Registry;
use crate::status::{ChainStatus, SharedChainStatus};

/// The `status` method result.
#[derive(Debug, Clone, Serialize)]
pub struct StatusResult {
    pub tip_height: u32,
    pub scan_tip_height: u32,
    pub spendable_zat: u64,
    pub mempool_notes: u64,
    pub spend_queue_depth: u32,
    pub in_flight: bool,
    pub treasury_available: bool,
    pub last_poll_unix: u64,
    pub names: u64,
    pub pending_challenges: u64,
}

#[rpc(server)]
pub trait MintApi {
    /// Liveness probe.
    #[method(name = "health")]
    fn health(&self) -> RpcResult<String>;

    /// Operational snapshot from the last poll tick + registry counters.
    #[method(name = "status")]
    async fn status(&self) -> RpcResult<StatusResult>;
}

/// Shared context behind the RPC server.
pub struct RpcContext {
    pub registry: Registry,
    pub status: SharedChainStatus,
}

#[jsonrpsee::core::async_trait]
impl MintApiServer for RpcContext {
    fn health(&self) -> RpcResult<String> {
        Ok("ok".into())
    }

    async fn status(&self) -> RpcResult<StatusResult> {
        let chain = *self.status.read().await;
        let stats = self.registry.stats().await.map_err(|e| {
            tracing::error!("status: {e}");
            ErrorObjectOwned::owned(-32603, "Internal error", None::<()>)
        })?;
        Ok(status_result(chain, stats))
    }
}

fn status_result(chain: ChainStatus, stats: crate::registry::RegistryStats) -> StatusResult {
    StatusResult {
        tip_height: chain.tip_height,
        scan_tip_height: chain.scan_tip_height,
        spendable_zat: chain.spendable_zat,
        mempool_notes: chain.mempool_notes,
        spend_queue_depth: chain.spend_queue_depth,
        in_flight: chain.in_flight,
        treasury_available: chain.treasury_available,
        last_poll_unix: chain.last_poll_unix,
        names: stats.names,
        pending_challenges: stats.pending_challenges,
    }
}

/// Serve the control plane on `addr` until `shutdown` fires or the server stops.
pub async fn serve(
    addr: String,
    ctx: RpcContext,
    mut shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<(), RpcError> {
    let server = Server::builder()
        .build(&addr)
        .await
        .map_err(|e| RpcError::Bind(format!("failed to bind RPC server: {e}")))?;
    let handle = server.start(ctx.into_rpc());
    let stopper = handle.clone();
    tracing::info!(%addr, "control plane listening");
    tokio::select! {
        _ = handle.stopped() => {}
        res = shutdown.changed() => {
            if res.is_ok() {
                tracing::debug!("stopping control plane");
                stopper
                    .stop()
                    .map_err(|e| RpcError::Bind(format!("rpc stop: {e}")))?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("rpc bind: {0}")]
    Bind(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::new_shared_status;
    use zns_state::State;

    #[tokio::test]
    async fn status_merges_chain_and_registry_counters() {
        let state = State::open_in_memory().unwrap();
        let registry = Registry::new(state);
        let status = new_shared_status();
        *status.write().await = ChainStatus {
            tip_height: 2_000_100,
            scan_tip_height: 2_000_050,
            spendable_zat: 42_000,
            mempool_notes: 3,
            spend_queue_depth: 2,
            in_flight: true,
            treasury_available: true,
            last_poll_unix: 1_700_000_000,
        };

        let ctx = RpcContext { registry, status };
        let result = ctx.status().await.unwrap();
        assert_eq!(result.tip_height, 2_000_100);
        assert_eq!(result.scan_tip_height, 2_000_050);
        assert_eq!(result.spendable_zat, 42_000);
        assert_eq!(result.mempool_notes, 3);
        assert_eq!(result.spend_queue_depth, 2);
        assert!(result.in_flight);
        assert!(result.treasury_available);
        assert_eq!(result.names, 0);
        assert_eq!(result.pending_challenges, 0);
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let registry = Registry::new(State::open_in_memory().unwrap());
        let ctx = RpcContext {
            registry,
            status: new_shared_status(),
        };
        assert_eq!(ctx.health().unwrap(), "ok");
    }
}