//! The daemon control plane — a small JSON-RPC surface for operators and
//! orchestration (liveness probes, dashboards).
//!
//! Read-only by construction: it exposes counters and the poll loop's last
//! observations, never an operation. Spends only ever originate from the
//! intake → policy-gated signer path.

use std::sync::Arc;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::Registry;

/// What the poll loop last saw — refreshed every tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainStatus {
    /// Chain tip at the last poll.
    pub tip_height: u32,
    /// Spendable treasury balance at the last funding selection.
    pub spendable_zat: u64,
    /// Number of ZNS notes seen in the mempool at the last poll.
    pub mempool_notes: u64,
    /// Unix seconds of the last completed poll (0 = none yet).
    pub last_poll_unix: u64,
}

/// The `status` method's result.
#[derive(Debug, Clone, Serialize)]
pub struct StatusResult {
    /// Chain tip at the last poll.
    pub tip_height: u32,
    /// Spendable treasury balance in zatoshis.
    pub spendable_zat: u64,
    /// Number of ZNS notes seen in the mempool at the last poll.
    pub mempool_notes: u64,
    /// Unix seconds of the last completed poll.
    pub last_poll_unix: u64,
    /// Currently registered names.
    pub names: u64,
    /// Pending OTP challenges.
    pub pending_challenges: u64,
    /// In-flight mint intents (non-zero between a broadcast and its
    /// persistence, or while reconciliation is owed).
    pub mint_intents: u64,
}

/// The control-plane surface.
#[rpc(server)]
pub trait MintApi {
    /// Liveness: returns `"ok"` if the daemon is serving.
    #[method(name = "health")]
    fn health(&self) -> RpcResult<String>;

    /// The daemon's operational state — last poll observations + registry
    /// counters.
    #[method(name = "status")]
    async fn status(&self) -> RpcResult<StatusResult>;
}

/// Shared context behind the RPC.
pub struct RpcContext {
    /// Registry handle (read-only queries).
    pub registry: Registry,
    /// The poll loop's latest observations.
    pub status: Arc<RwLock<ChainStatus>>,
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
        Ok(StatusResult {
            tip_height: chain.tip_height,
            spendable_zat: chain.spendable_zat,
            mempool_notes: chain.mempool_notes,
            last_poll_unix: chain.last_poll_unix,
            names: stats.names,
            pending_challenges: stats.pending_challenges,
            mint_intents: stats.mint_intents,
        })
    }
}

/// Serve the control plane on `addr` until the server stops.
pub async fn serve(addr: String, ctx: RpcContext) -> Result<(), crate::RegistryError> {
    let server = Server::builder()
        .build(&addr)
        .await
        .map_err(|e| crate::RegistryError::Rpc(format!("failed to bind RPC server: {e}")))?;
    let handle = server.start(ctx.into_rpc());
    tracing::info!("control plane listening on {addr}");
    handle.stopped().await;
    Ok(())
}
