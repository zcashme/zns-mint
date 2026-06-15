//! `zns-mint` — block-linear orchestrator.
//!
//! Scan runs ahead block-by-block; spend follows in a single lane. Names are
//! written when our Name Notes appear on chain — not at broadcast time.

mod boot;
mod config;
mod record;
mod registry;
mod reorg;
mod rpc;
mod scan;
mod shutdown;
mod spend;
mod status;
mod sweep;

use std::sync::Arc;

use tokio::sync::Mutex;
use zns_state::Treasury;

pub use boot::{boot, BootError};
pub use config::MintConfig;
pub use config::{
    ANCHOR_CONFIRMATIONS, HIGH_WATERMARK_ZAT, MIN_CLAIM_FEE_ZAT, MIN_MUTATION_FEE_ZAT,
    MINT_FEE_ZAT, POLL_INTERVAL, RPC_BIND, TX_EXPIRY_BLOCKS,
};
pub use registry::{Registry, RegistryStats};
pub use rpc::{RpcContext, RpcError, StatusResult};
pub use spend::{QueuedSpend, SpendLane, SpendVerb};
pub use status::{ChainStatus, SharedChainStatus};
pub use zns_auth::{new_challenge, verify, PendingChallenge, CHALLENGE_TTL_BLOCKS};
pub use zns_chain::{
    connect, scan_blocks, scan_incoming, scan_incoming_all, GrpcClient, GrpcError, IncomingNote,
    ScannerConfig,
};
pub use zns_core::{memo, parse_memo, Action, MemoError, ParsedMemo, ZERO_PREV_RCM};
pub use zns_signer::{
    build_name_note, test_orchard_ivk, test_registry_address, test_sapling_ivk, FundingInput,
    MintIntent, MintParams, MintProposal, MintResult, RequestId, Signer, SpendPolicy,
};
pub use zns_state::{FundingSelection, InFlightSpend, Name, SpendableNote};

/// The orchestrator. Constructed only via [`boot`].
pub struct Mint {
    config: MintConfig,
    grpc: GrpcClient,
    registry: Registry,
    treasury: Option<Mutex<Treasury>>,
    signer: Arc<Signer>,
    scanner: ScannerConfig,
    spend: SpendLane,
    chain_status: SharedChainStatus,
}

impl Mint {
    pub async fn run(self) -> Result<(), TickError> {
        tracing::info!(
            lwd = %self.config.lwd_url,
            registry_db = %self.config.registry_db,
            birthday = self.config.birthday,
            treasury = self.treasury.is_some(),
            rpc = %self.config.rpc_bind,
            "zns-mint started (scan-ahead / single-lane spend)"
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

        let ctx = RpcContext {
            registry: self.registry.clone(),
            status: self.chain_status.clone(),
        };
        let addr = self.config.rpc_bind.clone();
        let rpc_shutdown_rx = shutdown_rx.clone();
        let rpc_task = tokio::spawn(async move {
            if let Err(e) = rpc::serve(addr, ctx, rpc_shutdown_rx).await {
                tracing::error!(%e, "control plane stopped");
            }
        });

        let mut stop_after_tick = false;
        loop {
            self.tick().await?;

            if stop_after_tick {
                break;
            }

            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
                _ = shutdown::wait_for_shutdown() => {
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

    pub async fn tick(&self) -> Result<(), TickError> {
        let chain_tip = self.grpc.tip_height().await?;
        self.signer.roll_window();

        if let Some(reorg_at) =
            reorg::handle_reorg(&self.registry, &self.grpc, &self.signer, chain_tip).await?
        {
            self.spend.reset();
            tracing::warn!(reorg_at, "replay scan from reorg height (spend lane cleared)");
        }

        {
            let st = self.registry.lock().await;
            st.purge_expired_challenges(chain_tip)?;
        }

        if let Some(treasury) = self.treasury.as_ref() {
            let mut client = connect(&self.config.lwd_url).await?;
            let mut t = treasury.lock().await;
            t.sync(&mut client).await?;
        }

        let blocks = scan::catch_up(
            &self.registry,
            &self.scanner,
            self.config.birthday,
            chain_tip,
            &self.spend,
        )
        .await?;
        if blocks > 0 {
            tracing::info!(blocks, chain_tip, "scan catch-up");
        }

        self.spend
            .tick(
                &self.registry,
                self.treasury.as_ref(),
                &self.signer,
                &self.grpc,
                self.config.network,
                chain_tip,
            )
            .await?;

        if let Some(treasury) = self.treasury.as_ref() {
            sweep::maybe_sweep(
                &self.registry,
                &self.spend,
                treasury,
                &self.signer,
                &self.grpc,
                self.config.network,
                chain_tip,
            )
            .await?;
        }

        status::record_tick_status(
            &self.chain_status,
            &self.registry,
            &self.spend,
            self.treasury.as_ref(),
            &self.scanner,
            chain_tip,
        )
        .await;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TickError {
    #[error(transparent)]
    Grpc(#[from] GrpcError),
    #[error(transparent)]
    State(#[from] zns_state::StateError),
    #[error(transparent)]
    Scan(#[from] scan::ScanSyncError),
    #[error(transparent)]
    Reorg(#[from] reorg::ReorgError),
    #[error(transparent)]
    Spend(#[from] spend::SpendError),
    #[error(transparent)]
    Sweep(#[from] sweep::SweepError),
    #[error(transparent)]
    Treasury(#[from] zns_state::TreasuryError),
}