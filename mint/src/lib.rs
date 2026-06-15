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
use zcash_protocol::consensus::Network;
use zns_chain::{connect, GrpcClient, GrpcError, ScannerConfig};
use zns_signer::Signer;
use zns_state::Treasury;

pub use boot::{boot, BootError};
pub use config::{MintConfig, POLL_INTERVAL};
pub use rpc::{serve, RpcContext};
pub use shutdown::wait_for_shutdown;
pub use status::{new_shared_status, record_tick_status};

use registry::Registry;
use spend::SpendLane;

/// Registry scan + single-lane spend. Constructed only via [`boot`].
pub struct Mint {
    pub(crate) chain: Chain,
    pub(crate) registry: Registry,
    pub(crate) spend: Spend,
}

/// lightwalletd I/O and scan intake.
pub(crate) struct Chain {
    pub(crate) grpc: GrpcClient,
    pub(crate) scanner: ScannerConfig,
    pub(crate) network: Network,
    pub(crate) birthday: u32,
    pub(crate) lwd_url: String,
}

/// Signer, treasury wallet, spend queue.
pub(crate) struct Spend {
    pub(crate) signer: Arc<Signer>,
    pub(crate) treasury: Option<Mutex<Treasury>>,
    pub(crate) lane: SpendLane,
}

impl Mint {
    pub fn registry(&self) -> Registry {
        self.registry.clone()
    }

    pub fn has_treasury(&self) -> bool {
        self.spend.treasury.is_some()
    }

    /// One protocol step. Returns chain tip height observed for this tick.
    pub async fn tick(&self) -> Result<u32, TickError> {
        let chain_tip = self.chain.grpc.tip_height().await?;
        self.spend.signer.roll_window();

        if let Some(reorg_at) = reorg::handle_reorg(
            &self.registry,
            &self.chain.grpc,
            &self.spend.signer,
            chain_tip,
        )
        .await?
        {
            self.spend.lane.reset();
            tracing::warn!(reorg_at, "replay scan from reorg height (spend lane cleared)");
        }

        {
            let st = self.registry.lock().await;
            st.purge_expired_challenges(chain_tip)?;
        }

        if let Some(treasury) = self.spend.treasury.as_ref() {
            let mut client = connect(&self.chain.lwd_url).await?;
            let mut t = treasury.lock().await;
            t.sync(&mut client).await?;
        }

        let blocks = scan::catch_up(
            &self.registry,
            &self.chain.scanner,
            self.chain.birthday,
            chain_tip,
            &self.spend.lane,
        )
        .await?;
        if blocks > 0 {
            tracing::info!(blocks, chain_tip, "scan catch-up");
        }

        self.spend
            .lane
            .tick(
                &self.registry,
                self.spend.treasury.as_ref(),
                &self.spend.signer,
                &self.chain.grpc,
                self.chain.network,
                chain_tip,
            )
            .await?;

        if let Some(treasury) = self.spend.treasury.as_ref() {
            sweep::maybe_sweep(
                &self.registry,
                &self.spend.lane,
                treasury,
                &self.spend.signer,
                &self.chain.grpc,
                self.chain.network,
                chain_tip,
            )
            .await?;
        }

        Ok(chain_tip)
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