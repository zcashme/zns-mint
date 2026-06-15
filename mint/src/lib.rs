//! `zns-mint` — block-linear orchestrator.
//!
//! Scan runs ahead block-by-block; spend follows in a single lane. Names are
//! written when our Name Notes appear on chain — not at broadcast time.

mod boot;
mod config;
mod scan;
mod spend;
mod sweep;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::Mutex;
use zcash_protocol::consensus::Network;
use zns_chain::{connect, scan_mempool, GrpcClient, GrpcError, ScannerConfig};
use zns_signer::Signer;
use zns_state::{Name, State, StateError, Treasury, TreasuryError};

pub use boot::{boot, BootError};
pub use config::{MintConfig, POLL_INTERVAL};

use spend::SpendLane;

/// Table counters for the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RegistryStats {
    pub names: u64,
    pub pending_challenges: u64,
}

/// Async handle to the registry SQLite store.
#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<State>>,
}

impl Registry {
    pub fn new(state: State) -> Self {
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, State> {
        self.inner.lock().await
    }

    pub async fn lookup(&self, name: &str) -> Result<Option<Name>, StateError> {
        let st = self.inner.lock().await;
        st.get_record(name)
    }

    pub async fn stats(&self) -> Result<RegistryStats, StateError> {
        let st = self.inner.lock().await;
        let (names, pending_challenges) = st.table_counts()?;
        Ok(RegistryStats {
            names,
            pending_challenges,
        })
    }
}

/// Operator snapshot from the latest completed tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct TickSnapshot {
    pub tip_height: u32,
    pub scan_tip_height: u32,
    pub spendable_zat: u64,
    pub mempool_notes: u64,
    pub spend_queue_depth: u32,
    pub in_flight: bool,
    pub treasury_available: bool,
    pub last_poll_unix: u64,
    pub last_sweep_height: u32,
    pub last_sweep_txid: Option<[u8; 32]>,
}

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

    /// Observations after a tick (for the binary control plane).
    pub async fn snapshot(&self, chain_tip: u32) -> TickSnapshot {
        let scan_tip_height = {
            let st = self.registry.lock().await;
            st.get_scan_tip()
                .ok()
                .flatten()
                .map(|t| t.height)
                .unwrap_or(0)
        };

        let in_flight = {
            let st = self.registry.lock().await;
            st.get_in_flight().ok().flatten().is_some()
        };

        let spendable_zat = if let Some(treasury) = self.spend.treasury.as_ref() {
            let mut t = treasury.lock().await;
            t.select_funding(config::MINT_FEE_ZAT, config::ANCHOR_CONFIRMATIONS)
                .ok()
                .map(|f| f.spendable_total_zat)
                .unwrap_or(0)
        } else {
            0
        };

        let mempool_notes = scan_mempool(&self.chain.scanner, chain_tip)
            .await
            .map(|notes| notes.len() as u64)
            .unwrap_or(0);

        let (last_sweep_height, last_sweep_txid) = {
            let st = self.registry.lock().await;
            st.get_sweep_cursor()
                .ok()
                .map(|c| (c.height, c.txid))
                .unwrap_or((0, None))
        };

        let last_poll_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        TickSnapshot {
            tip_height: chain_tip,
            scan_tip_height,
            spendable_zat,
            mempool_notes,
            spend_queue_depth: self.spend.lane.pending_count() as u32,
            in_flight,
            treasury_available: self.spend.treasury.is_some(),
            last_poll_unix,
            last_sweep_height,
            last_sweep_txid,
        }
    }

    /// One protocol step. Returns chain tip height observed for this tick.
    pub async fn tick(&self) -> Result<u32, TickError> {
        let chain_tip = self.chain.grpc.tip_height().await?;
        self.spend.signer.roll_window();

        if let Some(reorg_at) = scan::handle_reorg(
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
            if let Err(e) = t.sync(&mut client).await {
                tracing::warn!(
                    %e,
                    "treasury sync failed; continuing tick (spend may defer until wallet recovers)"
                );
            }
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
    State(#[from] StateError),
    #[error(transparent)]
    Scan(#[from] scan::ScanSyncError),
    #[error(transparent)]
    Reorg(#[from] scan::ReorgError),
    #[error(transparent)]
    Spend(#[from] spend::SpendError),
    #[error(transparent)]
    Sweep(#[from] sweep::SweepError),
    #[error(transparent)]
    Treasury(#[from] TreasuryError),
}