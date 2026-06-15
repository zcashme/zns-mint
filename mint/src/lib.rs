//! `zns-mint` — block-linear orchestrator.
//!
//! Scan runs ahead block-by-block; spend follows in a single lane. Names are
//! written when our Name Notes appear on chain — not at broadcast time.

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
use zns_state::{ScanTip, State, Treasury, TreasuryConfig, TreasuryError};

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

/// The orchestrator.
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
    pub async fn boot(config: MintConfig) -> Result<Self, BootError> {
        let state = State::open(&config.registry_db)?;

        let rewind_height = config.birthday.saturating_sub(config::STARTUP_REWIND_BLOCKS);
        if rewind_height > 0 {
            state.set_scan_tip(&ScanTip {
                height: rewind_height,
                hash: [0u8; 32],
            })?;
            tracing::info!(
                rewind_height,
                birthday = config.birthday,
                "startup: scan_tip rewound for safety re-sync"
            );
        }

        let registry = Registry::new(state);

        let policy = SpendPolicy {
            registry_addr: test_registry_address(),
            cold_addr: test_registry_address(),
            max_fee_zat: MINT_FEE_ZAT,
            high_watermark_zat: config.high_watermark_zat,
            low_watermark_zat: 0,
            max_mints_per_window: u32::MAX,
        };
        let signer = Arc::new(Signer::new_test(policy)?);

        let grpc = GrpcClient::new(&config.lwd_url);

        let treasury_config = TreasuryConfig {
            registry_fvk: signer.fvk().clone(),
            network: config.network,
            birthday: config.birthday,
        };
        let treasury = match Treasury::open(
            &config.treasury_wallet_db,
            &config.treasury_block_db,
            &treasury_config,
        ) {
            Ok(t) => {
                tracing::info!("treasury wallet open");
                Some(Mutex::new(t))
            }
            Err(TreasuryError::Uninitialized(_)) => match bootstrap_treasury(&grpc, &config, &treasury_config)
                .await
            {
                Ok(t) => {
                    tracing::info!(birthday = config.birthday, "treasury wallet bootstrapped");
                    Some(Mutex::new(t))
                }
                Err(e) => {
                    tracing::warn!(%e, "treasury bootstrap failed — scan-only");
                    None
                }
            },
            Err(e) => return Err(e.into()),
        };

        let scanner = ScannerConfig {
            registry_ivk: test_orchard_ivk(),
            sapling_ivk: Some(test_sapling_ivk()),
            network: config.network,
            birthday: config.birthday,
            lwd_url: config.lwd_url.clone(),
        };

        Ok(Self {
            grpc,
            spend: SpendLane::new(),
            chain_status: status::new_shared_status(),
            config,
            registry,
            treasury,
            signer,
            scanner,
        })
    }

    pub async fn run(self) -> Result<(), TickError> {
        let mint = Arc::new(self);
        tracing::info!(
            lwd = %mint.config.lwd_url,
            registry_db = %mint.config.registry_db,
            birthday = mint.config.birthday,
            treasury = mint.treasury.is_some(),
            rpc = %mint.config.rpc_bind,
            "zns-mint started (scan-ahead / single-lane spend)"
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

        let ctx = RpcContext {
            registry: mint.registry.clone(),
            status: Arc::clone(&mint.chain_status),
        };
        let addr = mint.config.rpc_bind.clone();
        let rpc_shutdown_rx = shutdown_rx.clone();
        let rpc_task = tokio::spawn(async move {
            if let Err(e) = rpc::serve(addr, ctx, rpc_shutdown_rx).await {
                tracing::error!(%e, "control plane stopped");
            }
        });

        let mut stop_after_tick = false;
        loop {
            mint.tick().await?;

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

async fn bootstrap_treasury(
    grpc: &GrpcClient,
    config: &MintConfig,
    treasury_config: &TreasuryConfig,
) -> Result<Treasury, TreasuryError> {
    let prior_height = config.birthday.saturating_sub(1);
    let treestate = grpc
        .tree_state(prior_height)
        .await
        .map_err(|e| TreasuryError::Init(format!("get_tree_state: {e}")))?;
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_treestate(treestate, None)
        .map_err(|_| TreasuryError::Init("invalid account birthday from tree state".into()))?;
    Treasury::initialize(
        &config.treasury_wallet_db,
        &config.treasury_block_db,
        treasury_config,
        birthday,
    )
}

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error(transparent)]
    State(#[from] zns_state::StateError),
    #[error(transparent)]
    Treasury(#[from] TreasuryError),
    #[error(transparent)]
    Sign(#[from] zns_signer::SignError),
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
    Treasury(#[from] TreasuryError),
}