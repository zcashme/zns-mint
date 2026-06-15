//! One-time machine bring-up. Returns a [`Mint`](crate::Mint) ready for [`Mint::tick`](crate::Mint::tick).

use std::sync::Arc;

use tokio::sync::Mutex;
use zns_state::{ScanTip, State, Treasury, TreasuryConfig, TreasuryError};

use crate::config::{self, MintConfig, MINT_FEE_ZAT};
use crate::{Chain, Spend};
use crate::Registry;
use crate::spend::SpendLane;
use crate::Mint;
use zns_chain::{GrpcClient, ScannerConfig};
use zns_signer::{Signer, SpendPolicy, test_orchard_ivk, test_registry_address, test_sapling_ivk};

/// Open databases, wire keys and chain I/O, and return a runnable mint.
pub async fn boot(config: MintConfig) -> Result<Mint, BootError> {
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
        Err(TreasuryError::Uninitialized(_)) => {
            match bootstrap_treasury(&grpc, &config, &treasury_config).await {
                Ok(t) => {
                    tracing::info!(birthday = config.birthday, "treasury wallet bootstrapped");
                    Some(Mutex::new(t))
                }
                Err(e) => {
                    tracing::warn!(%e, "treasury bootstrap failed — scan-only");
                    None
                }
            }
        }
        Err(e) => return Err(e.into()),
    };

    let scanner = ScannerConfig {
        registry_ivk: test_orchard_ivk(),
        sapling_ivk: Some(test_sapling_ivk()),
        network: config.network,
        birthday: config.birthday,
        lwd_url: config.lwd_url.clone(),
    };

    Ok(Mint {
        chain: Chain {
            grpc,
            scanner,
            network: config.network,
            birthday: config.birthday,
            lwd_url: config.lwd_url,
        },
        registry,
        spend: Spend {
            signer,
            treasury,
            lane: SpendLane::new(),
        },
    })
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