use orchard::circuit::OrchardCircuitVersion;
use tokio::sync::Mutex as AsyncMutex;
use zcash_protocol::consensus::BranchId;
use zns_chain::GrpcClient;
use zns_signer::{FundingInput, Signer};
use zns_state::{InFlightSpend, Treasury, TreasuryError};

use crate::config::{ANCHOR_CONFIRMATIONS, MINT_FEE_ZAT, TX_EXPIRY_BLOCKS};
use crate::registry::Registry;
use crate::spend::SpendLane;

/// Drain hot treasury balance to cold when above the policy high watermark.
pub async fn maybe_sweep(
    registry: &Registry,
    spend: &SpendLane,
    treasury: &AsyncMutex<Treasury>,
    signer: &Signer,
    grpc: &GrpcClient,
    network: zcash_protocol::consensus::Network,
    _chain_tip: u32,
) -> Result<(), SweepError> {
    if !spend.is_idle(registry).await? {
        return Ok(());
    }

    let chain_tip = grpc.tip_height().await?;

    let (funding_note, hot_balance) = {
        let mut t = treasury.lock().await;
        let funding = t.select_funding(MINT_FEE_ZAT, ANCHOR_CONFIRMATIONS)?;
        (funding.note, funding.spendable_total_zat)
    };

    if signer.policy().evaluate_sweep(hot_balance).is_none() {
        return Ok(());
    }

    let Some(funding_note) = funding_note else {
        tracing::debug!("sweep deferred: treasury not spendable");
        return Ok(());
    };

    let expiry_height = chain_tip.saturating_add(TX_EXPIRY_BLOCKS);
    let branch_id = BranchId::for_height(&network, chain_tip.into());
    let funding = FundingInput {
        note: funding_note.note,
        merkle_path: funding_note.merkle_path,
        anchor: funding_note.anchor,
    };

    let result = signer.sign_sweep(
        funding,
        MINT_FEE_ZAT,
        branch_id,
        expiry_height,
        OrchardCircuitVersion::InsecurePreNu6_2,
    )?;

    match grpc.broadcast(result.tx_bytes).await {
        Ok(()) => {
            {
                let st = registry.lock().await;
                st.set_in_flight(&InFlightSpend {
                    txid: result.txid,
                    request_txid: [0u8; 32],
                    request_index: 0,
                    expiry_height,
                    relay: false,
                    sweep: true,
                    name: String::new(),
                })?;
            }

            tracing::info!(
                txid = %hex::encode(result.txid),
                amount_zat = result.amount_zat,
                hot_balance_zat = hot_balance,
                "broadcast cold sweep"
            );
        }
        Err(e) => {
            tracing::warn!(
                txid = %hex::encode(result.txid),
                error = %e,
                "sweep broadcast rejected; will retry"
            );
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    #[error(transparent)]
    State(#[from] zns_state::StateError),
    #[error(transparent)]
    Grpc(#[from] zns_chain::GrpcError),
    #[error(transparent)]
    Treasury(#[from] TreasuryError),
    #[error(transparent)]
    Sign(#[from] zns_signer::SignError),
}