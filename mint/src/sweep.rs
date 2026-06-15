use tokio::sync::Mutex as AsyncMutex;
use zcash_protocol::consensus::BranchId;
use zns_chain::GrpcClient;
use zns_signer::{FundingInput, Signer};
use zns_state::{SweepCursor, Treasury, TreasuryError};

use crate::config::{ANCHOR_CONFIRMATIONS, MINT_FEE_ZAT, SWEEP_INTERVAL_BLOCKS, TX_EXPIRY_BLOCKS};
use crate::consensus::orchard_circuit_version;
use crate::Registry;

fn sweep_due(chain_tip: u32, last_height: u32) -> bool {
    last_height == 0 || chain_tip >= last_height.saturating_add(SWEEP_INTERVAL_BLOCKS)
}

/// Drain hot treasury balance to cold when above the policy high watermark.
/// At most one attempt per [`SWEEP_INTERVAL_BLOCKS`]; cursor updated on successful broadcast.
pub async fn maybe_sweep(
    registry: &Registry,
    treasury: &AsyncMutex<Treasury>,
    signer: &Signer,
    grpc: &GrpcClient,
    network: zcash_protocol::consensus::Network,
    chain_tip: u32,
) -> Result<(), SweepError> {
    let last_height = {
        let st = registry.lock().await;
        st.get_sweep_cursor()?.height
    };
    if !sweep_due(chain_tip, last_height) {
        return Ok(());
    }

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
        orchard_circuit_version(branch_id),
    )?;

    match grpc.broadcast(result.tx_bytes).await {
        Ok(()) => {
            {
                let st = registry.lock().await;
                st.set_sweep_cursor(&SweepCursor {
                    height: chain_tip,
                    txid: Some(result.txid),
                })?;
            }
            tracing::info!(
                txid = %hex::encode(result.txid),
                amount_zat = result.amount_zat,
                hot_balance_zat = hot_balance,
                sweep_height = chain_tip,
                "broadcast cold sweep"
            );
        }
        Err(e) => {
            tracing::warn!(
                txid = %hex::encode(result.txid),
                error = %e,
                "sweep broadcast rejected; will retry when due"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_due_never_swept() {
        assert!(sweep_due(2_000_000, 0));
    }

    #[test]
    fn sweep_due_before_interval() {
        assert!(!sweep_due(2_000_500, 2_000_500));
        assert!(!sweep_due(
            2_000_500 + SWEEP_INTERVAL_BLOCKS - 1,
            2_000_500
        ));
    }

    #[test]
    fn sweep_due_after_interval() {
        assert!(sweep_due(
            2_000_500 + SWEEP_INTERVAL_BLOCKS,
            2_000_500
        ));
    }
}