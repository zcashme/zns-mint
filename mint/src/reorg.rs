use zns_chain::{GrpcClient, GrpcError};
use zns_signer::{RequestId, Signer};
use zns_state::StateError;

use crate::registry::Registry;

/// Detect a chain reorg against the scan tip and rewind if needed.
pub async fn handle_reorg(
    registry: &Registry,
    grpc: &GrpcClient,
    signer: &Signer,
    chain_tip: u32,
) -> Result<Option<u32>, ReorgError> {
    let scan_tip = {
        let st = registry.lock().await;
        st.get_scan_tip()?
    };

    let Some(scan_tip) = scan_tip else {
        return Ok(None);
    };

    let reorg_height = if scan_tip.height > chain_tip {
        chain_tip.saturating_add(1)
    } else {
        let current_hash = grpc.block_hash(scan_tip.height).await?;
        if current_hash == scan_tip.hash {
            return Ok(None);
        }

        let mut h = scan_tip.height;
        loop {
            let stored = {
                let st = registry.lock().await;
                st.processed_hash_at_height(h)?
            };
            let Some(stored) = stored else {
                break 0;
            };
            let current = grpc.block_hash(h).await?;
            if stored == current {
                break h.saturating_add(1);
            }
            if h == 0 {
                break 0;
            }
            h -= 1;
        }
    };

    let affected = {
        let st = registry.lock().await;
        st.apply_reorg(reorg_height, |(txid, idx)| {
            signer.release_request(RequestId {
                txid,
                action_index: idx,
            });
        })?
    };

    tracing::warn!(
        reorg_height,
        affected_names = affected,
        "chain reorg: registry rewound"
    );
    Ok(Some(reorg_height))
}

#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Grpc(#[from] GrpcError),
}