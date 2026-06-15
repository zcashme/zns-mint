use pasta_curves::group::ff::PrimeField;
use zns_chain::IncomingNote;
use zns_core::Action;
use zns_signer::derive_psi_rcm;
use zns_state::{MintedAction, StateError};

use crate::registry::Registry;
use crate::spend::SpendLane;

/// Persist a registry-authored Name Note seen on chain and finish the spend lane.
pub async fn apply_name_note(
    registry: &Registry,
    spend: &SpendLane,
    note: &IncomingNote,
    height: u32,
    hash: [u8; 32],
    action: Action,
    name: String,
    ua: String,
    prev_rcm: [u8; 32],
) -> Result<(), StateError> {
    let (psi, rcm) = derive_psi_rcm(action, &name, &ua, &prev_rcm);
    let minted = MintedAction {
        name: name.clone(),
        action,
        ua,
        txid: note.txid,
        cmx: [0u8; 32],
        rcm: rcm.to_repr(),
        psi: psi.to_repr(),
        prev_rcm,
        height,
    };

    {
        let st = registry.lock().await;
        st.apply_mint(&minted)?;
        st.mark_processed(
            &note.txid,
            pool_byte(&note.pool),
            note.output_index,
            height,
            &hash,
        )?;
    }

    let flight = {
        let st = registry.lock().await;
        st.get_in_flight()?
    };
    if let Some(flight) = flight {
        if !flight.relay && flight.name == name {
            let request_pool = spend
                .active_job()
                .map(|j| j.pool)
                .unwrap_or_else(|| pool_byte(&note.pool));
            let st = registry.lock().await;
            st.mark_processed(
                &flight.request_txid,
                request_pool,
                flight.request_index,
                height,
                &hash,
            )?;
            st.clear_in_flight()?;
            spend.clear_active();
            tracing::info!(name = %name, height, "mint confirmed on chain");
        }
    }

    Ok(())
}

fn pool_byte(pool: &zcash_protocol::ShieldedProtocol) -> u8 {
    match pool {
        zcash_protocol::ShieldedProtocol::Orchard => 0,
        zcash_protocol::ShieldedProtocol::Sapling => 1,
    }
}