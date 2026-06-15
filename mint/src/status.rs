use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use zns_chain::scan_mempool;

use crate::config::{ANCHOR_CONFIRMATIONS, MINT_FEE_ZAT};
use crate::Mint;

/// Observations from the latest completed poll tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainStatus {
    pub tip_height: u32,
    pub scan_tip_height: u32,
    pub spendable_zat: u64,
    pub mempool_notes: u64,
    pub spend_queue_depth: u32,
    pub in_flight: bool,
    pub treasury_available: bool,
    pub last_poll_unix: u64,
}

pub(crate) type SharedChainStatus = Arc<RwLock<ChainStatus>>;

pub fn new_shared_status() -> SharedChainStatus {
    Arc::new(RwLock::new(ChainStatus::default()))
}

pub async fn record_tick_status(status: &SharedChainStatus, mint: &Mint, chain_tip: u32) {
    let scan_tip_height = {
        let st = mint.registry.lock().await;
        st.get_scan_tip()
            .ok()
            .flatten()
            .map(|t| t.height)
            .unwrap_or(0)
    };

    let in_flight = {
        let st = mint.registry.lock().await;
        st.get_in_flight().ok().flatten().is_some()
    };

    let spendable_zat = if let Some(treasury) = mint.spend.treasury.as_ref() {
        let mut t = treasury.lock().await;
        t.select_funding(MINT_FEE_ZAT, ANCHOR_CONFIRMATIONS)
            .ok()
            .map(|f| f.spendable_total_zat)
            .unwrap_or(0)
    } else {
        0
    };

    let mempool_notes = scan_mempool(&mint.chain.scanner, chain_tip)
        .await
        .map(|notes| notes.len() as u64)
        .unwrap_or(0);

    let last_poll_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    *status.write().await = ChainStatus {
        tip_height: chain_tip,
        scan_tip_height,
        spendable_zat,
        mempool_notes,
        spend_queue_depth: mint.spend.lane.pending_count() as u32,
        in_flight,
        treasury_available: mint.spend.treasury.is_some(),
        last_poll_unix,
    };
}