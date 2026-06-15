use std::sync::Arc;

use tokio::sync::RwLock;
use zns_registry::{Mint, TickSnapshot};

pub type SharedStatus = Arc<RwLock<TickSnapshot>>;

pub fn new_shared_status() -> SharedStatus {
    Arc::new(RwLock::new(TickSnapshot::default()))
}

pub async fn record_tick_status(status: &SharedStatus, mint: &Mint, chain_tip: u32) {
    *status.write().await = mint.snapshot(chain_tip).await;
}