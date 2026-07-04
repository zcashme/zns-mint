//! Zebra mempool event primitives.
//!
//! Mempool events are useful for tracking submitted transaction lifecycle, but
//! they are not canonical ZNS state. Confirmed chain blocks remain authoritative.

use tokio::sync::mpsc;
use zebra_indexer_proto::{mempool_change_message::ChangeType, MempoolChangeMessage};

/// A transaction lifecycle notice from Zebra's mempool stream.
pub struct Event {
    pub change: Change,
    pub tx_hash: Vec<u8>,
    pub auth_digest: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Added,
    Invalidated,
    Mined,
}

impl Event {
    pub fn from_proto(message: MempoolChangeMessage) -> Self {
        let change = match ChangeType::try_from(message.change_type)
            .expect("zebra returned an unknown mempool change type")
        {
            ChangeType::Added => Change::Added,
            ChangeType::Invalidated => Change::Invalidated,
            ChangeType::Mined => Change::Mined,
        };

        Self {
            change,
            tx_hash: message.tx_hash,
            auth_digest: message.auth_digest,
        }
    }
}

/// Spawns a background task that streams Zebra's mempool events 24/7.
///
/// Yields lifecycle events (Added, Invalidated, Mined) for unmined transactions.
pub fn spawn_observer() -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel(100);

    tokio::spawn(async move {
        // TODO: Wire this to a real gRPC endpoint when it is fully implemented
        // by the Zebra node. For now, this acts as a stub loop.
        let _ = tx;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    rx
}
