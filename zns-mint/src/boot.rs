use zebra_indexer_proto::{ZebraClient, Empty};

use crate::key::Keys;

/// Temporary dev path. Will be replaced by TEE-injected blob decryption.
fn obtain_dev_seed() -> [u8; 32] {
    tracing::warn!("boot: USING DEV ZERO SEED for derivation — replace with real blob path");
    [0u8; 32]
}

pub async fn boot() -> Accounts {
    tracing::info!("boot: starting");
    let mut client = connect_zebra().await;

    // Liveness before we ever touch seed material (design constraint)
    let resp = client
        .chain_tip_change(Empty {})
        .await
        .expect("chain_tip_change failed");
    let mut stream = resp.into_inner();
    let tip = stream
        .message()
        .await
        .expect("no chain tip message")
        .expect("stream closed with no tip");
    tracing::info!(height = tip.height, "boot: zebra liveness ok");

    // Derive the two ZIP-32 accounts from a single seed.
    // Treasury = account 0, Registry = account 1.
    let seed = obtain_dev_seed();
    let keys = Keys::from_seed(seed);
    tracing::info!("boot: keys derived");

    let accounts = Accounts::from_keys(&keys);
    drop(keys);

    tracing::info!("boot: accounts ready");
    accounts
}

async fn connect_zebra() -> ZebraClient {
    const ZEBRA_INDEXER_URL: &str = "http://light.zcash.me:8230";
    ZebraClient::connect(ZEBRA_INDEXER_URL)
        .await
        .expect("zebra indexer gRPC connect failed")
}

pub struct Accounts {
    treasury_fvk: zcash_keys::keys::UnifiedFullViewingKey,
    registry_fvk: zcash_keys::keys::UnifiedFullViewingKey,
}

impl Accounts {
    pub fn from_keys(keys: &Keys) -> Self {
        Self {
            treasury_fvk: keys.treasury_fvk(),
            registry_fvk: keys.registry_fvk(),
        }
    }

    pub fn treasury_fvk(&self) -> &zcash_keys::keys::UnifiedFullViewingKey {
        &self.treasury_fvk
    }

    pub fn registry_fvk(&self) -> &zcash_keys::keys::UnifiedFullViewingKey {
        &self.registry_fvk
    }
}
