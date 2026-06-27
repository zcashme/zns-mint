use zebra_indexer_proto::{ZebraClient, Empty};

use crate::key::Keys;

/// Temporary dev path. Will be replaced by TEE-injected blob decryption.
fn obtain_dev_seed() -> [u8; 32] {
    tracing::warn!("boot: USING DEV ZERO SEED for derivation — replace with real blob path");
    [0u8; 32]
}

pub async fn boot() -> Keys {
    tracing::info!("boot: starting");

    // Liveness before we ever touch seed material (design constraint)
    tracing::info!("boot: zebra indexer gRPC liveness");
    let mut client = connect_zebra().await;

    tracing::info!("zebra: performing liveness check (ChainTipChange)");
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
    tracing::info!(
        height = tip.height,
        "zebra: liveness check passed — chain tip received"
    );

    // Derive the two ZIP-32 accounts from a single seed.
    // Treasury = account 0, Registry = account 1.
    let seed = obtain_dev_seed();
    let keys = Keys::from_seed(seed);

    // Touch the public fvk accessors (cheap). This proves derivation worked
    // and will be replaced by real consumers of treasury_fvk / registry_fvk.
    let _ = keys.treasury_fvk();
    let _ = keys.registry_fvk();

    tracing::info!("boot: ZIP-32 derivation complete (treasury=0, registry=1)");
    tracing::info!("boot: done");

    keys
}

async fn connect_zebra() -> ZebraClient {
    const ZEBRA_INDEXER_URL: &str = "http://light.zcash.me:8230";
    ZebraClient::connect(ZEBRA_INDEXER_URL)
        .await
        .expect("zebra indexer gRPC connect failed")
}