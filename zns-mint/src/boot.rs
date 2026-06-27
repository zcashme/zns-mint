use zebra_indexer_proto::{BlockHashAndHeight, BlockRequest, Empty, ZebraClient};
use zcash_primitives::block::{Block, BlockHash};
use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};

use crate::key::Keys;

/// Runs the boot phase: connect → prove the chain is alive → verify the tip
/// block → derive accounts.
///
/// Each step fails loudly (`.expect` / `assert!`) rather than soldiering on with
/// partial state, per the project's "liveness before trust" + "fail loud" rules.
/// Seed material is touched only by [`derive_accounts`], after every chain check
/// has passed.
pub async fn boot() -> Accounts {
    tracing::info!("boot: starting");

    let mut client = connect_zebra().await;
    let tip = liveness_check(&mut client).await;
    let _block = verify_tip_block(&mut client, &tip).await;
    derive_accounts()
}

/// Proves the Zebra indexer is alive and reports a best-chain tip.
///
/// Calls `ChainTipChange` and reads exactly one stream message (the current tip
/// per Zebra's first-message contract). The stream is then dropped — we do not
/// subscribe to ongoing tip changes here; that's a future sync-loop concern.
///
/// Returns the tip as a [`BlockHashAndHeight`] (hash in display order, height).
async fn liveness_check(client: &mut ZebraClient) -> BlockHashAndHeight {
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
    tip
}

/// Proves the node serves a real, structurally-valid, integrity-checked block at
/// the given tip.
///
/// This is NOT full consensus verification (no PoW/Equihash, no merkle-root
/// recomputation over txs, no signature/proof checks, no chain linkage) — those
/// remain Zebra's job. It is "is the node serving an untampered,
/// internally-consistent block at this tip."
///
/// Steps:
/// 1. `GetBlock(tip.height)` → encoded block bytes.
/// 2. `Block::read` against `MAIN_NETWORK` — parses the bytes and enforces
///    structural consensus invariants (coinbase present + no sprout data,
///    coinbase consensus-branch-id matches the network params for the claimed
///    height, no non-coinbase null transparent inputs).
/// 3. Header-hash integrity: the hash recomputed from the parsed header must
///    equal both the `GetBlock`-reported hash and the `ChainTipChange`-reported
///    hash. Catches tampering/corruption of the `data` field and RPC
///    disagreement about the tip.
/// 4. Height consistency: the parsed block's claimed height must equal
///    `tip.height`.
/// 5. Coinbase presence (belt-and-braces; `Block::read` already enforces this).
async fn verify_tip_block(client: &mut ZebraClient, tip: &BlockHashAndHeight) -> Block {
    let block_req = BlockRequest {
        hash_or_height: tip.height.to_be_bytes().to_vec(),
    };
    let block_resp = client
        .get_block(block_req)
        .await
        .expect("get_block request failed");
    let block_and_hash = block_resp.into_inner();
    tracing::info!(height = tip.height, "boot: get_block ok");

    let parsed = Block::read(&block_and_hash.data[..], &MAIN_NETWORK)
        .expect("get_block returned bytes that do not parse as a mainnet block");
    tracing::info!(height = tip.height, "boot: block parsed ok");

    // `Block::read` recomputes the header hash (SHA-256d of the encoded header),
    // so `parsed.header().hash()` is independent of any server-reported hash.
    // The proto reports hashes in display order; `BlockHash` stores internal
    // order, so we reverse the server-reported bytes before comparing.
    let tip_hash = block_hash_from_display(&tip.hash)
        .expect("chain_tip_change returned a malformed 32-byte hash");
    let getblock_hash = block_hash_from_display(&block_and_hash.hash)
        .expect("get_block returned a malformed 32-byte hash");
    assert_eq!(
        tip_hash, getblock_hash,
        "chain_tip_change hash != get_block hash"
    );
    assert_eq!(
        parsed.header().hash(),
        getblock_hash,
        "recomputed header hash != get_block hash"
    );
    tracing::info!("boot: block hash matches chain tip");

    // `claimed_height` is only trustworthy for a chain-validated block, which is
    // exactly the assumption when trusting the local Zebra node.
    assert_eq!(
        parsed.claimed_height(),
        BlockHeight::from_u32(tip.height),
        "parsed block height != chain tip height"
    );
    tracing::info!("boot: block height matches chain tip");

    assert!(
        !parsed.vtx().is_empty(),
        "parsed block has no transactions"
    );
    tracing::info!(
        tx_count = parsed.vtx().len(),
        "boot: block has transactions"
    );

    parsed
}

/// Derives the two ZIP-32 accounts from a single seed.
///
/// Treasury = account 0, Registry = account 1. This is the **only** place that
/// touches seed material, and it runs only after [`liveness_check`] and
/// [`verify_tip_block`] have passed — so seed material is never read on a broken
/// or unverified chain connection.
fn derive_accounts() -> Accounts {
    let seed = obtain_dev_seed();
    let keys = Keys::from_seed(seed);
    tracing::info!("boot: keys derived");

    let accounts = Accounts::from_keys(&keys);

    tracing::info!("boot: accounts ready");
    accounts
}

/// Temporary dev path. Will be replaced by TEE-injected blob decryption.
fn obtain_dev_seed() -> [u8; 32] {
    tracing::warn!("boot: USING DEV ZERO SEED for derivation — replace with real blob path");
    [0u8; 32]
}

/// Constructs a [`BlockHash`] from a 32-byte hash in display order.
///
/// Zebra's indexer proto reports block hashes in display order (the byte-reversed
/// form used by block explorers and RPCs). `BlockHash` stores the internal
/// (non-display) order. This helper reverses the bytes and returns a `BlockHash`,
/// or `None` if the input is not exactly 32 bytes.
fn block_hash_from_display(display: &[u8]) -> Option<BlockHash> {
    let mut bytes: [u8; 32] = BlockHash::try_from_slice(display)?.0;
    bytes.reverse();
    Some(BlockHash(bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Manual node-health check: connects to the same hard-coded endpoint as
    /// [`boot`] and exercises the liveness + tip-block verification path against
    /// a live Zebra indexer. Ignored by default — run with
    /// `cargo test --release -- --ignored --nocapture zebra_smoke`.
    #[tokio::test]
    #[ignore]
    async fn zebra_smoke_liveness_and_verify_tip_block() {
        let mut client = connect_zebra().await;
        let tip = liveness_check(&mut client).await;
        let block = verify_tip_block(&mut client, &tip).await;
        tracing::info!(
            height = %tip.height,
            tx_count = block.vtx().len(),
            "smoke: tip block verified"
        );
    }
}