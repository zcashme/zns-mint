//! ZNS Mint Boot Sequence

use zcash_protocol::consensus::BlockHeight;
use zeroize::Zeroizing;

use crate::key::Keys;
use crate::zcash;

pub async fn boot() -> (
    zcash::chain::Reader,
    Keys,
    crate::wallet::Wallet,
    BlockHeight,
) {
    tracing::info!("boot: starting");

    // 1. Network Path: Prove node is reachable
    let info = check_liveness().await;

    // 2. Data Flow Path: Connect to data stream and strictly verify integrity
    let (chain, tip_height) = verify_chain_integrity(&info).await;

    // 3. Cryptography Path: Trust established, touch the seed
    let keys = derive_keys(obtain_key_source());

    // 4. RAM Path: Initialize the in-memory wallet (rebuilt from birthday on every boot)
    let wallet = initialize_wallet(&keys);

    // Return the verified environment to the orchestrator
    (chain, keys, wallet, tip_height)
}

/// Pings the node via JSON-RPC to ensure the network path is alive.
async fn check_liveness() -> zcash::zebra::BlockchainInfo {
    let zebra_rpc = zcash::zebra::JsonRpc::new();
    let info = zebra_rpc
        .get_blockchain_info()
        .await
        .expect("json-rpc getblockchaininfo failed, node is unreachable");
    
    tracing::info!(
        height = info.blocks,
        hash = %info.bestblockhash,
        "boot: zebra json-rpc liveness ok"
    );
    info
}

/// Connects via gRPC, fetches the tip, cross-validates against RPC, and verifies the block.
async fn verify_chain_integrity(info: &zcash::zebra::BlockchainInfo) -> (zcash::chain::Reader, BlockHeight) {
    let mut chain = zcash::chain::Reader::connect().await;
    let (tip_height, tip_hash) = chain.tip().await;

    assert_eq!(
        info.blocks,
        u32::from(tip_height),
        "split-brain: json-rpc height != grpc height"
    );

    assert_eq!(
        info.bestblockhash,
        tip_hash.to_string(),
        "split-brain: json-rpc tip hash != grpc tip hash"
    );

    let block = chain.block(tip_height).await;
    tracing::info!(
        height = u32::from(tip_height),
        tx_count = block.transactions().count(),
        "boot: block verified ok"
    );

    (chain, tip_height)
}

/// Seeds the in-memory wallet using the derived viewing keys.
fn initialize_wallet(keys: &Keys) -> crate::wallet::Wallet {
    let ufvks = [
        (crate::mint::TREASURY_ACCOUNT, keys.treasury_fvk()),
        (crate::mint::REGISTRY_ACCOUNT, keys.registry_fvk()),
    ];
    crate::wallet::Wallet::new(ufvks)
}

/// The source of the mint's seed material.
///
/// This is the typed seam between "the operator gave the TEE something" and
/// "the mint is now holding a seed". It exists so that *which* trust
/// assumption the mint is operating under is a value the compiler checks,
/// not a log line a human has to read.
///
/// Per `AGENTS.md` "Seed and key material", Layer 1: the seed must arrive as
/// an encrypted blob bound to the TEE's measurement — never an env var, CLI
/// flag, or config file. The only variant here is `SealedBlob`. There is no
/// `Dev` variant: the crate is hardcoded mainnet (`MAIN_NETWORK` in `key.rs`,
/// `CHECKPOINT_NETWORK = "main"` in `zcash::zebra`), there is no testnet
/// mode, and a hardcoded zero seed on mainnet is not a trust assumption worth
/// naming — it is a bug. The binary refuses to boot until the sealed-blob
/// decrypt path is implemented.
enum KeySource {
    /// A TEE-sealed seed blob: operator-unreadable ciphertext that only the
    /// attested enclave can decrypt. The blob's bytes are not the seed; the
    /// seed is recovered inside the enclave by `decrypt_sealed_blob` and
    /// returned already wrapped in `Zeroizing`.
    SealedBlob { blob: Vec<u8> },
}

/// The one and only key source the mint will accept today.
///
/// Not implemented. The TEE-sealed-blob decrypt path is the load-bearing
/// security guarantee and is not yet wired — see `AGENTS.md` "Seed and key
/// material", Layer 1 ("Status: not yet wired"). Until it is, the mint
/// cannot boot, which is the honest state: a zero-seed mainnet run is worse
/// than no run.
fn obtain_key_source() -> KeySource {
    todo!("TEE-sealed-blob decryption is not yet wired; the mint cannot boot until it is")
}

/// Decrypts a sealed blob into a seed, inside the attested boundary.
///
/// This is where the TEE unseals the blob and returns the plaintext seed
/// wrapped in `Zeroizing`. Unimplemented; the future TEE work lands here.
fn decrypt_sealed_blob(_blob: &[u8]) -> Zeroizing<[u8; 32]> {
    todo!("TEE-sealed-blob decryption is not yet wired")
}

/// Derives the two ZIP-32 keys from a single seed.
///
/// Treasury = account 0, Registry = account 1. This is the **only** place that
/// touches seed material, and it runs only after liveness and tip verification
/// have passed — so seed material is never read on a broken or unverified chain.
///
/// The seed arrives already wrapped in `Zeroizing` from `decrypt_sealed_blob`.
/// An unwrapped `[u8; 32]` seed is unrepresentable at this call site — see
/// `AGENTS.md` "Seed and key material", Layer 2.
fn derive_keys(source: KeySource) -> Keys {
    let seed = match source {
        KeySource::SealedBlob { blob } => decrypt_sealed_blob(&blob),
    };
    let keys = Keys::from_seed(seed);
    tracing::info!("boot: keys derived");
    keys
}
