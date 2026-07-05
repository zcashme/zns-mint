//! ZNS Mint Boot Sequence

use std::str::FromStr;
use secrecy::{ExposeSecret, Secret};
use zcash_protocol::consensus::BlockHeight;
use zip32::{fingerprint::SeedFingerprint, AccountId};

use crate::key::{self, AccountKeys};
use crate::zcash;

/// The expected seed fingerprint, hardcoded at deployment time.
///
/// At boot, the TEE-injected seed is verified against this value. If they
/// don't match, the wrong seed was injected — the mint refuses to boot before
/// touching the chain.
///
/// **Dummy value** — this is the fingerprint of the all-zeros seed
/// (`[0u8; 32]`), used during development. Replace with the actual deployment
/// seed's fingerprint before production. To compute:
/// `SeedFingerprint::from_seed(&seed).unwrap().to_string()` and paste the
/// `zip32seedfp1...` string here.
const EXPECTED_SEED_FINGERPRINT: &str = "zip32seedfp1rc52vh66vxh4klcd22fgmxlzfxcutdfr34gahe5mksv2g82mcejsqqwlyu";

pub async fn boot() -> (
    zcash::chain::Reader,
    crate::wallet::Wallet,
    AccountKeys,
    AccountKeys,
    BlockHeight,
) {
    tracing::info!("boot: starting");

    // 1. Network Path: Prove node is reachable
    let info = check_liveness().await;

    // 2. Data Flow Path: Connect to data stream and strictly verify integrity
    let (chain, tip_height) = verify_chain_integrity(&info).await;

    // 3. Cryptography Path: Trust established, touch the seed
    let source = obtain_key_source();
    let blob = match &source {
        KeySource::SealedBlob { blob } => blob.as_slice(),
    };
    let seed = decrypt_sealed_blob(blob);
    verify_fingerprint(&seed);

    // 4. Key Derivation: derive per-module keys from the seed
    let treasury_keys = key::derive_account(&seed, AccountId::const_from_u32(0));
    let registry_keys = key::derive_account(&seed, AccountId::const_from_u32(1));
    tracing::info!("boot: keys derived");
    // `seed` drops here — Secret zeroizes the bytes.

    // 5. RAM Path: Initialize the in-memory wallet (rebuilt from birthday on every boot)
    let wallet = initialize_wallet(&treasury_keys.fvk(), &registry_keys.fvk());

    // Return the verified environment to the orchestrator
    (chain, wallet, treasury_keys, registry_keys, tip_height)
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

/// Verifies the TEE-injected seed against the hardcoded expected fingerprint.
///
/// If the fingerprints don't match, the wrong seed was injected. This is a
/// critical safety check: a different seed means different spending keys,
/// different viewing keys, and a different namespace. The mint refuses to boot.
fn verify_fingerprint(seed: &Secret<[u8; 32]>) {
    let expected = SeedFingerprint::from_str(EXPECTED_SEED_FINGERPRINT)
        .expect("hardcoded seed fingerprint is valid bech32m");
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");
    assert_eq!(
        actual, expected,
        "SEED FINGERPRINT MISMATCH: wrong seed injected into TEE. \
         expected={}, actual={}",
        expected, actual
    );
    tracing::info!("boot: seed fingerprint verified = {}", actual);
}

/// Seeds the in-memory wallet using the derived viewing keys.
fn initialize_wallet(
    treasury_fvk: &zcash_keys::keys::UnifiedFullViewingKey,
    registry_fvk: &zcash_keys::keys::UnifiedFullViewingKey,
) -> crate::wallet::Wallet {
    let ufvks = [
        (crate::mint::TREASURY_ACCOUNT, treasury_fvk.clone()),
        (crate::mint::REGISTRY_ACCOUNT, registry_fvk.clone()),
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
    /// returned as `Secret<[u8; 32]>`.
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
/// wrapped in `Secret<[u8; 32]>`, which zeroizes on drop. Unimplemented; the
/// future TEE work lands here.
fn decrypt_sealed_blob(_blob: &[u8]) -> Secret<[u8; 32]> {
    todo!("TEE-sealed-blob decryption is not yet wired")
}