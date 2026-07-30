//! ZNS Mint Boot Sequence
//!
//! The boot is a concrete, parameterless, deterministic sequence:
//!
//! 1. **Liveness** — JSON-RPC `getblockchaininfo` proves Zebra is reachable.
//! 2. **Chain integrity** — gRPC `chain_tip_change` + `get_block` cross-validates
//!    the tip against JSON-RPC, verifies the mainnet genesis block hash,
//!    checks NU5 activation and tip freshness.
//! 3. **Seed intake** — SEV-SNP sealed-blob decryption (production) or dev zero
//!    seed (`dev-seed` feature). Fingerprint verification guards against wrong-seed
//!    injection.
//! 4. **Key derivation** — ZIP-32 Treasury (account 0) + Registry (account 1).
//! 5. **Wallet initialization** — UFVKs registered, commitment trees seeded from
//!    the birthday checkpoint's `z_gettreestate`.
//! 6. **NU6.3 enforcement** — production boot refuses to start before
//!    Ironwood activation. The `pre-nu63-activation` feature is the explicit
//!    development exception.
//! 7. **Attestation** — SEV-SNP attestation report (Linux) or skip (non-Linux).
//!
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use secrecy::{ExposeSecret, Secret};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};
use crate::zcash::NETWORK;
use zip32::fingerprint::SeedFingerprint;

#[cfg(not(feature = "dev-seed"))]
use std::str::FromStr;

#[cfg(target_os = "linux")]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use zeroize::Zeroize;

use crate::key::{self, RegistryKeys, TreasuryKeys};
use crate::mint::{ChainCursor, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::registry::Registry;
use crate::treasury::Treasury;
use crate::wallet::Wallet;
use crate::zcash::{self, ChainClient, CheckpointData};

// ---------------------------------------------------------------------------
// boot — the concrete entry point
// ---------------------------------------------------------------------------

/// Proof that the full boot sequence completed successfully.
///
/// Can only be constructed by [`Boot::run`]. Every field is private — the
/// run loop accepts `Boot` as evidence that all checks passed: Zebra is on
/// the right chain, the seed is decrypted, Ironwood is active, and the
/// commitment trees are seeded from the correct checkpoint.
///
/// There is no public constructor. The only path to a `Boot` value is
/// [`Boot::run`], which panics on any failure.
pub struct Boot {
    chain: ChainClient,
    wallet: Wallet,
    registry: Registry,
    treasury: Treasury,
    cursor: ChainCursor,
    treasury_keys: TreasuryKeys,
    registry_keys: RegistryKeys,
}

impl Boot {
    /// The only entry point. Runs the full boot sequence.
    ///
    /// Panics on any failure — boot failures are fatal. The mint refuses
    /// to enter the run loop in a degraded state.
    pub async fn run() -> Boot {
        tracing::info!("boot: starting");

        // 1. Liveness: JSON-RPC getblockchaininfo
        let info = check_liveness().await;

        // 2. Chain integrity: gRPC cross-validation + tip block verification
        let (chain_client, tip_height) = verify_chain_integrity(&info).await;

        // 3. NU6.3/Ironwood is a boot invariant for the production mint.
        require_nu6_3_active(tip_height);

        // 4. Seed intake + fingerprint verification
        let source = obtain_key_source();
        let seed = match &source {
            KeySource::SealedBlob { blob } => decrypt_sealed_blob(blob),
            #[cfg(feature = "dev-seed")]
            KeySource::Dev => Secret::new([0u8; 32]),
        };
        verify_fingerprint(&seed, expected_seed_fingerprint());

        // 5. Key derivation
        let treasury_keys = key::derive_treasury(&seed);
        let registry_keys = key::derive_registry(&seed);
        tracing::info!("boot: keys derived (treasury=acct0, registry=acct1)");

        // 6. Wallet initialization
        let ufvks = [
            (TREASURY_ACCOUNT, treasury_keys.fvk()),
            (REGISTRY_ACCOUNT, registry_keys.fvk()),
        ];
        let mut wallet = Wallet::new(ufvks);

        // 7. ZNS Origin Checkpoint: fetch tree state from Zebra and seed ShardTrees
        let origin_height = u32::from(ironwood_activation_height());

        #[cfg(not(feature = "pre-nu63-activation"))]
        {
            assert!(
                u32::from(tip_height) >= origin_height - 1,
                "FATAL: Zebra tip {} is before Ironwood activation {}",
                u32::from(tip_height),
                origin_height
            );
        }

        #[cfg(feature = "pre-nu63-activation")]
        {
            if u32::from(tip_height) < origin_height - 1 {
                tracing::warn!(
                    "dev: tip {} below Ironwood activation {}, continuing (pre-nu63-activation)",
                    u32::from(tip_height),
                    origin_height
                );
            }
        }

        let rpc = zcash::JsonRpc::new();
        let checkpoint = origin_checkpoint(&rpc).await;
        let checkpoint_height = checkpoint.metadata.block_height();
        wallet.seed_trees(&checkpoint, checkpoint_height);
        tracing::info!(
            "boot: commitment trees seeded from origin checkpoint at height {}",
            u32::from(checkpoint_height)
        );

        // 8. Attestation
        let report_data = generate_attestation_report_data(&treasury_keys, &registry_keys);
        let attestation_bytes = generate_mint_attestation(report_data);
        if !attestation_bytes.is_empty() {
            std::fs::write("zns_mint_attestation.bin", &attestation_bytes)
                .expect("FATAL: failed to write attestation to disk");
            tracing::info!("boot: attestation report written to zns_mint_attestation.bin");
        }

        tracing::info!("boot: complete at node tip {}", u32::from(tip_height));

        Boot {
            chain: chain_client,
            wallet,
            registry: Registry::new(),
            treasury: Treasury::default(),
            cursor: ChainCursor::from_metadata(checkpoint.metadata),
            treasury_keys,
            registry_keys,
        }
    }

    /// The chain height at the boot checkpoint.
    pub fn height(&self) -> BlockHeight {
        self.cursor.height()
    }

    /// The chain cursor — fully-applied chain prefix.
    pub fn cursor(&self) -> &ChainCursor {
        &self.cursor
    }

    /// Consumes the boot evidence and returns the mutable run-loop components.
    ///
    /// The orchestrator is the only caller; this keeps the fields private
    /// while allowing the run loop to take ownership of the initialized
    /// subsystems.
    pub fn into_parts(
        self,
    ) -> (
        ChainClient,
        Wallet,
        Registry,
        Treasury,
        TreasuryKeys,
        RegistryKeys,
    ) {
        (
            self.chain,
            self.wallet,
            self.registry,
            self.treasury,
            self.treasury_keys,
            self.registry_keys,
        )
    }
}

// ---------------------------------------------------------------------------
// Step 1: Liveness
// ---------------------------------------------------------------------------

/// JSON-RPC `getblockchaininfo` — proves Zebra is reachable and responsive.
async fn check_liveness() -> zcash::BlockchainInfo {
    let rpc = zcash::JsonRpc::new();
    let info = rpc
        .get_blockchain_info()
        .await
        .expect("FATAL: JSON-RPC getblockchaininfo failed, Zebra is unreachable");

    tracing::info!(
        height = info.blocks,
        hash = %info.bestblockhash,
        "boot: zebra json-rpc liveness ok"
    );
    info
}

// ---------------------------------------------------------------------------
// Step 2: Chain integrity
// ---------------------------------------------------------------------------

/// gRPC tip stream + block fetch, cross-validated against JSON-RPC.
///
/// Verifies:
/// - gRPC and JSON-RPC agree on tip height and hash (split-brain detection).
/// - The genesis block hash matches the mainnet constant (network identity).
/// - Tip is at or after NU5 activation (consensus baseline).
/// - Tip block's timestamp is within 2 hours of wall clock (stuck-node detection).
async fn verify_chain_integrity(info: &zcash::BlockchainInfo) -> (ChainClient, BlockHeight) {
    let mut chain = ChainClient::connect()
        .await
        .expect("FATAL: Zebra gRPC unreachable or timed out");

    // Open the tip stream and read the first message
    use zebra_indexer_proto::Empty;
    let resp = chain
        .client()
        .chain_tip_change(Empty {})
        .await
        .expect("FATAL: chain_tip_change gRPC call failed");
    let mut stream = resp.into_inner();
    let tip_msg = stream
        .message()
        .await
        .expect("FATAL: no chain tip message from gRPC stream")
        .expect("FATAL: gRPC tip stream closed with no tip");

    let (tip_height, tip_hash) = zcash::tip_height_hash(&tip_msg);

    // Split-brain: gRPC vs JSON-RPC must agree
    assert_eq!(
        info.blocks,
        u32::from(tip_height),
        "FATAL: split-brain — JSON-RPC height {} != gRPC height {}",
        info.blocks,
        u32::from(tip_height)
    );
    assert_eq!(
        info.bestblockhash,
        tip_hash.to_string(),
        "FATAL: split-brain — JSON-RPC tip hash != gRPC tip hash"
    );

    let rpc = zcash::JsonRpc::new();

    // Network identity check: mainnet genesis hash in production builds only.
    #[cfg(not(feature = "pre-nu63-activation"))]
    {
        let genesis = rpc
            .get_block(BlockHeight::from_u32(0))
            .await
            .expect("FATAL: failed to fetch genesis block via JSON-RPC");
        assert_eq!(
            genesis.header().hash(),
            zcash::MAINNET_GENESIS_HASH,
            "FATAL: genesis block hash mismatch — Zebra is not on mainnet"
        );
    }

    // Fetch the tip block via JSON-RPC since Zebra gRPC doesn't implement get_block.
    let block = rpc
        .get_block(tip_height)
        .await
        .expect("FATAL: failed to fetch tip block via JSON-RPC");

    // Consensus baseline: NU5 must be active. Skipped in dev/regtest builds.
    #[cfg(not(feature = "pre-nu63-activation"))]
    {
        const NU5_MAINNET_ACTIVATION_HEIGHT: u32 = 1_687_104;
        assert!(
            u32::from(tip_height) >= NU5_MAINNET_ACTIVATION_HEIGHT,
            "FATAL: node is on a pre-NU5 branch (tip {}, NU5 at {})",
            u32::from(tip_height),
            NU5_MAINNET_ACTIVATION_HEIGHT
        );
    }

    // Freshness: tip must be within 2 hours of wall clock. Skipped in dev/regtest.
    #[cfg(not(feature = "pre-nu63-activation"))]
    {
        let tip_time = block.header().time;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("FATAL: system time before UNIX epoch")
            .as_secs() as u32;

        assert!(
            now.saturating_sub(tip_time) <= 7200,
            "FATAL: liveness failure — tip block is too old (tip_time={}, now={}). Node may be stuck.",
            tip_time,
            now
        );
    }

    tracing::info!(
        height = u32::from(tip_height),
        tx_count = block.vtx().len(),
        "boot: tip block verified, chain integrity ok"
    );

    (chain, tip_height)
}

#[cfg(not(feature = "pre-nu63-activation"))]
fn require_nu6_3_active(tip_height: BlockHeight) {
    assert!(
        NETWORK.is_nu_active(NetworkUpgrade::Nu6_3, tip_height),
        "FATAL: NU6.3/Ironwood is not active at Zebra tip {}",
        u32::from(tip_height),
    );
    tracing::info!("boot: NU6.3/Ironwood active");
}

#[cfg(feature = "pre-nu63-activation")]
fn require_nu6_3_active(tip_height: BlockHeight) {
    if NETWORK.is_nu_active(NetworkUpgrade::Nu6_3, tip_height) {
        tracing::info!("boot: NU6.3/Ironwood active");
    } else {
        tracing::warn!(
            height = u32::from(tip_height),
            "boot: pre-nu63-activation feature enabled; starting before Ironwood activation"
        );
    }
}

// ---------------------------------------------------------------------------
// Step 7: ZNS Origin Checkpoint
// ---------------------------------------------------------------------------

/// The Ironwood (NU6.3) activation height on mainnet, sourced from
/// `zcash_protocol` so it tracks upstream automatically.
pub fn ironwood_activation_height() -> BlockHeight {
    NETWORK
        .activation_height(NetworkUpgrade::Nu6_3)
        .expect("NU6.3 activation height must be set in zcash_protocol")
}

/// Fetches the origin checkpoint from Zebra via `z_gettreestate`.
///
/// The mint orchestrator begins scanning blocks from `ironwood_activation_height()`.
/// The checkpoint provides the commitment tree state for the block immediately
/// preceding it, establishing the tree root for the wallet.
///
/// Sapling and Orchard trees are fetched from Zebra (they contain years of
/// commitments at this height). The Ironwood tree is empty — it does not
/// exist until Ironwood activates.
///
/// Zebra is the trust root (same TEE). `verify_chain_integrity` already
/// cross-validates gRPC vs JSON-RPC, verifies the mainnet genesis block hash,
/// and checks tip freshness. No hardcoded origin-hash pinning is needed — the
/// checkpoint hash from `z_gettreestate` is stored in metadata for reference.
async fn origin_checkpoint(rpc: &zcash::JsonRpc) -> CheckpointData {
    let checkpoint_height = ironwood_activation_height().saturating_sub(1);

    let checkpoint = rpc
        .get_checkpoint(checkpoint_height)
        .await
        .expect("FATAL: failed to fetch origin checkpoint from Zebra");

    tracing::info!(
        "boot: origin checkpoint at height {}, hash {}",
        u32::from(checkpoint_height),
        checkpoint.metadata.block_hash()
    );

    checkpoint
}

// ---------------------------------------------------------------------------
// Seed fingerprint verification
// ---------------------------------------------------------------------------

/// The expected ZIP-32 seed fingerprint, compiled into the binary.
///
/// This is read at compile time from `deployment/seed_fingerprint.txt`. That
/// file is a deployment artifact, not a runtime config: it must be replaced
/// with the real seed fingerprint before a production artifact is built. The
/// placeholder value causes boot to fail closed if it is not replaced.
static EXPECTED_SEED_FINGERPRINT_RAW: &str =
    include_str!("../deployment/seed_fingerprint.txt");

fn expected_seed_fingerprint() -> &'static str {
    EXPECTED_SEED_FINGERPRINT_RAW.trim()
}

fn verify_fingerprint(seed: &Secret<[u8; 32]>, expected: &str) {
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");

    #[cfg(feature = "dev-seed")]
    {
        let _ = expected; // Suppress unused warning in dev mode only.
        tracing::warn!("boot: dev-seed fingerprint = {} (verification skipped)", actual);
    }

    #[cfg(not(feature = "dev-seed"))]
    {
        if expected.eq("PLACEHOLDER") {
            panic!(
                "FATAL: production build contains the placeholder seed fingerprint. \
                 Replace deployment/seed_fingerprint.txt with the real fingerprint before building."
            );
        }

        let expected_fp = SeedFingerprint::from_str(expected)
            .expect("FATAL: compiled binary contains an invalid seed fingerprint");

        if actual != expected_fp {
            // Redacted panic: do not print either fingerprint.
            panic!(
                "FATAL: SEED FINGERPRINT MISMATCH — decrypted seed does not match the fingerprint compiled into this binary"
            );
        }
        tracing::info!("boot: seed fingerprint verified");
    }
}

// ---------------------------------------------------------------------------
// Attestation report data
// ---------------------------------------------------------------------------

/// Constructs the 64-byte attestation report data: BLAKE2b-512 of
/// `treasury_default_address || "||" || registry_fvk`.
///
/// An external verifier checks this against the expected Treasury address
/// and Registry UFVK, binding the attestation to the mint's identity.
fn generate_attestation_report_data(
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
) -> [u8; 64] {
    use zcash_keys::keys::UnifiedAddressRequest;

    let (treasury_addr, _) = treasury_keys
        .fvk()
        .default_address(UnifiedAddressRequest::SHIELDED)
        .expect("FATAL: Treasury FVK missing default address");
    let treasury_addr_str = treasury_addr.encode(&NETWORK);
    let registry_fvk_str = registry_keys.fvk().encode(&NETWORK);

    let mut hasher = blake2b_simd::Params::new().hash_length(64).to_state();
    hasher.update(treasury_addr_str.as_bytes());
    hasher.update(b"||");
    hasher.update(registry_fvk_str.as_bytes());
    let hash = hasher.finalize();

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(hash.as_bytes());
    report_data
}

// ---------------------------------------------------------------------------
// Seed intake (sealed blob)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, serde::Serialize)]
struct SeedCapsule {
    magic: [u8; 8],
    fingerprint: [u8; 32],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

enum KeySource {
    SealedBlob {
        blob: Vec<u8>,
    },
    #[cfg(feature = "dev-seed")]
    Dev,
}

fn obtain_key_source() -> KeySource {
    #[cfg(feature = "dev-seed")]
    return KeySource::Dev;

    #[cfg(not(feature = "dev-seed"))]
    {
        tracing::info!("boot: reading seed capsule from zns_seed.capsule");
        let blob = std::fs::read("zns_seed.capsule").expect(
            "FATAL: failed to read zns_seed.capsule. The mint cannot boot without the sealed seed.",
        );
        KeySource::SealedBlob { blob }
    }
}

fn decrypt_sealed_blob(blob: &[u8]) -> Secret<[u8; 32]> {
    tracing::info!("boot: deriving instance-bound SEV-SNP sealing key");
    let mut raw_key = derive_sealing_key();
    let seed = decrypt_capsule(blob, &raw_key);
    raw_key.zeroize();
    seed
}

fn decrypt_capsule(blob: &[u8], raw_key: &[u8; 32]) -> Secret<[u8; 32]> {
    tracing::info!("boot: deserializing capsule");
    let capsule: SeedCapsule =
        postcard::from_bytes(blob).expect("FATAL: failed to parse zns_seed.capsule");

    assert_eq!(&capsule.magic, b"ZNS_SEED", "FATAL: capsule magic mismatch");

    let cipher =
        XChaCha20Poly1305::new_from_slice(raw_key).expect("sealing key is exactly 32 bytes");

    let mut aad = Vec::with_capacity(8 + 32);
    aad.extend_from_slice(&capsule.magic);
    aad.extend_from_slice(&capsule.fingerprint);

    let nonce = <&XNonce>::from(capsule.nonce.as_slice());

    tracing::info!("boot: decrypting seed");
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &capsule.ciphertext,
                aad: &aad,
            },
        )
        .expect("FATAL: failed to decrypt seed. Capsule tampering or wrong SEV-SNP instance.");

    if plaintext.len() != 32 {
        plaintext.zeroize();
        panic!("FATAL: decrypted seed is not exactly 32 bytes");
    }

    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Secret::new(seed_bytes)
}

#[cfg(target_os = "linux")]
fn derive_sealing_key() -> [u8; 32] {
    let mut firmware = Firmware::open().expect("FATAL: failed to open /dev/sev-guest");

    let mut guest_fields = GuestFieldSelect::default();
    guest_fields.set_guest_policy(true);
    guest_fields.set_image_id(true);
    guest_fields.set_family_id(true);
    guest_fields.set_measurement(true);

    let request = DerivedKey::new(true, guest_fields, 0, 0, 0, None);
    firmware
        .get_derived_key(Some(1), request)
        .expect("FATAL: failed to derive SEV-SNP VMRK sealing key")
}

#[cfg(not(target_os = "linux"))]
fn derive_sealing_key() -> [u8; 32] {
    panic!("FATAL: SEV-SNP key derivation is only supported on Linux. The mint cannot securely boot here.");
}

// ---------------------------------------------------------------------------
// SEV-SNP attestation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn generate_mint_attestation(report_data: [u8; 64]) -> Vec<u8> {
    use sev::firmware::guest::Firmware;

    tracing::info!("boot: generating mint attestation report");

    let mut firmware = Firmware::open().expect("FATAL: failed to open /dev/sev-guest");

    firmware
        .get_report(None, Some(report_data), None)
        .expect("FATAL: failed to request SEV-SNP attestation report")
}

#[cfg(not(target_os = "linux"))]
fn generate_mint_attestation(_report_data: [u8; 64]) -> Vec<u8> {
    tracing::warn!("boot: skipped attestation generation (not on linux)");
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests — one critical invariant: fingerprint mismatch fails closed without leaking it
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    #[test]
    #[cfg(not(feature = "dev-seed"))]
    #[should_panic(expected = "FATAL: SEED FINGERPRINT MISMATCH")]
    fn verify_fingerprint_mismatch_is_redacted() {
        let seed = Secret::new([0xAB; 32]);
        let wrong_fp = SeedFingerprint::from_seed(&[0xCD; 32]).unwrap().to_string();
        verify_fingerprint(&seed, &wrong_fp);
    }
}
