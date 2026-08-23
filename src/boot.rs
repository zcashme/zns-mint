//! ZNS Mint Boot Sequence
//!
//! Production boot is a concrete, parameterless, deterministic sequence. Its
//! development-only regtest counterpart supplies its own fixed parameters; the
//! shared boot core carries the selected concrete parameters into the loop.
//!
//! 1. **Liveness** — JSON-RPC `getblockchaininfo` proves Zebra is reachable.
//! 2. **Chain integrity** — gRPC `chain_tip_change` + `get_block` cross-validates
//!    the tip against JSON-RPC, verifies the selected network's genesis hash,
//!    checks NU5 activation.
//! 3. **Seed intake** — SEV-SNP sealed-blob decryption (production) or dev zero
//!    seed (`dev-seed` feature). Fingerprint verification guards against wrong-seed
//!    injection.
//! 4. **Key derivation** — ZIP-32 Treasury (account 0) + Registry (account 1).
//! 5. **Wallet initialization** — UFVKs registered, commitment trees seeded from
//!    the birthday checkpoint's `z_gettreestate`.
//! 6. **Attestation** — SEV-SNP attestation report (Linux) or skip (non-Linux).
//!
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use secrecy::{ExposeSecret, Secret};
use zcash_protocol::consensus::{BlockHeight, MainNetwork, NetworkUpgrade, Parameters};
#[cfg(feature = "dev-regtest")]
use zcash_protocol::local_consensus::LocalNetwork;
use zip32::fingerprint::SeedFingerprint;

#[cfg(not(feature = "dev-seed"))]
use std::str::FromStr;

#[cfg(target_os = "linux")]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use zeroize::Zeroize;

use crate::key::{RegistryKeys, TreasuryKeys};
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
/// Can only be constructed by [`Boot::run`] or the development-only
/// [`Boot::run_regtest`]. Every field is private — the
/// run loop accepts `Boot` as evidence that all checks passed: Zebra is on
/// the right chain, the seed is decrypted, Ironwood is active, and the
/// commitment trees are seeded from the correct checkpoint.
///
/// Production has no public constructor other than [`Boot::run`], which
/// panics on any failure.
pub struct Boot<P: Parameters> {
    network: P,
    chain: ChainClient,
    wallet: Wallet,
    registry: Registry,
    treasury: Treasury,
    cursor: ChainCursor,
    treasury_keys: TreasuryKeys,
    registry_keys: RegistryKeys,
}

/// Expected genesis hash — mainnet in production, regtest in dev builds.
#[cfg(not(feature = "dev-regtest"))]
const EXPECTED_GENESIS: zcash_primitives::block::BlockHash = zcash::MAINNET_GENESIS_HASH;

#[cfg(feature = "dev-regtest")]
const EXPECTED_GENESIS: zcash_primitives::block::BlockHash = zcash_primitives::block::BlockHash([
    // Zebra's immutable regtest genesis (`zebra-chain` 11.3.0,
    // `parameters/network/testnet.rs:47-49`), stored in BlockHash's
    // internal byte order.
    0x27, 0xe3, 0x01, 0x34, 0xd6, 0x20, 0xe9, 0xfe, 0x61, 0xf7, 0x19, 0x93, 0x83, 0x20, 0xba, 0xb6,
    0x3e, 0x7e, 0x72, 0xc9, 0x1b, 0x5e, 0x23, 0x02, 0x56, 0x76, 0xf9, 0x0e, 0xd8, 0x11, 0x9f, 0x02,
]);

/// Network label for logging.
#[cfg(not(feature = "dev-regtest"))]
const NETWORK_LABEL: &str = "mainnet";

#[cfg(feature = "dev-regtest")]
const NETWORK_LABEL: &str = "regtest";

impl Boot<MainNetwork> {
    /// Production entry point. This is deliberately parameterless and only
    /// permits the mainnet parameters compiled by librustzcash.
    pub async fn run() -> Self {
        Self::run_with_network(zcash_protocol::consensus::MAIN_NETWORK).await
    }
}

#[cfg(feature = "dev-regtest")]
impl Boot<LocalNetwork> {
    /// Development-harness entry point. It is unavailable unless the
    /// development-only `dev-regtest` feature is compiled in.
    pub async fn run_regtest() -> Self {
        Self::run_with_network(regtest_network()).await
    }
}

impl<P: Parameters> Boot<P> {
    /// Boot sequence for a concrete, boot-owned network parameter set.
    ///
    async fn run_with_network(network: P) -> Self {
        tracing::info!("boot: starting");

        // 1. Liveness: JSON-RPC getblockchaininfo
        let info = check_liveness().await;

        // 2. Chain integrity: gRPC cross-validation + tip block verification
        let (chain_client, tip_height) = verify_chain_integrity::<P>(&info, &network).await;

        // 3. Seed intake + fingerprint verification, then derivation.
        //
        // The seed lives only inside this block: the moment both capabilities
        // exist, `Secret`'s `Drop` wipes it. No copy of the seed outlives
        // derivation.
        let (treasury_keys, registry_keys) = {
            let source = obtain_key_source();
            let seed = match &source {
                KeySource::SealedBlob { blob } => decrypt_sealed_blob(blob),
                #[cfg(feature = "dev-seed")]
                KeySource::Dev => Secret::new([0u8; 32]),
            };
            verify_fingerprint(&seed, expected_seed_fingerprint());
            (
                TreasuryKeys::derive(&network, &seed),
                RegistryKeys::derive(&network, &seed),
            )
        };
        tracing::info!("boot: keys derived (treasury=acct0, registry=acct1); seed wiped");

        // 5. Wallet initialization
        let mut wallet = Wallet::new([
            (TREASURY_ACCOUNT, treasury_keys.fvk()),
            (REGISTRY_ACCOUNT, registry_keys.fvk()),
        ]);

        // 6. ZNS Origin Checkpoint: fetch tree state from Zebra and seed ShardTrees
        let rpc = zcash::JsonRpc::new();
        let checkpoint = origin_checkpoint(&rpc, &network).await;
        let checkpoint_height = checkpoint.metadata.block_height();
        wallet
            .seed_trees(
                checkpoint.sapling_tree.to_frontier(),
                checkpoint.orchard_tree.to_frontier(),
                checkpoint
                    .ironwood_tree
                    .as_ref()
                    .map(|tree| tree.to_frontier())
                    .unwrap_or_else(incrementalmerkletree::frontier::Frontier::empty),
                checkpoint_height,
            )
            .expect("FATAL: failed to seed commitment trees from the verified Zebra checkpoint");
        tracing::info!(
            "boot: commitment trees seeded from origin checkpoint at height {}",
            u32::from(checkpoint_height)
        );

        // 7. Attestation (production only)
        #[cfg(not(feature = "dev-regtest"))]
        {
            let report_data =
                generate_attestation_report_data(&network, &treasury_keys, &registry_keys);
            let attestation_bytes = generate_mint_attestation(report_data);
            if !attestation_bytes.is_empty() {
                std::fs::write("zns_mint_attestation.bin", &attestation_bytes)
                    .expect("FATAL: failed to write attestation to disk");
                tracing::info!("boot: attestation report written to zns_mint_attestation.bin");
            }
        }

        tracing::info!(
            network = NETWORK_LABEL,
            "boot: complete at node tip {}",
            u32::from(tip_height)
        );

        Boot {
            network,
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
        P,
        ChainClient,
        Wallet,
        Registry,
        Treasury,
        TreasuryKeys,
        RegistryKeys,
    ) {
        (
            self.network,
            self.chain,
            self.wallet,
            self.registry,
            self.treasury,
            self.treasury_keys,
            self.registry_keys,
        )
    }
}

#[cfg(feature = "dev-regtest")]
fn regtest_network() -> LocalNetwork {
    // Matches `regtest-harness/src/lib.rs:zebrad_toml`. Zebra defaults every
    // unconfigured pre-NU5 activation to 1 on regtest; the harness explicitly
    // configures NU5/NU6 at 1 and NU6.1/2/3 at 4.
    let one = BlockHeight::from_u32(1);
    let four = BlockHeight::from_u32(4);
    LocalNetwork {
        overwinter: Some(one),
        sapling: Some(one),
        blossom: Some(one),
        heartwood: Some(one),
        canopy: Some(one),
        nu5: Some(one),
        nu6: Some(one),
        nu6_1: Some(four),
        nu6_2: Some(four),
        nu6_3: Some(four),
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
/// - The genesis block hash matches the selected boot-network constant.
/// - Tip is at or after NU5 activation (consensus baseline).
async fn verify_chain_integrity<P: Parameters>(
    info: &zcash::BlockchainInfo,
    network: &P,
) -> (ChainClient, BlockHeight) {
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

    // Network identity check. This is hash-only because upstream Block::read
    // intentionally rejects the genesis block.
    {
        let genesis_hash = rpc
            .get_block_hash(BlockHeight::from_u32(0))
            .await
            .expect("FATAL: failed to fetch genesis hash via JSON-RPC");
        assert_eq!(
            genesis_hash, EXPECTED_GENESIS,
            "FATAL: genesis block hash mismatch — Zebra is not on the boot-selected network"
        );
    }

    // Fetch the tip block via JSON-RPC since Zebra gRPC doesn't implement get_block.
    let block = rpc
        .get_block(network, tip_height)
        .await
        .expect("FATAL: failed to fetch tip block via JSON-RPC");

    // Consensus baseline: NU5 must be active.
    {
        assert!(
            network.is_nu_active(NetworkUpgrade::Nu5, tip_height),
            "FATAL: node is on a pre-NU5 branch (tip {})",
            u32::from(tip_height),
        );
    }

    tracing::info!(
        height = u32::from(tip_height),
        tx_count = block.vtx().len(),
        "boot: tip block verified, chain integrity ok"
    );

    (chain, tip_height)
}

// ---------------------------------------------------------------------------
// Step 6: ZNS Origin Checkpoint
// ---------------------------------------------------------------------------

/// The Ironwood (NU6.3) activation height in boot-proven parameters.
pub fn ironwood_activation_height<P: Parameters>(network: &P) -> BlockHeight {
    network
        .activation_height(NetworkUpgrade::Nu6_3)
        .expect("NU6.3 activation height must be set in zcash_protocol")
}

/// Fetches the origin checkpoint from Zebra via `z_gettreestate`.
///
/// The mint orchestrator begins scanning blocks from the boot-proven
/// `ironwood_activation_height`.
/// The checkpoint provides the commitment tree state for the block immediately
/// preceding it, establishing the tree root for the wallet.
///
/// Sapling and Orchard trees are fetched from Zebra (they contain years of
/// commitments at this height). The Ironwood tree is empty — it does not
/// exist until Ironwood activates.
///
/// Zebra is the trust root (same TEE). `verify_chain_integrity` already
/// cross-validates gRPC vs JSON-RPC, verifies the selected network's genesis
/// block hash, and checks the required upgrade baseline. No hardcoded
/// origin-hash pinning is needed — the checkpoint hash from `z_gettreestate`
/// is stored in metadata for reference.
async fn origin_checkpoint<P: Parameters>(rpc: &zcash::JsonRpc, network: &P) -> CheckpointData {
    let checkpoint_height = ironwood_activation_height(network).saturating_sub(1);

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
static EXPECTED_SEED_FINGERPRINT_RAW: &str = include_str!("../deployment/seed_fingerprint.txt");

fn expected_seed_fingerprint() -> &'static str {
    EXPECTED_SEED_FINGERPRINT_RAW.trim()
}

fn verify_fingerprint(seed: &Secret<[u8; 32]>, expected: &str) {
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");

    #[cfg(feature = "dev-seed")]
    {
        let _ = expected; // Suppress unused warning in dev mode only.
        tracing::warn!(
            "boot: dev-seed fingerprint = {} (verification skipped)",
            actual
        );
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
fn generate_attestation_report_data<P: Parameters>(
    network: &P,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
) -> [u8; 64] {
    use zcash_keys::keys::UnifiedAddressRequest;

    let (treasury_addr, _) = treasury_keys
        .fvk()
        .default_address(UnifiedAddressRequest::SHIELDED)
        .expect("FATAL: Treasury FVK missing default address");
    let treasury_addr_str = treasury_addr.encode(network);
    let registry_fvk_str = registry_keys.fvk().encode(network);

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

    #[cfg(feature = "dev-regtest")]
    #[test]
    fn regtest_parameters_match_the_pinned_harness_schedule() {
        let network = regtest_network();
        let one = BlockHeight::from_u32(1);
        let four = BlockHeight::from_u32(4);

        assert_eq!(
            network.network_type(),
            zcash_protocol::consensus::NetworkType::Regtest
        );
        for upgrade in [
            NetworkUpgrade::Overwinter,
            NetworkUpgrade::Sapling,
            NetworkUpgrade::Blossom,
            NetworkUpgrade::Heartwood,
            NetworkUpgrade::Canopy,
            NetworkUpgrade::Nu5,
            NetworkUpgrade::Nu6,
        ] {
            assert_eq!(network.activation_height(upgrade), Some(one));
        }
        for upgrade in [
            NetworkUpgrade::Nu6_1,
            NetworkUpgrade::Nu6_2,
            NetworkUpgrade::Nu6_3,
        ] {
            assert_eq!(network.activation_height(upgrade), Some(four));
        }
        assert!(!network.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(3)));
        assert!(network.is_nu_active(NetworkUpgrade::Nu6_3, four));
    }
}
