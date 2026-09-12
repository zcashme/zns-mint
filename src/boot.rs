//! The boot sequence: acquire and verify every capability the run loop
//! cannot acquire for itself, then hand them over as one contract.
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use secrecy::{ExposeSecret, Secret};
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
use zcash_protocol::consensus::MainNetwork;
#[cfg(feature = "testnet")]
use zcash_protocol::consensus::TestNetwork;
use zcash_protocol::consensus::{BlockHeight, Parameters};
#[cfg(feature = "regtest")]
use zcash_protocol::local_consensus::LocalNetwork;
use zip32::fingerprint::SeedFingerprint;

#[cfg(not(feature = "regtest"))]
use std::str::FromStr;

use zeroize::Zeroize;

use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::mtp::MtpTracker;
use crate::mint::otp::OtpQueue;
use crate::mint::pricing::Oracle;
use crate::mint::registry::{ReceivedNameNote, Registry};
use crate::mint::{decrypt_name_notes, MINT_BIRTHDAY, MIN_TREASURY_BALANCE, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;
use crate::zcash::{self, ChainClient};
use sapling::circuit::{OutputParameters, SpendParameters};
use incrementalmerkletree::Position;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{chain::ChainState, BlockMetadata, WalletWrite as _};
use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
use zcash_client_backend::scanning::Nullifiers;
use std::convert::Infallible;

// ---------------------------------------------------------------------------
// Boot life-cycle
// ---------------------------------------------------------------------------

/// The boot product: constructed only after every boot check succeeds.
/// Consumed exactly once by `main`'s exhaustive destructure — the seam
/// contract, one criterion line per field.
pub struct Boot<P: Parameters> {
    /// verified: boot-to-loop consensus — the loop never discovers parameters
    pub network: P,
    /// acquired: boot proved that both Zebra transports are live
    pub chain: ChainClient,
    /// produced: trees seeded from the verified origin
    pub wallet: Wallet,
    /// produced: the origin cursor the loop extends
    pub cursor: BlockMetadata,
    /// cannot: derived from the seed — the seed dies before this exists
    pub treasury_keys: TreasuryKeys,
    /// cannot: derived from the seed
    pub registry_keys: RegistryKeys,
    /// must not fail after attestation: hash-verified before the report
    pub sapling_spend: SpendParameters,
    /// must not fail after attestation: hash-verified before the report
    pub sapling_output: OutputParameters,
    /// produced: backfilled before the first scan
    pub mtp: MtpTracker,
    /// must not: fail-closed at birth — the first price or no start
    pub oracle: Oracle,
    /// boot-initialized faculty: born empty, filled by `main`
    pub challenges: OtpQueue,
    /// produced: scanned and verified during boot sync
    pub registry: Registry,
}

/// Network label for logging.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
const NETWORK_LABEL: &str = "mainnet";

#[cfg(feature = "testnet")]
const NETWORK_LABEL: &str = "testnet";

#[cfg(feature = "regtest")]
const NETWORK_LABEL: &str = "regtest";

#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
impl Boot<MainNetwork> {
    pub async fn start() -> Self {
        Self::start_with_network(zcash_protocol::consensus::MAIN_NETWORK).await
    }
}

#[cfg(feature = "testnet")]
impl Boot<TestNetwork> {
    pub async fn start() -> Self {
        Self::start_with_network(zcash_protocol::consensus::TEST_NETWORK).await
    }
}

#[cfg(feature = "regtest")]
impl Boot<LocalNetwork> {
    /// Development-harness entry point. It is unavailable unless the
    /// development-only `regtest` feature is compiled in.
    pub async fn start() -> Self {
        Self::start_with_network(regtest_network()).await
    }
}

impl<P: Parameters + Send + 'static> Boot<P> {
    /// Boot sequence for a concrete, boot-owned network parameter set.
    ///
    async fn start_with_network(network: P) -> Self {
        tracing::info!("boot: starting");

        // 1. Liveness + connect: confirm both Zebra transports, get chain client.
        let (chain_client, _tip_height) = connect_zebra().await;

        // 2. Seed intake + verification: read capsule, derive sealing key,
        //    decrypt, verify fingerprint, then derive keys. The seed lives
        //    only inside this block — Secret's Drop wipes it.
        let (treasury_keys, registry_keys) = {
            tracing::info!("boot: reading seed capsule from keys/zns_seed.capsule");
            let blob = std::fs::read("keys/zns_seed.capsule").expect(
                "FATAL: failed to read keys/zns_seed.capsule. The mint cannot boot without the sealed seed.",
            );
            let seed = decrypt_sealed_blob(&blob);
            verify_fingerprint(&seed, SEED_FINGERPRINT_RAW.trim());
            (
                TreasuryKeys::derive(&network, &seed),
                RegistryKeys::derive(&network, &seed),
            )
        };
        tracing::info!("boot: keys derived (treasury=acct0, registry=acct1); seed wiped");

        // 3a. Origin checkpoint: fetch tree state from Zebra. The wallet is
        // born from it (trees seeded) and the cursor derives from it.
        //
        // `ChainState` (frontiers) seeds the trees; the cursor carries
        // `BlockMetadata` (height, hash, tree sizes) — the upstream continuity
        // value `scan_block`'s `prior_metadata` and every `to_block_metadata()`
        // call produce. Sizes derive from the frontiers (`Frontier::tree_size`),
        // mirroring upstream's `ScannedBlock::to_block_metadata`.
        let rpc = zcash::JsonRpc::new();
        let origin = origin_checkpoint(&rpc).await;
        let checkpoint_height = origin.block_height();

        // 3b. Wallet initialization from the checkpoint's chain state.
        let mut wallet = Wallet::new(
            [
                (TREASURY_ACCOUNT, treasury_keys.fvk()),
                (REGISTRY_ACCOUNT, registry_keys.fvk()),
            ],
            &origin,
        )
        .expect("FATAL: failed to seed commitment trees from the verified Zebra checkpoint");
        tracing::info!(
            "boot: wallet initialized with trees seeded from origin checkpoint at height {}",
            u32::from(checkpoint_height)
        );

        // 3c. MTP backfill: the 11 header timestamps through the origin
        // checkpoint, so the MTP window is complete before the first scan.
        let mut mtp = MtpTracker::default();
        mtp.backfill(checkpoint_height, |height| {
            let rpc = rpc.clone();
            async move {
                let (_, _, timestamp) = rpc.get_block_header(height).await?;
                Ok::<_, zcash::TransportError>(
                    u32::try_from(timestamp.as_seconds())
                        .expect("Zcash block-header timestamps are u32 seconds"),
                )
            }
        })
        .await
        .expect("FATAL: MTP backfill from Zebra failed");
        tracing::info!(
            "boot: MTP backfilled from headers through checkpoint {}",
            u32::from(checkpoint_height)
        );

        // 4. Boot sync: scan from checkpoint to chain tip.
        let mut cursor = block_metadata(&origin);
        let mut registry = Registry::new(checkpoint_height);
        let source = crate::zcash::CanonicalBlockSource::new();
        let (best_height, _best_hash) = source.exact_tip().await
            .expect("FATAL: Zebra tip unavailable during boot sync");
        tracing::info!(
            from = u32::from(checkpoint_height),
            to = u32::from(best_height),
            "boot: syncing to chain tip"
        );
        while cursor.block_height() < best_height {
            let from_height = cursor.block_height();
            let next_height = from_height + 1;

            let from_state = rpc.chain_state_at(from_height).await
                .expect("FATAL: chain state unavailable during boot sync");
            let block = rpc.get_block(&network, next_height).await
                .expect("FATAL: block unavailable during boot sync");
            let block_time = block.header().time;

            let candidates = decrypt_name_notes(&network, &block, &registry_keys);
            let name_notes: Vec<ReceivedNameNote> = candidates
                .iter()
                .map(|c| ReceivedNameNote::new(c.txid, c.action_index, c.nullifier, c.payload.clone()))
                .collect();
            let treasury_memos = crate::mint::note::decrypt_treasury_memos(&block, &treasury_keys);

            let (header, batches) = decrypt_block(&network, block, wallet.scanning_keys());
            let nullifiers = Nullifiers::unspent(&wallet)
                .expect("FATAL: wallet nullifiers unavailable during boot sync");
            let scanned = scan_block(
                &network, next_height, &header, batches,
                wallet.scanning_keys(), &nullifiers, Some(&cursor),
                |_| Ok::<Option<(zip32::AccountId, Option<transparent::keys::TransparentKeyScope>)>, Infallible>(None),
            ).expect("FATAL: block scan failed during boot sync");

            let mut next_mtp = mtp.clone();
            next_mtp.update(next_height, block_time);
            let block_mtp = next_mtp.current().expect("FATAL: MTP unavailable");

            let (next_registry, accepted_name_notes) =
                registry.apply_block(&network, &scanned, &name_notes, block_mtp);

            let ironwood_start = scanned.ironwood().final_tree_size()
                .checked_sub(u32::try_from(scanned.ironwood().commitments().len())
                    .expect("Ironwood action count fits u32"))
                .expect("FATAL: impossible Ironwood tree size");
            let accepted_name_notes = accepted_name_notes.into_iter().map(|index| {
                let candidate = &candidates[index];
                let position = Position::from(
                    u64::from(ironwood_start)
                        + u64::try_from(candidate.ordinal).expect("ordinal fits u64"),
                );
                (index, position)
            }).collect::<Vec<_>>();
            let next_metadata = scanned.to_block_metadata();

            wallet.put_blocks(&from_state, vec![scanned])
                .expect("FATAL: wallet commit failed during boot sync");
            // Upstream's ScannedBlock drops note plaintexts; the Treasury
            // lane's memos were decrypted above and are stored alongside.
            for (txid, action_index, memo) in treasury_memos {
                wallet.store_scanned_memo(
                    zcash_client_backend::wallet::NoteId::new(
                        txid,
                        zcash_protocol::ShieldedPool::Ironwood,
                        u16::try_from(action_index).expect("Ironwood action index fits u16"),
                    ),
                    memo,
                );
            }
            for (index, position) in accepted_name_notes {
                let c = &candidates[index];
                wallet.store_name_note(
                    next_height, position, c.txid, c.action_index,
                    c.note.clone(), c.nullifier, c.ephemeral_key.clone(), c.memo,
                );
            }

            mtp = next_mtp;
            registry = next_registry;
            cursor = next_metadata;
        }
        tracing::info!(
            height = u32::from(cursor.block_height()),
            "boot: synced to chain tip"
        );

        // 5. Genesis sanity checks. The anchor lineage pool is the ceremony's
        // root, conserved one-for-one by every accepted claim: exactly
        // ANCHOR_POOL_SIZE standing, forever. Forged or donated zero-value
        // Registry notes are not in the pool and never count.
        let anchor_count = registry.anchor_pool().len();
        assert_eq!(
            anchor_count,
            crate::mint::registry::ANCHOR_POOL_SIZE,
            "FATAL: anchor lineage pool expected {}, found {anchor_count}",
            crate::mint::registry::ANCHOR_POOL_SIZE
        );
        let treasury_balance: u64 = wallet
            .unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(best_height))
            .iter()
            .map(|n| n.note().value().inner())
            .sum();
        assert!(
            treasury_balance >= MIN_TREASURY_BALANCE,
            "FATAL: Treasury balance {treasury_balance} below minimum {MIN_TREASURY_BALANCE}"
        );
        tracing::info!(
            anchors = anchor_count,
            treasury_balance,
            "boot: genesis sanity checks passed"
        );

        // 6. Price fetch (MTP is now at the tip).
        let mtp_now = mtp.current().expect("MTP complete after sync");
        let price = crate::mint::pricing::fetch_round()
            .await
            .expect("FATAL: initial price fetch failed; restart when exchanges are reachable");
        let oracle = Oracle::new(price, mtp_now);
        tracing::info!(
            usd_per_zec = %price.round_dp(2),
            zats_per_usd = oracle.current().into_u64(),
            "boot: initial price ingested"
        );

        // The challenge memory: empty by construction, filled by the run
        // loop as liveness challenges and update/release relays are issued.
        let challenges = OtpQueue::new();

        // 4. Sapling proving parameters. Loading and hash verification happen
        // before attestation: a mint that produces a report can also prove
        // every transaction shape it is responsible for broadcasting.
        let sapling_spend = load_sapling_spend_params();
        let sapling_output = load_sapling_output_params();

        // 5. Attestation (production only). Nothing fallible is acquired
        // after this point.
        #[cfg(not(feature = "regtest"))]
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
            "boot: complete at tip {}",
            u32::from(cursor.block_height())
        );

        Boot {
            network,
            chain: chain_client,
            cursor,
            wallet,
            treasury_keys,
            registry_keys,
            sapling_spend,
            sapling_output,
            mtp,
            oracle,
            challenges,
            registry,
        }
    }
}

use crate::wallet::block_metadata;

#[cfg(feature = "regtest")]
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
// Step 1: Liveness + connect
// ---------------------------------------------------------------------------

/// Zebra liveness; boot tip.
async fn connect_zebra() -> (ChainClient, BlockHeight) {
    // JSON-RPC liveness
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

    // gRPC liveness; the tip stream is change-only, so the boot tip comes
    // from the getblockchaininfo answer above.
    let mut chain = ChainClient::connect()
        .await
        .expect("FATAL: Zebra gRPC unreachable or timed out");
    chain
        .chain_tip_change_stream()
        .await
        .expect("FATAL: chain_tip_change gRPC call failed");
    tracing::info!("boot: gRPC chain client connected");

    (chain, BlockHeight::from_u32(info.blocks))
}

// ---------------------------------------------------------------------------
// Step 2: Seed intake + verification
// ---------------------------------------------------------------------------

/// The sealed seed envelope written by zns-keygen: magic, fingerprint
/// (authenticated as additional data), nonce, ciphertext.
#[derive(serde::Deserialize, serde::Serialize)]
struct SeedCapsule {
    magic: [u8; 8],
    fingerprint: [u8; 32],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Decrypts the seed capsule with this instance's sealing key; the raw key
/// is wiped before return and the caller's `Secret` wipes the seed on drop.
fn decrypt_sealed_blob(blob: &[u8]) -> Secret<[u8; 32]> {
    tracing::info!("boot: deriving instance-bound SEV-SNP sealing key");
    let mut raw_key = derive_sealing_key();

    let capsule: SeedCapsule =
        postcard::from_bytes(blob).expect("FATAL: failed to parse zns_seed.capsule");
    assert_eq!(&capsule.magic, b"ZNS_SEED", "FATAL: capsule magic mismatch");

    let cipher =
        XChaCha20Poly1305::new_from_slice(&raw_key).expect("sealing key is exactly 32 bytes");
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
    raw_key.zeroize();

    if plaintext.len() != 32 {
        plaintext.zeroize();
        panic!("FATAL: decrypted seed is not exactly 32 bytes");
    }
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Secret::new(seed_bytes)
}

/// Derives — never fetches — the sealing key from the SEV-SNP firmware at
/// boot: `firmware.get_derived_key` returns a VCEK-rooted, per-chip key mixed
/// from exactly two guest fields, matching zns-keygen:
///   guest_policy — launch conditions (debug, SMT, migration)
///   measurement  — code identity (hash of the guest image)
///
/// image_id and family_id are deliberately excluded: they are
/// hypervisor-supplied labels with no security content, and including them
/// makes the key brittle to launch-blob drift. VCEK (root_key_select = false)
/// is stable across reboots; VMRK is random per launch without a Migration
/// Agent and would brick the capsule on first reboot.
#[cfg(target_os = "linux")]
fn derive_sealing_key() -> [u8; 32] {
    use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

    let mut firmware = Firmware::open()
        .expect("FATAL: SEV-SNP firmware not available — cannot derive sealing key");
    let mut guest_fields = GuestFieldSelect::default();
    guest_fields.set_guest_policy(true);
    guest_fields.set_measurement(true);
    let request = DerivedKey::new(false, guest_fields, 0, 0, 0, None);
    firmware
        .get_derived_key(Some(1), request)
        .expect("FATAL: failed to derive SEV-SNP VCEK sealing key")
}

#[cfg(not(target_os = "linux"))]
fn derive_sealing_key() -> [u8; 32] {
    panic!("FATAL: the mint boots only on AMD SEV-SNP Linux. This platform cannot hold the seed.")
}

static SEED_FINGERPRINT_RAW: &str = "PLACEHOLDER";

fn verify_fingerprint(seed: &Secret<[u8; 32]>, expected: &str) {
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");

    #[cfg(feature = "regtest")]
    {
        let _ = expected; // Suppress unused warning in dev mode only.
        tracing::warn!(
            "boot: regtest fingerprint = {} (verification skipped)",
            actual
        );
    }

    #[cfg(not(feature = "regtest"))]
    {
        #[cfg(not(feature = "testnet"))]
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
// Step 3: Initialize (origin checkpoint, wallet, MTP)
// ---------------------------------------------------------------------------

/// Fetches the origin treestate from Zebra: the block before the birthday.
///
/// Zebra is part of the same measured TEE image; its identity is guaranteed
/// by the SEV-SNP attestation, not by runtime RPC checks.
async fn origin_checkpoint(rpc: &zcash::JsonRpc) -> ChainState {
    let checkpoint_height = MINT_BIRTHDAY - 1;

    let chain_state = rpc
        .chain_state_at(checkpoint_height)
        .await
        .expect("FATAL: birthday treestate unavailable from Zebra");

    tracing::info!(
        "boot: origin checkpoint at height {}, hash {}",
        u32::from(checkpoint_height),
        chain_state.block_hash()
    );

    chain_state
}

// ---------------------------------------------------------------------------
// Step 4: Sapling proving parameters
// ---------------------------------------------------------------------------

/// The BLAKE2b-512 hash of the canonical `sapling-spend.params` file.
const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";

/// The BLAKE2b-512 hash of the canonical `sapling-output.params` file.
const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";

/// Expected file sizes for the Sapling parameter files.
const SAPLING_SPEND_BYTES: u64 = 47_958_396;
const SAPLING_OUTPUT_BYTES: u64 = 3_592_860;

fn sapling_params_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("ZCASH_PARAMS_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    std::path::PathBuf::from(home).join(".zcash-params")
}

fn read_verified_sapling_params(
    path: &std::path::Path,
    expected_hash: &str,
    expected_bytes: u64,
) -> Vec<u8> {
    use std::io::Read;

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        size,
        expected_bytes,
        "Sapling params size mismatch at {}: expected {expected_bytes}, got {size}",
        path.display(),
    );

    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        panic!(
            "FATAL: cannot open Sapling params at {}: {e}",
            path.display()
        )
    });
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes).unwrap_or_else(|e| {
        panic!(
            "FATAL: cannot read Sapling params at {}: {e}",
            path.display()
        )
    });

    let hash = blake2b_simd::Params::new().hash_length(64).hash(&bytes);
    let hash_hex = hex::encode(hash.as_bytes());
    assert_eq!(
        hash_hex,
        expected_hash,
        "Sapling params hash mismatch at {}: expected {expected_hash}, got {hash_hex}",
        path.display(),
    );
    bytes
}

/// Loads and verifies the Sapling spend prover: file size, BLAKE2b-512 hash,
/// then upstream's own deserializer. Acquired by the run loop's prologue, not
/// by boot — boot passes what the loop cannot acquire for itself.
///
/// `verify_point_encodings: false` is upstream-documented for exactly this
/// pattern: verify the parameters another way, "such as checking the hash of
/// the parameters file on disk" (sapling-crypto 0.7.0, circuit.rs).
pub(crate) fn load_sapling_spend_params() -> SpendParameters {
    let dir = sapling_params_dir();
    let path = dir.join("sapling-spend.params");
    let bytes = read_verified_sapling_params(&path, SAPLING_SPEND_HASH, SAPLING_SPEND_BYTES);
    SpendParameters::read(&bytes[..], false)
        .expect("FATAL: failed to deserialize sapling-spend.params")
}

/// Loads and verifies the Sapling output prover. See
/// [`load_sapling_spend_params`].
pub(crate) fn load_sapling_output_params() -> OutputParameters {
    let dir = sapling_params_dir();
    let path = dir.join("sapling-output.params");
    let bytes = read_verified_sapling_params(&path, SAPLING_OUTPUT_HASH, SAPLING_OUTPUT_BYTES);
    OutputParameters::read(&bytes[..], false)
        .expect("FATAL: failed to deserialize sapling-output.params")
}

// ---------------------------------------------------------------------------
// Step 5: Attestation
// ---------------------------------------------------------------------------

/// Constructs the 64-byte attestation report data: BLAKE2b-512 of
/// `treasury_default_address || "||" || registry_fvk`.
///
/// An external verifier checks this against the expected Treasury address
/// and Registry UFVK, binding the attestation to the mint's identity.
#[cfg(not(feature = "regtest"))]
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

#[cfg(all(not(feature = "regtest"), target_os = "linux"))]
fn generate_mint_attestation(report_data: [u8; 64]) -> Vec<u8> {
    use sev::firmware::guest::Firmware;

    tracing::info!("boot: generating mint attestation report");

    let mut firmware = Firmware::open()
        .expect("FATAL: SEV-SNP firmware not available — cannot generate attestation");

    firmware
        .get_report(None, Some(report_data), None)
        .expect("FATAL: failed to request SEV-SNP attestation report")
}

#[cfg(all(not(feature = "regtest"), not(target_os = "linux")))]
fn generate_mint_attestation(_report_data: [u8; 64]) -> Vec<u8> {
    panic!("FATAL: mint attestation requires AMD SEV-SNP Linux.")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "regtest"))]
    #[should_panic(expected = "FATAL: SEED FINGERPRINT MISMATCH")]
    fn verify_fingerprint_mismatch_is_redacted() {
        use secrecy::Secret;
        let seed = Secret::new([0xAB; 32]);
        let wrong_fp = SeedFingerprint::from_seed(&[0xCD; 32]).unwrap().to_string();
        verify_fingerprint(&seed, &wrong_fp);
    }

    #[cfg(feature = "regtest")]
    #[test]
    fn regtest_parameters_match_the_pinned_harness_schedule() {
        use zcash_protocol::consensus::NetworkUpgrade;

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
        // The regtest birthday mirrors the harness: origin at 3, first
        // observed block at 4.
        assert_eq!(MINT_BIRTHDAY, four);
    }
}
