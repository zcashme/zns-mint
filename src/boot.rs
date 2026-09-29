//! The boot sequence: acquire and verify every capability the run loop
//! cannot acquire for itself, then hand them over as one contract.
pub mod capsule;
mod key;
pub mod tee;

pub use key::{RegistryKeys, TreasuryKeys};

use secrecy::{ExposeSecret, Secret};
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
use zcash_protocol::consensus::MainNetwork;
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
use zcash_protocol::consensus::TestNetwork;
use zcash_protocol::consensus::{BlockHeight, Parameters};
#[cfg(feature = "regtest")]
use zcash_protocol::local_consensus::LocalNetwork;
use zip32::fingerprint::SeedFingerprint;

#[cfg(not(feature = "regtest"))]
use std::str::FromStr;

use crate::mint::mtp::MtpTracker;
use crate::mint::presale::{self, AccessCodeKey};
use crate::mint::pricing::Oracle;
use crate::mint::registry::Registry;
use crate::mint::treasury::OtpQueue;
use crate::mint::{MIN_TREASURY_BALANCE, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;
use crate::zcash::{self, ChainClient};
use capsule::Capsule;
use sapling::circuit::{OutputParameters, SpendParameters};
use tee::Tee;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::{chain::ChainState, BlockMetadata};

// ---------------------------------------------------------------------------
// Boot life-cycle
// ---------------------------------------------------------------------------

/// The boot product: constructed only after every boot check succeeds.
/// Consumed exactly once by `main`'s exhaustive destructure — the seam
/// contract, one criterion line per field.
pub struct Boot<P: Parameters> {
    /// verified: boot-to-loop consensus — the loop never discovers parameters
    pub network: P,
    /// verified: Registry birth and the run loop's reorg boundary
    pub birthday: BlockHeight,
    /// acquired: boot proved that both Zebra transports are live
    pub chain: ChainClient,
    /// produced: trees seeded from the verified origin
    pub wallet: Wallet<P>,
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
    /// TEE-derived access-code key (HMAC purpose key, not the root)
    pub access_code_key: AccessCodeKey,
    /// produced: scanned and verified during boot sync
    pub registry: Registry,
}

/// Network label for logging.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
const NETWORK_LABEL: &str = "mainnet";

#[cfg(all(feature = "testnet", not(feature = "regtest")))]
const NETWORK_LABEL: &str = "testnet";

#[cfg(feature = "regtest")]
const NETWORK_LABEL: &str = "regtest";

/// The build-selected network type; exactly one per binary.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
type Network = MainNetwork;
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
type Network = TestNetwork;
#[cfg(feature = "regtest")]
type Network = LocalNetwork;

/// The one network value this build serves.
fn boot_network() -> Network {
    #[cfg(not(feature = "regtest"))]
    #[cfg(not(feature = "testnet"))]
    {
        zcash_protocol::consensus::MAIN_NETWORK
    }
    #[cfg(all(feature = "testnet", not(feature = "regtest")))]
    {
        zcash_protocol::consensus::TEST_NETWORK
    }
    #[cfg(feature = "regtest")]
    {
        regtest_network()
    }
}

/// Registry birth and the mint's MTP day-zero block.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(3_400_000);

#[cfg(all(feature = "testnet", not(feature = "regtest")))]
const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4_338_933);

/// Regtest birth: the fixture boundary. NU6.3 activates at height 4;
/// the fixture's coinbase maturity runs through 104; nothing the mint
/// owns is earlier.
#[cfg(feature = "regtest")]
const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(100);

impl Boot<Network> {
    /// Boot sequence for this build's network.
    pub async fn start() -> Self {
        let network = boot_network();
        tracing::info!("boot: starting");

        // 1. Liveness + connect: confirm both Zebra transports, get chain client.
        let (chain_client, _tip_height) = connect_zebra().await;

        // 1b. TEE handshake: pick the enclave seam. Production = `RealSnpTee`;
        // `fake-tee` feature = `FakeTee` for off-SNP tests. Capsule AEAD and
        // `report_data` stay real; only the key/report source changes.
        let tee = select_tee();

        // Access-code root from the TEE, then HMAC to the purpose key
        // (`access-code-v1`). Issuers with that purpose key can recompute
        // codes offline; the mint never stores codes in Supabase.
        let access_code_key = {
            let root = tee
                .derive_sealing_key(presale::ACCESS_CODE_KEY_CONTEXT)
                .expect("FATAL: access-code root key unavailable from the TEE");
            AccessCodeKey::from_private_key(&root)
        };

        // 2. Seed intake + verification: read capsule, unseal with the
        //    TEE-derived sealing key, verify the compiled-in fingerprint,
        //    then derive keys. The seed lives only inside this block —
        //    Secret's Drop wipes it.
        let (treasury_keys, registry_keys) = {
            tracing::info!("boot: reading seed capsule from keys/zns_seed.capsule");
            let blob = capsule::read_capsule_file("keys/zns_seed.capsule").expect(
                "FATAL: failed to read keys/zns_seed.capsule. The mint cannot boot without the sealed seed.",
            );
            let capsule = Capsule::parse(&blob).expect("FATAL: failed to parse zns_seed.capsule");
            tracing::info!("boot: deriving instance-bound sealing key from the TEE");
            let seed = capsule.unseal(tee.as_ref())
                .expect("FATAL: failed to unseal seed. Capsule tampering, wrong TEE, or wrong capsule for this instance.");
            verify_fingerprint(&seed, SEED_FINGERPRINT_RAW.trim());
            (
                TreasuryKeys::derive(&network, &seed),
                RegistryKeys::derive(&network, &seed),
            )
        };
        tracing::info!("boot: keys derived (treasury=acct0, registry=acct1); seed wiped");

        // 3. Born complete: fetch the origin checkpoint and both
        // subtree-root batches, then one `Wallet::new`.
        let rpc = zcash::JsonRpc::new();
        let origin = origin_checkpoint(&rpc).await;
        let checkpoint_height = origin.block_height();
        let sapling_roots = rpc
            .get_subtree_roots::<sapling::Node>("sapling", 0)
            .await
            .expect("FATAL: Sapling subtree roots unavailable from Zebra");
        let ironwood_roots = rpc
            .get_subtree_roots::<orchard::tree::MerkleHashOrchard>("ironwood", 0)
            .await
            .expect("FATAL: Ironwood subtree roots unavailable from Zebra");
        let mut wallet = Wallet::new(
            [
                (TREASURY_ACCOUNT, treasury_keys.fvk()),
                (REGISTRY_ACCOUNT, registry_keys.fvk()),
            ],
            &origin,
            &sapling_roots,
            &ironwood_roots,
            network,
        )
        .expect("FATAL: failed to seed commitment trees from the verified Zebra checkpoint");
        tracing::info!(
            height = u32::from(checkpoint_height),
            sapling_roots = sapling_roots.len(),
            ironwood_roots = ironwood_roots.len(),
            "boot: wallet born complete from the origin checkpoint"
        );

        // 3d. The mint's birthday: a throwaway window ending at the
        // birthday block, whose median is the birthday block's MTP —
        // the day-zero anchor for `current_day`.
        let mut birthday = MtpTracker::default();
        birthday
            .backfill(MINT_BIRTHDAY, |height| {
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
            .expect("FATAL: birthday MTP backfill from Zebra failed");
        let birthday_mtp = birthday
            .current()
            .expect("FATAL: birthday MTP unavailable from Zebra");
        let mut mtp = MtpTracker::born(birthday_mtp);

        // 3e. MTP backfill: the 11 header timestamps through the origin
        // checkpoint, so the MTP window is complete before the first scan.
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

        // 4. Boot sync: scan from checkpoint to chain tip. The body is
        // `apply_block` — the same one the run loop calls — with scratch
        // queues: arrivals from history are balance, not instruction, so
        // each block's intake lands in a queue that falls out of scope with
        // the iteration.
        let mut cursor = block_metadata(&origin);
        let mut registry = Registry::new();
        let source = crate::zcash::CanonicalBlockSource::new();
        let (best_height, _best_hash) = source
            .exact_tip()
            .await
            .expect("FATAL: Zebra tip unavailable during boot sync");
        tracing::info!(
            from = u32::from(checkpoint_height),
            to = u32::from(best_height),
            "boot: syncing to chain tip"
        );
        while cursor.block_height() < best_height {
            let from_height = cursor.block_height();
            let next_height = from_height + 1;

            let from_state = rpc
                .chain_state_at(from_height)
                .await
                .expect("FATAL: chain state unavailable during boot sync");
            let block = rpc
                .get_block(&network, next_height)
                .await
                .expect("FATAL: block unavailable during boot sync");

            let _ = crate::mint::apply_block(
                &network,
                MINT_BIRTHDAY,
                &registry_keys,
                &treasury_keys,
                &from_state,
                block,
                next_height,
                &mut wallet,
                &mut registry,
                &mut mtp,
                &mut cursor,
            );
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
        // Boot refuses to run with a treasury below MIN_TREASURY_BALANCE.
        // The node's tip is never pushed into the wallet.
        let treasury_balance = wallet
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .expect("FATAL: balance summary failed")
            .expect("FATAL: chain knowledge missing at boot balance check")
            .account_balances()
            .get(&TREASURY_ACCOUNT)
            .expect("FATAL: treasury account missing from summary")
            .ironwood_balance()
            .total()
            .into_u64();
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
        let today = mtp.current_day().expect("MTP complete after sync");
        let price = crate::mint::pricing::fetch_round()
            .await
            .expect("FATAL: initial price fetch failed; restart when exchanges are reachable");
        let oracle = Oracle::new(price, today, mtp_now);
        tracing::info!(
            usd_per_zec = %price.round_dp(2),
            zats_per_usd = oracle.current().into_u64(),
            "boot: initial price ingested"
        );

        // The challenge memory: empty by construction, filled by the run
        // loop as update/release relays are issued.
        let challenges = OtpQueue::new();

        // 7. Sapling proving parameters. Loading and hash verification happen
        // before attestation: a mint that produces a report can also prove
        // every transaction shape it is responsible for broadcasting.
        let sapling_spend = load_sapling_spend_params();
        let sapling_output = load_sapling_output_params();

        // 8. Attestation. Nothing fallible is acquired after this point.
        //
        // Regtest does NOT skip attestation: regtest is a local-consensus
        // toggle, not a TEE toggle. `--features fake-tee` (typically with
        // `regtest,fake-tee`) is what substitutes the report source so
        // the mint can produce a report outside SEV-SNP.
        {
            let report_data =
                generate_attestation_report_data(&network, &treasury_keys, &registry_keys);
            let attestation = tee
                .get_attestation(&report_data)
                .expect("FATAL: failed to obtain TEE attestation report");
            std::fs::write("zns_mint_attestation.bin", attestation.as_bytes())
                .expect("FATAL: failed to write attestation to disk");
            tracing::info!("boot: attestation report written to zns_mint_attestation.bin");
        }

        tracing::info!(
            network = NETWORK_LABEL,
            "boot: complete at tip {}",
            u32::from(cursor.block_height())
        );

        Boot {
            network,
            birthday: MINT_BIRTHDAY,
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
            access_code_key,
            registry,
        }
    }
}

use crate::wallet::block_metadata;

#[cfg(feature = "regtest")]
fn regtest_network() -> LocalNetwork {
    // Matches the live integration harness (zns-integration-tests
    // `zebra.rs`): every upgrade through NU6 defaults to 1 on regtest;
    // the NU6.x family activates at 4 — ahead of the mint's birthday.
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

/// Selects the TEE seam for this build: [`crate::tee::FakeTee`] behind the
/// `fake-tee` feature (dev-only; blocked from release by a
/// `compile_error!` in `crate::lib`), otherwise [`crate::tee::RealSnpTee`].
///
/// Returned as a boxed trait object because boot doesn't specialise on
/// which TEE it holds — the two capabilities it needs (sealing key,
/// attestation) are exactly what the trait exposes.
fn select_tee() -> Box<dyn Tee> {
    #[cfg(feature = "fake-tee")]
    {
        tracing::warn!(
            "boot: FAKE TEE selected — sealing key and attestation are dev-only; \
             any real verifier rejects this report"
        );
        Box::new(tee::FakeTee)
    }
    #[cfg(not(feature = "fake-tee"))]
    {
        Box::new(tee::RealSnpTee)
    }
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
// Step 3: Initialize (origin checkpoint, subtree roots, wallet, MTP)
// ---------------------------------------------------------------------------

/// Fetches the treestate immediately before the wallet scan window.
/// The checkpoint height must sit at or after every pool's activation —
/// `z_gettreestate` omits pool sections that were never active.
///
/// Zebra is part of the same measured TEE image; its identity is guaranteed
/// by the SEV-SNP attestation, not by runtime RPC checks.
async fn origin_checkpoint(rpc: &zcash::JsonRpc) -> ChainState {
    #[cfg(not(feature = "regtest"))]
    let checkpoint_height = MINT_BIRTHDAY - 101;
    #[cfg(feature = "regtest")]
    let checkpoint_height = MINT_BIRTHDAY - 1;

    let chain_state = rpc
        .chain_state_at(checkpoint_height)
        .await
        .expect("FATAL: wallet origin treestate unavailable from Zebra");

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

/// Loads and verifies the Sapling spend prover: size, BLAKE2b-512 hash,
/// then upstream's own deserializer.
///
/// `verify_point_encodings: false` is upstream-documented for exactly this
/// pattern: verify the parameters another way, "such as checking the hash of
/// the parameters file on disk" (sapling-crypto 0.7.0, circuit.rs).
fn load_sapling_spend_params() -> SpendParameters {
    let dir = sapling_params_dir();
    let path = dir.join("sapling-spend.params");
    let bytes = read_verified_sapling_params(&path, SAPLING_SPEND_HASH, SAPLING_SPEND_BYTES);
    SpendParameters::read(&bytes[..], false)
        .expect("FATAL: failed to deserialize sapling-spend.params")
}

/// Loads and verifies the Sapling output prover. See
/// [`load_sapling_spend_params`].
fn load_sapling_output_params() -> OutputParameters {
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
/// Production code path — not gated on any dev feature, so a `fake-tee`
/// build still binds a real identity into its (unverifiable) report.
fn generate_attestation_report_data(
    network: &Network,
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds encrypted scan fixtures with dummy proofs and signatures.
    fn scan_transaction(
        builder: orchard::builder::Builder,
    ) -> zcash_primitives::transaction::Transaction {
        let (bundle, _) = builder
            .build::<zcash_protocol::value::ZatBalance>(rand::rngs::OsRng)
            .unwrap()
            .unwrap();
        let proof_size = orchard::Proof::expected_proof_size(bundle.actions().len());
        let bundle = bundle.map_authorization(
            &mut (),
            |_, _, _| [0u8; 64].into(),
            |_, _| {
                orchard::bundle::Authorized::from_parts(
                    orchard::Proof::new(vec![0; proof_size]),
                    [0u8; 64].into(),
                )
            },
        );
        zcash_primitives::transaction::TransactionData::from_parts_v6(
            zcash_protocol::consensus::BranchId::Nu6_3,
            0,
            BlockHeight::from_u32(0),
            None,
            None,
            None,
            Some(bundle),
        )
        .freeze()
        .unwrap()
    }

    #[test]
    fn birthday_gates_protocol_processing_without_skipping_wallet_history() {
        use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
        use incrementalmerkletree::witness::IncrementalWitness;
        use orchard::builder::{Builder, BundleType};
        use orchard::bundle::BundleVersion;
        use orchard::tree::MerkleHashOrchard;
        use orchard::value::NoteValue;
        use zcash_client_backend::data_api::wallet::TargetHeight;
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_primitives::block::{Block, BlockHash, BlockHeaderData};
        use zcash_protocol::consensus::NetworkUpgrade;

        let network = boot_network();
        let seed = Secret::new([0; 32]);
        let treasury_keys = TreasuryKeys::derive(&network, &seed);
        let registry_keys = RegistryKeys::derive(&network, &seed);
        let treasury_fvk = treasury_keys.orchard_fvk();
        let registry_fvk = registry_keys.orchard_fvk();
        let first_height = network.activation_height(NetworkUpgrade::Nu6_3).unwrap() + 100;
        let second_height = first_height + 1;
        let origin = ChainState::empty(first_height - 1, BlockHash([0; 32]));
        let version = BundleVersion::ironwood_v3();
        let builder = |anchor| {
            Builder::new(
                BundleType::DEFAULT,
                version,
                version.default_flags(),
                anchor,
            )
            .unwrap()
        };
        let test_block = |tx, height: BlockHeight, prev_block| {
            let header = BlockHeaderData {
                version: 4,
                prev_block,
                merkle_root: [0; 32],
                final_sapling_root: [0; 32],
                time: u32::from(height),
                bits: 0,
                nonce: [0; 32],
                solution: vec![],
            }
            .freeze()
            .unwrap();
            Block::from_parts(header, (tx, Vec::new()).into(), height)
        };

        let mut funding = builder(orchard::Anchor::empty_tree());
        funding
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::from_raw(60_000),
                [0; 512],
            )
            .unwrap();
        let funding_tx = scan_transaction(funding);
        let funding_bundle = funding_tx.ironwood_bundle().unwrap();
        let (payment_index, _, payment, _, _) = funding_bundle
            .decrypt_outputs_with_keys(&[treasury_fvk.to_ivk(zip32::Scope::External)])
            .pop()
            .unwrap();
        let payment_nf = payment.nullifier(&treasury_fvk);
        let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let mut witness = None;
        for (index, action) in funding_bundle.actions().iter().enumerate() {
            let leaf = MerkleHashOrchard::from_cmx(action.cmx());
            tree.append(leaf).unwrap();
            if index == payment_index {
                witness = IncrementalWitness::from_tree(tree.clone());
            } else if let Some(witness) = witness.as_mut() {
                witness.append(leaf).unwrap();
            }
        }
        let funding_block = test_block(funding_tx, first_height, origin.block_hash());
        let funded = ChainState::new(
            first_height,
            funding_block.header().hash(),
            Frontier::empty(),
            Frontier::empty(),
            tree.to_frontier(),
        );
        let mut request = builder(tree.root().into());
        request
            .add_spend(
                treasury_fvk.clone(),
                payment,
                witness.unwrap().path().unwrap().into(),
            )
            .unwrap();
        let (ua, _) = treasury_keys
            .fvk()
            .default_address(UnifiedAddressRequest::SHIELDED)
            .unwrap();
        let memo = zcash_protocol::memo::MemoBytes::from_bytes(
            format!("ZNS:claim:forever:alice:{}", ua.encode(&network)).as_bytes(),
        )
        .unwrap();
        let expected_request = crate::mint::Request::Claim {
            name: crate::mint::Name::parse("alice").unwrap(),
            ua,
            term: crate::mint::Term::Forever,
            code: None,
        };
        request
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::from_raw(50_000),
                *memo.as_array(),
            )
            .unwrap();
        request
            .add_output(
                None,
                registry_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::ZERO,
                [0; 512],
            )
            .unwrap();
        let request_tx = scan_transaction(request);
        let request_txid = request_tx.txid();
        let request_bundle = request_tx.ironwood_bundle().unwrap();
        let (_, _, gift, _, _) = request_bundle
            .decrypt_outputs_with_keys(&[registry_fvk.to_ivk(zip32::Scope::External)])
            .pop()
            .unwrap();
        let gift_nf = gift.nullifier(&registry_fvk);
        let first_root = tree.root();
        for action in request_bundle.actions().iter() {
            tree.append(MerkleHashOrchard::from_cmx(action.cmx()))
                .unwrap();
        }
        let roots = [first_root, tree.root()];
        let request_block = test_block(request_tx, second_height, funded.block_hash());
        let blocks = [(origin.clone(), funding_block), (funded, request_block)];

        for birthday in [second_height + 1, second_height] {
            let mut wallet = Wallet::new(
                [
                    (TREASURY_ACCOUNT, treasury_keys.fvk()),
                    (REGISTRY_ACCOUNT, registry_keys.fvk()),
                ],
                &origin,
                &[],
                &[],
                network,
            )
            .unwrap();
            let mut registry = Registry::new();
            let mut mtp = MtpTracker::default();
            let mut cursor = block_metadata(&origin);
            let mut tree_size = 0;
            for (index, (from_state, block)) in blocks.iter().enumerate() {
                let height = first_height + u32::try_from(index).unwrap();
                tree_size +=
                    u32::try_from(block.vtx()[0].ironwood_bundle().unwrap().actions().len())
                        .unwrap();
                let arrivals = crate::mint::apply_block(
                    &network,
                    birthday,
                    &registry_keys,
                    &treasury_keys,
                    from_state,
                    test_block(block.vtx()[0].clone(), height, from_state.block_hash()),
                    height,
                    &mut wallet,
                    &mut registry,
                    &mut mtp,
                    &mut cursor,
                );
                assert_eq!(cursor.block_height(), height);
                assert_eq!(cursor.block_hash(), block.header().hash());
                assert_eq!(wallet.tip().block_height(), height);
                assert_eq!(wallet.tip().block_hash(), cursor.block_hash());
                assert_eq!(cursor.sapling_tree_size(), Some(0));
                assert_eq!(cursor.orchard_tree_size(), Some(0));
                assert_eq!(cursor.ironwood_tree_size(), Some(tree_size));
                assert_eq!(
                    wallet.ironwood_anchor(height).unwrap().unwrap(),
                    roots[index].into()
                );
                assert_eq!(
                    mtp.current().unwrap().as_seconds(),
                    i64::from(u32::from(height))
                );
                let tip = TargetHeight::from(height + 1);
                let notes = wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, tip);
                assert_eq!(notes.len(), 1);
                assert_eq!(notes[0].note().value().inner(), [60_000, 50_000][index]);
                assert_eq!(
                    wallet
                        .unspent_ironwood_note_by_nullifier(TREASURY_ACCOUNT, payment_nf, tip)
                        .is_some(),
                    index == 0,
                );
                assert_eq!(
                    wallet
                        .unspent_ironwood_note_by_nullifier(REGISTRY_ACCOUNT, gift_nf, tip)
                        .is_some(),
                    index == 1,
                );
                assert_eq!(
                    registry.anchor_pool().len(),
                    usize::from(height >= birthday)
                );
                assert_eq!(
                    registry.anchor_pool().contains(&gift_nf),
                    height >= birthday
                );
                if height < birthday {
                    assert!(arrivals.is_empty());
                } else {
                    assert!(matches!(
                        arrivals.as_slice(),
                        [(txid, crate::mint::MintInbound::Request(request), paid)]
                            if *txid == request_txid && request == &expected_request
                                && paid.into_u64() == 50_000
                    ));
                }
            }
        }
    }

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
        // The regtest birthday sits past the NU6.3 activation and the
        // fixture's coinbase-maturity boilerplate: the wallet's history
        // begins at the fixture boundary.
        assert_eq!(MINT_BIRTHDAY, BlockHeight::from_u32(100));
    }
}
