//! The mint's boot steps zns-rebind runs, copied from `mint/src/boot.rs`:
//! the build's network, then the seed intake with the same checks in the
//! same order.

use std::str::FromStr;

use secrecy::{ExposeSecret, Secret};
use zcash_client_backend::data_api::chain::ChainState;
use zcash_protocol::consensus::BlockHeight as Height;
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
use zcash_protocol::consensus::MainNetwork;
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
use zcash_protocol::consensus::TestNetwork;
#[cfg(feature = "regtest")]
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork};
use zip32::fingerprint::SeedFingerprint;
use zns_canon::capsule::{parse_capsule, read_capsule_file, unseal_seed};
use zns_canon::custody;
use zns_canon::genesis::Anchor;
#[cfg(not(feature = "non-tee"))]
use zns_canon::sealing::derive_sealing_key;
#[cfg(feature = "non-tee")]
use zns_canon::sealing::dev_sealing_key;
use zns_canon::sealing::{SealingKey, TeeError};
use zns_mint::mint::mtp::MtpTracker;
use zns_mint::zcash::{self, CanonicalBlockSource};
use zns_mint::{RegistryKeys, TreasuryKeys};

/// Network label for logging.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
pub const NETWORK_LABEL: &str = "mainnet";

#[cfg(all(feature = "testnet", not(feature = "regtest")))]
pub const NETWORK_LABEL: &str = "testnet";

#[cfg(feature = "regtest")]
pub const NETWORK_LABEL: &str = "regtest";

/// The build-selected network type; exactly one per binary.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
pub type Network = MainNetwork;
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
pub type Network = TestNetwork;
#[cfg(feature = "regtest")]
pub type Network = LocalNetwork;

/// The one network value this build serves.
pub fn boot_network() -> Network {
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
        LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(1)),
            blossom: Some(BlockHeight::from_u32(1)),
            heartwood: Some(BlockHeight::from_u32(1)),
            canopy: Some(BlockHeight::from_u32(1)),
            nu5: Some(BlockHeight::from_u32(1)),
            nu6: Some(BlockHeight::from_u32(1)),
            nu6_1: Some(BlockHeight::from_u32(4)),
            nu6_2: Some(BlockHeight::from_u32(4)),
            nu6_3: Some(BlockHeight::from_u32(4)),
            nu7: None,
        }
    }
}

/// `non-tee` builds use the public test key, even on an SNP guest.
/// Hardware builds require the guest sealing key.
fn sealing_key() -> Result<SealingKey, TeeError> {
    #[cfg(feature = "non-tee")]
    {
        Ok(dev_sealing_key())
    }
    #[cfg(not(feature = "non-tee"))]
    {
        derive_sealing_key()
    }
}

/// SEV-SNP attestation report length. Any other size is not a report.
#[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
const ATTESTATION_REPORT_LEN: usize = 1184;

/// The keygen report has to cover this capsule file. It carries
/// `BLAKE2b-512(fingerprint ‖ capsule hash)` under the AMD signature.
/// A missing report, or one that does not cover this file, refuses boot.
#[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
fn require_keygen_attestation(capsule_bytes: &[u8], fingerprint: &SeedFingerprint) {
    let report = read_attestation_report(std::path::Path::new("keys/zns_attestation.bin"));
    zns_canon::attestation::verify(capsule_bytes, fingerprint, report)
        .expect("FATAL: keygen attestation report failed verification");
}

/// One open of the keygen report. The descriptor must be a regular file
/// of [`ATTESTATION_REPORT_LEN`] bytes; that same descriptor is what is read.
#[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
fn read_attestation_report(path: &std::path::Path) -> Vec<u8> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .unwrap_or_else(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                panic!("FATAL: {} is a symlink", path.display());
            }
            if error.kind() == std::io::ErrorKind::IsADirectory {
                panic!("FATAL: {} is not a regular file", path.display());
            }
            panic!("FATAL: cannot read {}: {error}", path.display());
        });
    let meta = file
        .metadata()
        .unwrap_or_else(|error| panic!("FATAL: cannot stat {}: {error}", path.display()));
    if !meta.file_type().is_file() {
        panic!("FATAL: {} is not a regular file", path.display());
    }
    if meta.len() != ATTESTATION_REPORT_LEN as u64 {
        panic!(
            "FATAL: {} is not a {ATTESTATION_REPORT_LEN}-byte SEV-SNP attestation report",
            path.display()
        );
    }
    let mut bytes = vec![0u8; ATTESTATION_REPORT_LEN];
    file.read_exact(&mut bytes)
        .unwrap_or_else(|error| panic!("FATAL: cannot read {}: {error}", path.display()));
    bytes
}

/// Reads `keys/zns_custody_manifest.toml`. Missing, malformed, or a non-hex
/// txid refuses the run.
pub fn load_manifest() -> (String, custody::Custody, Anchor) {
    let text = std::fs::read_to_string(custody::PATH)
        .unwrap_or_else(|error| panic!("FATAL: cannot read {}: {error}", custody::PATH));
    let anchor =
        Anchor::read(&text).unwrap_or_else(|error| panic!("FATAL: {} {error}", custody::PATH));
    let custody = custody::Custody::read(&text)
        .unwrap_or_else(|error| panic!("FATAL: {} {error}", custody::PATH));
    (text, custody, anchor)
}

fn require_ceremony_network(custody: &custody::Custody) {
    assert_eq!(
        custody.network,
        NETWORK_LABEL,
        "FATAL: {} network does not match {NETWORK_LABEL} build",
        custody::PATH
    );
}

fn verify_fingerprint(seed: &Secret<[u8; 32]>, expected: &str) {
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");

    let expected_fp = SeedFingerprint::from_str(expected)
        .unwrap_or_else(|_| panic!("FATAL: invalid seed_fingerprint in {}", custody::PATH));

    if actual != expected_fp {
        // Redacted panic: do not print either fingerprint.
        panic!(
            "FATAL: SEED FINGERPRINT MISMATCH — decrypted seed does not match {}",
            custody::PATH
        );
    }
    tracing::info!("rebind: seed fingerprint verified");
}

/// The seed intake: read the capsule, require the keygen report for this
/// file, unseal, check the fingerprint, derive both accounts' keys. The
/// seed lives only inside this function; `Secret`'s drop wipes it.
pub fn unseal(network: &Network, custody: &custody::Custody) -> (TreasuryKeys, RegistryKeys) {
    require_ceremony_network(custody);
    tracing::info!("rebind: reading seed capsule from keys/zns_seed.capsule");
    let blob = read_capsule_file("keys/zns_seed.capsule")
        .expect("FATAL: failed to read keys/zns_seed.capsule");
    let capsule = parse_capsule(&blob).expect("FATAL: failed to parse zns_seed.capsule");
    // Manifest, capsule field, and the attested fingerprint are one
    // value. Unseal then requires that value of the decrypted seed.
    let expected = SeedFingerprint::from_str(custody.seed_fingerprint.trim())
        .unwrap_or_else(|_| panic!("FATAL: invalid seed_fingerprint in {}", custody::PATH));
    if expected.to_bytes() != capsule.fingerprint {
        panic!(
            "FATAL: capsule fingerprint does not match {}",
            custody::PATH
        );
    }
    #[cfg(not(feature = "non-tee"))]
    require_keygen_attestation(&blob, &expected);
    let capsule_key = sealing_key().expect("FATAL: sealing key unavailable");
    let seed = unseal_seed(&capsule_key, &capsule).expect(
        "FATAL: failed to unseal seed. Capsule tampering, wrong TEE, or wrong capsule for this instance.",
    );
    verify_fingerprint(&seed, custody.seed_fingerprint.trim());
    (
        TreasuryKeys::derive(network, &seed),
        RegistryKeys::derive(network, &seed),
    )
}

/// The live mint's wallet origin (`46f61f9`): the treestate 101 blocks
/// before its birthday on mainnet and testnet, one block on regtest. The
/// wallet then holds every Treasury note the live mint holds.
pub async fn origin_checkpoint(
    birthday: Height,
    treestate: impl AsyncFnOnce(Height) -> Result<ChainState, zcash::TransportError>,
) -> ChainState {
    #[cfg(not(feature = "regtest"))]
    let checkpoint_height = birthday - 101;
    #[cfg(feature = "regtest")]
    let checkpoint_height = birthday - 1;

    let chain_state = treestate(checkpoint_height)
        .await
        .expect("FATAL: wallet origin treestate unavailable from Zebra");

    tracing::info!(
        "rebind: origin checkpoint at height {}, hash {}",
        u32::from(checkpoint_height),
        chain_state.block_hash()
    );

    chain_state
}

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
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "FATAL: cannot read Sapling params at {}: {e}",
            path.display()
        )
    });
    assert_eq!(
        bytes.len() as u64,
        expected_bytes,
        "Sapling params size mismatch at {}",
        path.display(),
    );
    let hash_hex = blake2b_simd::blake2b(&bytes).to_hex();
    assert_eq!(
        hash_hex.as_str(),
        expected_hash,
        "Sapling params hash mismatch at {}",
        path.display(),
    );
    bytes
}

/// The Sapling provers both builders need: size and BLAKE2b-512 checked,
/// then upstream's own deserializer.
pub fn sapling_provers() -> (
    sapling::circuit::SpendParameters,
    sapling::circuit::OutputParameters,
) {
    let dir = sapling_params_dir();
    let spend = read_verified_sapling_params(
        &dir.join("sapling-spend.params"),
        SAPLING_SPEND_HASH,
        SAPLING_SPEND_BYTES,
    );
    let output = read_verified_sapling_params(
        &dir.join("sapling-output.params"),
        SAPLING_OUTPUT_HASH,
        SAPLING_OUTPUT_BYTES,
    );
    (
        sapling::circuit::SpendParameters::read(&spend[..], false)
            .expect("FATAL: failed to deserialize sapling-spend.params"),
        sapling::circuit::OutputParameters::read(&output[..], false)
            .expect("FATAL: failed to deserialize sapling-output.params"),
    )
}

/// Replaces the manifest in one rename: a crash leaves the old file or the
/// new one, never a short one.
pub fn write_manifest(text: &str) {
    use std::io::Write;
    let path = std::path::Path::new(custody::PATH);
    let tmp = path.with_extension("toml.tmp");
    let mut file = std::fs::File::create(&tmp)
        .unwrap_or_else(|error| panic!("FATAL: create {}: {error}", tmp.display()));
    file.write_all(text.as_bytes())
        .unwrap_or_else(|error| panic!("FATAL: write {}: {error}", tmp.display()));
    file.sync_all()
        .unwrap_or_else(|error| panic!("FATAL: sync {}: {error}", tmp.display()));
    std::fs::rename(&tmp, path)
        .unwrap_or_else(|error| panic!("FATAL: rename to {}: {error}", path.display()));
    std::fs::File::open(path.parent().expect("keys/"))
        .and_then(|dir| dir.sync_all())
        .expect("FATAL: sync keys/");
}

/// The 11 header timestamps through the origin checkpoint, so the MTP
/// window is complete before the first block applies.
pub async fn mtp_through(checkpoint: Height, source: &CanonicalBlockSource) -> MtpTracker {
    let mut mtp = MtpTracker::default();
    mtp.backfill(checkpoint, |height| {
        let source = source.clone();
        async move { source.header_time(height).await }
    })
    .await
    .expect("FATAL: MTP backfill from Zebra failed");
    mtp
}
