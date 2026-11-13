//! The mint's boot steps zns-rebind runs, copied from `mint/src/boot.rs`:
//! the build's network, then the seed intake with the same checks in the
//! same order.

use std::str::FromStr;

use secrecy::{ExposeSecret, Secret};
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
