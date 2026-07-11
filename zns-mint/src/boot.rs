//! ZNS Mint Boot Sequence

use secrecy::{ExposeSecret, Secret};
use zip32::fingerprint::SeedFingerprint;
use std::future::Future;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
#[cfg(target_os = "linux")]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use zeroize::Zeroize;

#[derive(serde::Deserialize)]
struct SeedCapsule {
    magic: [u8; 8],
    fingerprint: [u8; 32],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

const EXPECTED_SEED_FINGERPRINT: &str =
    "zip32seedfp1rc52vh66vxh4klcd22fgmxlzfxcutdfr34gahe5mksv2g82mcejsqqwlyu";

pub trait BootEnv {
    type BlockchainInfo;
    type ChainTip;
    type AccountKeys;
    type Wallet;
    type NetworkClient;

    fn check_liveness(&self) -> impl Future<Output = Self::BlockchainInfo> + Send;
    fn verify_chain_integrity(&self, info: &Self::BlockchainInfo) -> impl Future<Output = (Self::NetworkClient, Self::ChainTip)> + Send;
    fn derive_keys(&self, seed: &Secret<[u8; 32]>) -> (Self::AccountKeys, Self::AccountKeys);
    fn initialize_wallet(&self, treasury: &Self::AccountKeys, registry: &Self::AccountKeys) -> Self::Wallet;
    fn generate_attestation_report_data(&self, treasury: &Self::AccountKeys, registry: &Self::AccountKeys) -> [u8; 64];
}

pub async fn boot<E: BootEnv>(
    env: &E,
) -> (E::NetworkClient, E::Wallet, E::AccountKeys, E::AccountKeys, E::ChainTip) {
    tracing::info!("boot: starting");

    let info = env.check_liveness().await;
    let (client, tip) = env.verify_chain_integrity(&info).await;

    let source = obtain_key_source();
    let seed = match &source {
        KeySource::SealedBlob { blob } => decrypt_sealed_blob(blob),
        #[cfg(feature = "dev-seed")]
        KeySource::Dev => Secret::new([0u8; 32]),
    };
    verify_fingerprint(&seed);

    let (treasury_keys, registry_keys) = env.derive_keys(&seed);
    tracing::info!("boot: keys derived");

    let wallet = env.initialize_wallet(&treasury_keys, &registry_keys);

    let report_data = env.generate_attestation_report_data(&treasury_keys, &registry_keys);
    let attestation_bytes = generate_mint_attestation(report_data);
    if !attestation_bytes.is_empty() {
        std::fs::write("zns_mint_attestation.bin", attestation_bytes)
            .expect("FATAL: failed to write attestation to disk");
        tracing::info!("boot: attestation report written to zns_mint_attestation.bin");
    }

    (client, wallet, treasury_keys, registry_keys, tip)
}

fn verify_fingerprint(seed: &Secret<[u8; 32]>) {
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");

    assert_eq!(
        actual.to_string(),
        EXPECTED_SEED_FINGERPRINT,
        "SEED FINGERPRINT MISMATCH: wrong seed injected into TEE. expected={}, actual={}",
        EXPECTED_SEED_FINGERPRINT,
        actual
    );
    tracing::info!("boot: seed fingerprint verified = {}", actual);
}

enum KeySource {
    SealedBlob { blob: Vec<u8> },
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
    tracing::info!("boot: deserializing capsule");
    let capsule: SeedCapsule =
        postcard::from_bytes(blob).expect("FATAL: failed to parse zns_seed.capsule");

    assert_eq!(&capsule.magic, b"ZNS_SEED", "FATAL: capsule magic mismatch");

    tracing::info!("boot: deriving instance-bound SEV-SNP sealing key");
    let mut raw_key = derive_sealing_key();

    let cipher =
        XChaCha20Poly1305::new_from_slice(&raw_key).expect("sealing key is exactly 32 bytes");
    raw_key.zeroize();

    let mut aad = Vec::with_capacity(8 + 32);
    aad.extend_from_slice(&capsule.magic);
    aad.extend_from_slice(&capsule.fingerprint);

    let nonce = <&XNonce>::try_from(capsule.nonce.as_slice())
        .expect("FATAL: capsule nonce is not 24 bytes");

    tracing::info!("boot: decrypting seed");
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &capsule.ciphertext,
                aad: &aad,
            },
        )
        .expect("FATAL: failed to decrypt seed. Capsule tampering or wrong SEV-SNP instance.");

    assert_eq!(
        plaintext.len(),
        32,
        "FATAL: decrypted seed is not exactly 32 bytes"
    );

    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&plaintext);
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
