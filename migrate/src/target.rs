//! M2. The attested ephemeral key is published before any seed arrives.
//!
//! A transfer is decrypted only after its source attestation matches this
//! offer and this ciphertext, and that report's measurement is
//! `from_measurement` and its guest policy is `from_guest_policy`. After the
//! capsule is linked into place, it is read back and unsealed. The receipt is
//! written only when that reopened seed matches the one just decrypted. The
//! receipt is published with an attestation that binds this offer and this
//! receipt, and only when that report's measurement is `to_measurement` and
//! its guest policy is `to_guest_policy`. An existing capsule is left
//! untouched unless the operator set `--replace-after-verified-migration`.

use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::Secret;
use tracing::info;
use zns_canon::capsule::{self, SEED_LEN};
use zns_canon::migration::{self, MigrationOffer};
use zns_canon::sealing::{get_attestation, SealingKey};
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::attest::{self, require_measurement, require_policy};
use crate::cli::Args;
use crate::error::MigrateError;
use crate::handoff::{self, MigrationReceipt};
use crate::persist;
use crate::transport::{self, DirTransport};

pub fn run(
    sealing_key: &SealingKey,
    args: &Args,
    manifest: &UpgradeManifest,
    transport: &DirTransport,
) -> Result<(), MigrateError> {
    let output = args
        .output_capsule
        .as_deref()
        .ok_or_else(|| MigrateError::usage("--output-capsule is required"))?;
    transport::capsule_outside_transport(output, transport.dir())?;
    persist::guard_output(output, args.replace_after_verified_migration)?;

    info!(
        manifest = hex::encode(upgrade::manifest_hash(manifest)),
        "target waiting"
    );
    transport.target_begin()?;
    persist::guard_output(output, args.replace_after_verified_migration)?;

    let mut rng = OsRng;
    let keypair = handoff::generate_ephemeral_keypair(&mut rng);
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let manifest_hash = upgrade::manifest_hash(manifest);
    let offer = MigrationOffer {
        ephemeral_pubkey: keypair.public,
        nonce,
        manifest_hash,
    };
    let report_data = migration::migration_report_data(&offer);
    let attestation = get_attestation(&report_data)?;
    if attestation.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    let offer_report = attest::verified_report(attestation.as_bytes(), &report_data)?;
    require_measurement(
        &offer_report.measurement,
        &manifest.to_measurement,
        MigrateError::Measurement,
    )?;
    require_policy(
        offer_report.guest_policy,
        manifest.to_guest_policy,
        MigrateError::GuestPolicy,
    )?;
    transport.publish_offer(&handoff::encode_offer(&offer))?;
    transport.publish_attestation(attestation.as_bytes())?;
    info!("offer attested");

    let transfer_bytes = transport.wait_encrypted_seed()?;
    let source_report = transport.wait_source_attestation()?;
    let transfer = handoff::decode_transfer(&transfer_bytes)?;
    let expected = handoff::transfer_report_data(&offer, &transfer);
    let source = attest::verified_report(&source_report, &expected)?;
    require_measurement(
        &source.measurement,
        &manifest.from_measurement,
        MigrateError::SourceMeasurement,
    )?;
    require_policy(
        source.guest_policy,
        manifest.from_guest_policy,
        MigrateError::SourceGuestPolicy,
    )?;
    let seed = {
        let seed = handoff::decrypt_transfer(&keypair.secret, &offer, &transfer)?;
        drop(keypair);
        seed
    };

    let capsule = capsule::seal_seed(sealing_key, &seed, &mut rng)?;
    let bytes = capsule::serialize_capsule(&capsule)?;
    let staged = persist::stage(output, &bytes)?;
    prove_persisted(
        sealing_key,
        &seed,
        &capsule::read_capsule_file(staged.path())?,
    )?;
    staged.install(output, args.replace_after_verified_migration)?;

    let persisted = capsule::read_capsule_file(output)?;
    let parsed = prove_persisted(sealing_key, &seed, &persisted)?;
    drop(seed);
    info!(path = %output.display(), "capsule reopened");

    let receipt = MigrationReceipt {
        manifest_hash,
        new_capsule_hash: handoff::hash_capsule(&persisted),
        seed_fingerprint: parsed.fingerprint,
    };
    let receipt_report = handoff::receipt_report_data(&offer, &receipt);
    let receipt_attestation = get_attestation(&receipt_report)?;
    if receipt_attestation.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    let receipt_launch = attest::verified_report(receipt_attestation.as_bytes(), &receipt_report)?;
    require_measurement(
        &receipt_launch.measurement,
        &manifest.to_measurement,
        MigrateError::Measurement,
    )?;
    require_policy(
        receipt_launch.guest_policy,
        manifest.to_guest_policy,
        MigrateError::GuestPolicy,
    )?;
    transport.publish_receipt(&handoff::encode_receipt(&receipt))?;
    transport.publish_receipt_attestation(receipt_attestation.as_bytes())?;
    info!(
        capsule = hex::encode(receipt.new_capsule_hash),
        fingerprint = hex::encode(receipt.seed_fingerprint),
        "receipt published"
    );
    Ok(())
}

fn prove_persisted(
    sealing_key: &SealingKey,
    seed: &Secret<[u8; SEED_LEN]>,
    bytes: &[u8],
) -> Result<zns_canon::capsule::Capsule, MigrateError> {
    let parsed = capsule::parse_capsule(bytes)?;
    let opened = capsule::unseal_seed(sealing_key, &parsed)?;
    handoff::ensure_same_seed(seed, &opened)?;
    Ok(parsed)
}
