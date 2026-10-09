//! M1. One pass, then exit.
//!
//! ```text
//! verify manifest structure (already done by the loader)
//! verify M2 attestation
//! verify target measurement and guest policy
//! verify our measurement and guest policy are the source's
//! verify the capsule file and fingerprint are the named seed
//! unseal
//! encrypt
//! attest the transfer
//! publish the transfer only if that report matches the source measurement and policy
//! zeroize seed
//! wait for the receipt and the target's attestation of it
//! exit only when that report matches the target measurement and policy
//! ```
//!
//! There is no second offer. A failed check of the target returns before the
//! capsule is unsealed. The source checks its own measurement and guest
//! policy, then the capsule file hash and header fingerprint, before that
//! unseal. The transfer is published only with an attestation that binds this
//! offer and this ciphertext, and only when that report's measurement is
//! `from_measurement` and its guest policy is `from_guest_policy`. The receipt
//! is accepted only when a target report binds this offer and this receipt,
//! and that report's measurement is `to_measurement` and its guest policy is
//! `to_guest_policy`.

use rand::rngs::OsRng;
use tracing::info;
use zns_canon::capsule;
use zns_canon::migration::{self, MigrationOffer};
use zns_canon::sealing::{get_attestation, SealingKey};
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::attest::{self, require_measurement, require_policy};
use crate::cli::Args;
use crate::error::MigrateError;
use crate::handoff;
use crate::transport::{self, DirTransport};

pub fn run(
    sealing_key: &SealingKey,
    args: &Args,
    manifest: &UpgradeManifest,
    transport: &DirTransport,
) -> Result<(), MigrateError> {
    let input = args
        .input_capsule
        .as_deref()
        .ok_or_else(|| MigrateError::usage("--input-capsule is required"))?;
    transport::require_regular_file(input)?;
    transport::capsule_outside_transport(input, transport.dir())?;

    info!(
        manifest = hex::encode(upgrade::manifest_hash(manifest)),
        "source watching"
    );
    transport.source_begin()?;

    let offer = handoff::decode_offer(&transport.wait_offer()?)?;
    let report = transport.wait_attestation()?;
    let expected = migration::migration_report_data(&offer);
    let target = attest::verified_report(&report, &expected)?;
    authorize(manifest, &offer, &target.measurement, target.guest_policy)?;
    info!(
        measurement = hex::encode(target.measurement),
        "target measurement authorized"
    );

    let source_identity = handoff::source_report_data(&offer);
    let source_identity_report = get_attestation(&source_identity)?;
    if source_identity_report.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    let own = attest::verified_report(source_identity_report.as_bytes(), &source_identity)?;
    require_measurement(
        &own.measurement,
        &manifest.from_measurement,
        MigrateError::SourceMeasurement,
    )?;
    require_policy(
        own.guest_policy,
        manifest.from_guest_policy,
        MigrateError::SourceGuestPolicy,
    )?;

    let capsule_bytes = capsule::read_capsule_file(input)?;
    let capsule = capsule::parse_capsule(&capsule_bytes)?;
    require_source_capsule(manifest, &capsule_bytes, &capsule.fingerprint)?;
    let transfer = {
        let seed = capsule::unseal_seed(sealing_key, &capsule)?;
        let transfer = handoff::encrypt_seed_for_target(
            &seed,
            offer.ephemeral_pubkey,
            offer.nonce,
            offer.manifest_hash,
            &mut OsRng,
        )?;
        drop(seed);
        transfer
    };
    let transfer_report = handoff::transfer_report_data(&offer, &transfer);
    let source_report = get_attestation(&transfer_report)?;
    if source_report.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    let source = attest::verified_report(source_report.as_bytes(), &transfer_report)?;
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
    transport.publish_encrypted_seed(&handoff::encode_transfer(&transfer))?;
    transport.publish_source_attestation(source_report.as_bytes())?;
    info!("seed wrapped; plaintext dropped");

    let receipt = wait_peer(transport.wait_receipt())?;
    let receipt = handoff::decode_receipt(&receipt)?;
    handoff::verify_receipt(&receipt, manifest, &capsule_bytes, &capsule.fingerprint)?;
    let receipt_report = wait_peer(transport.wait_receipt_attestation())?;
    let expected = handoff::receipt_report_data(&offer, &receipt);
    let receipt_report = attest::verified_report(&receipt_report, &expected)?;
    require_measurement(
        &receipt_report.measurement,
        &manifest.to_measurement,
        MigrateError::Measurement,
    )?;
    require_policy(
        receipt_report.guest_policy,
        manifest.to_guest_policy,
        MigrateError::GuestPolicy,
    )?;
    info!(
        capsule = hex::encode(receipt.new_capsule_hash),
        fingerprint = hex::encode(receipt.seed_fingerprint),
        "receipt accepted"
    );
    Ok(())
}

pub(crate) fn authorize(
    manifest: &UpgradeManifest,
    offer: &MigrationOffer,
    measurement: &[u8; 48],
    guest_policy: u64,
) -> Result<(), MigrateError> {
    require_measurement(
        measurement,
        &manifest.to_measurement,
        MigrateError::Measurement,
    )?;
    require_policy(
        guest_policy,
        manifest.to_guest_policy,
        MigrateError::GuestPolicy,
    )?;
    if offer.manifest_hash != upgrade::manifest_hash(manifest) {
        return Err(MigrateError::ManifestHash);
    }
    Ok(())
}

pub(crate) fn require_source_capsule(
    manifest: &UpgradeManifest,
    capsule_bytes: &[u8],
    fingerprint: &[u8; 32],
) -> Result<(), MigrateError> {
    if fingerprint != &manifest.seed_fingerprint {
        return Err(MigrateError::SeedFingerprint);
    }
    if handoff::hash_capsule(capsule_bytes) != manifest.source_capsule_hash {
        return Err(MigrateError::SourceCapsule);
    }
    Ok(())
}

fn wait_peer(result: Result<Vec<u8>, MigrateError>) -> Result<Vec<u8>, MigrateError> {
    match result {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.to_string().contains("timed out") => Err(MigrateError::transport(
            format!("{error}; encrypted seed was already written, not retrying"),
        )),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zns_canon::upgrade::UpgradeManifest;

    fn manifest(to: [u8; 48]) -> UpgradeManifest {
        UpgradeManifest {
            version: 1,
            sequence: 1,
            from_measurement: [0x11; 48],
            to_measurement: to,
            from_guest_policy: 0x30000,
            to_guest_policy: 0x30000,
            seed_fingerprint: [0x44; 32],
            source_capsule_hash: [0x55; 32],
            artifact_hash: [0x33; 32],
            release: "guest-2".into(),
        }
    }

    fn offer_for(manifest: &UpgradeManifest) -> MigrationOffer {
        MigrationOffer {
            ephemeral_pubkey: [0x44; 32],
            nonce: [0x55; 32],
            manifest_hash: upgrade::manifest_hash(manifest),
        }
    }

    #[test]
    fn measurement_and_manifest_hash_are_both_required() {
        let manifest = manifest([0x22; 48]);
        let offer = offer_for(&manifest);
        authorize(
            &manifest,
            &offer,
            &manifest.to_measurement,
            manifest.to_guest_policy,
        )
        .unwrap();

        assert!(matches!(
            authorize(&manifest, &offer, &[0u8; 48], manifest.to_guest_policy),
            Err(MigrateError::ZeroMeasurement)
        ));
        assert!(matches!(
            authorize(&manifest, &offer, &[0x99; 48], manifest.to_guest_policy),
            Err(MigrateError::Measurement)
        ));
        assert!(matches!(
            authorize(&manifest, &offer, &manifest.to_measurement, 0x70000),
            Err(MigrateError::GuestPolicy)
        ));
        let mut other = offer;
        other.manifest_hash[0] ^= 1;
        assert!(matches!(
            authorize(
                &manifest,
                &other,
                &manifest.to_measurement,
                manifest.to_guest_policy
            ),
            Err(MigrateError::ManifestHash)
        ));
    }

    #[test]
    fn the_named_capsule_is_required_before_unseal() {
        let mut manifest = manifest([0x22; 48]);
        let bytes = b"capsule-bytes";
        manifest.source_capsule_hash = handoff::hash_capsule(bytes);
        require_source_capsule(&manifest, bytes, &manifest.seed_fingerprint).unwrap();

        let mut wrong_fingerprint = manifest.seed_fingerprint;
        wrong_fingerprint[0] ^= 1;
        assert!(matches!(
            require_source_capsule(&manifest, bytes, &wrong_fingerprint),
            Err(MigrateError::SeedFingerprint)
        ));
        assert!(matches!(
            require_source_capsule(&manifest, b"other", &manifest.seed_fingerprint),
            Err(MigrateError::SourceCapsule)
        ));
    }
}
