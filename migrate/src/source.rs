//! M1. One pass, then exit.
//!
//! ```text
//! verify manifest structure (already done by the loader)
//! verify M2 attestation
//! verify target measurement
//! unseal
//! encrypt
//! attest the transfer
//! publish the transfer only if our measurement is from_measurement
//! zeroize seed
//! wait for receipt
//! exit
//! ```
//!
//! There is no second offer. A failed check of the target returns before the
//! capsule is unsealed. The transfer is published only with an attestation
//! that binds this offer and this ciphertext, and only when that report's
//! measurement is the manifest's `from_measurement`.

use rand::rngs::OsRng;
use tracing::info;
use zns_canon::capsule;
use zns_canon::migration::{self, MigrationOffer};
use zns_canon::sealing::Tee;
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::attest::{self, require_measurement};
use crate::cli::Args;
use crate::error::MigrateError;
use crate::handoff::{self, MigrationReceipt};
use crate::transport::{self, DirTransport};

pub fn run(
    tee: &impl Tee,
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
    let measurement = attest::measurement(&report, &expected)?;
    authorize(manifest, &offer, &measurement)?;
    info!(
        measurement = hex::encode(measurement),
        "target measurement authorized"
    );

    let capsule_bytes = capsule::read_capsule_file(input)?;
    let capsule = capsule::parse_capsule(&capsule_bytes)?;
    let transfer = {
        let seed = capsule::unseal_seed(tee, &capsule)?;
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
    let source_report = tee.get_attestation(&transfer_report)?;
    if source_report.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    let source_measurement = attest::measurement(source_report.as_bytes(), &transfer_report)?;
    require_measurement(
        &source_measurement,
        &manifest.from_measurement,
        MigrateError::SourceMeasurement,
    )?;
    transport.publish_encrypted_seed(&handoff::encode_transfer(&transfer))?;
    transport.publish_source_attestation(source_report.as_bytes())?;
    info!("seed wrapped; plaintext dropped");

    let receipt = wait_receipt(transport)?;
    handoff::verify_receipt(&receipt, manifest, &capsule_bytes, &capsule.fingerprint)?;
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
) -> Result<(), MigrateError> {
    require_measurement(
        measurement,
        &manifest.to_measurement,
        MigrateError::Measurement,
    )?;
    if offer.manifest_hash != upgrade::manifest_hash(manifest) {
        return Err(MigrateError::ManifestHash);
    }
    Ok(())
}

fn wait_receipt(transport: &DirTransport) -> Result<MigrationReceipt, MigrateError> {
    match transport.wait_receipt() {
        Ok(bytes) => Ok(handoff::decode_receipt(&bytes)?),
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
        authorize(&manifest, &offer, &manifest.to_measurement).unwrap();

        assert!(matches!(
            authorize(&manifest, &offer, &[0u8; 48]),
            Err(MigrateError::ZeroMeasurement)
        ));
        assert!(matches!(
            authorize(&manifest, &offer, &[0x99; 48]),
            Err(MigrateError::Measurement)
        ));
        let mut other = offer;
        other.manifest_hash[0] ^= 1;
        assert!(matches!(
            authorize(&manifest, &other, &manifest.to_measurement),
            Err(MigrateError::ManifestHash)
        ));
    }
}
