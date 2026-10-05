//! M2. The attested ephemeral key is published before any seed arrives.
//!
//! After the capsule is linked into place, it is read back and unsealed. The
//! receipt is written only when that reopened seed matches the one just
//! decrypted. An existing capsule is left untouched unless the operator set
//! `--replace-after-verified-migration`.

use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::Secret;
use tracing::info;
use zns_canon::capsule::{self, SEED_LEN};
use zns_canon::migration::{self, MigrationOffer};
use zns_canon::sealing::Tee;
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::cli::Args;
use crate::error::MigrateError;
use crate::handoff::{self, MigrationReceipt};
use crate::persist;
use crate::transport::{self, DirTransport};

pub fn run(
    tee: &impl Tee,
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
    let attestation = tee.get_attestation(&report_data)?;
    if attestation.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    transport.publish_offer(&handoff::encode_offer(&offer))?;
    transport.publish_attestation(attestation.as_bytes())?;
    info!("offer attested");

    let transfer = handoff::decode_transfer(&transport.wait_encrypted_seed()?)?;
    let seed = {
        let seed = handoff::decrypt_transfer(&keypair.secret, &offer, &transfer)?;
        drop(keypair);
        seed
    };

    let capsule = capsule::seal_seed(tee, &seed, &mut rng)?;
    let bytes = capsule::serialize_capsule(&capsule)?;
    let staged = persist::stage(output, &bytes)?;
    prove_persisted(tee, &seed, &capsule::read_capsule_file(staged.path())?)?;
    staged.install(output, args.replace_after_verified_migration)?;

    let persisted = capsule::read_capsule_file(output)?;
    let parsed = prove_persisted(tee, &seed, &persisted)?;
    drop(seed);
    info!(path = %output.display(), "capsule reopened");

    let receipt = MigrationReceipt {
        manifest_hash,
        new_capsule_hash: handoff::hash_capsule(&persisted),
        seed_fingerprint: parsed.fingerprint,
    };
    transport.publish_receipt(&handoff::encode_receipt(&receipt))?;
    info!(
        capsule = hex::encode(receipt.new_capsule_hash),
        fingerprint = hex::encode(receipt.seed_fingerprint),
        "receipt published"
    );
    Ok(())
}

fn prove_persisted(
    tee: &impl Tee,
    seed: &Secret<[u8; SEED_LEN]>,
    bytes: &[u8],
) -> Result<zns_canon::capsule::Capsule, MigrateError> {
    let parsed = capsule::parse_capsule(bytes)?;
    let opened = capsule::unseal_seed(tee, &parsed)?;
    handoff::ensure_same_seed(seed, &opened)?;
    Ok(parsed)
}
