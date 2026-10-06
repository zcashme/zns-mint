//! Protocol binding for handing a seed from one measured guest to the next.
//!
//! M2 builds a [`MigrationOffer`] and asks the TEE for an attestation whose
//! `report_data` is [`migration_report_data`]. M1 checks that report, the
//! upgrade manifest, and only then encrypts the unsealed seed to M2's
//! ephemeral key. The X25519 handoff itself is not implemented.

use blake2b_simd::Params as Blake2bParams;
use thiserror::Error;

use crate::attestation::REPORT_DATA_LEN;

/// Domain separation for [`migration_report_data`].
pub const MIGRATION_DOMAIN: &[u8] = b"ZNS_MIGRATION_V1";

/// What M2 commits to before M1 will release the seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationOffer {
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    pub manifest_hash: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MigrationError {
    #[error("no impl: {0}")]
    NoImpl(&'static str),
}

/// `BLAKE2b-512(b"ZNS_MIGRATION_V1" || ephemeral_pubkey || nonce || manifest_hash)`.
///
/// Pass the result to [`crate::sealing::get_attestation`].
pub fn migration_report_data(offer: &MigrationOffer) -> [u8; REPORT_DATA_LEN] {
    let mut input = Vec::with_capacity(MIGRATION_DOMAIN.len() + 32 + 32 + 32);
    input.extend_from_slice(MIGRATION_DOMAIN);
    input.extend_from_slice(&offer.ephemeral_pubkey);
    input.extend_from_slice(&offer.nonce);
    input.extend_from_slice(&offer.manifest_hash);
    let digest = Blake2bParams::new()
        .hash_length(REPORT_DATA_LEN)
        .to_state()
        .update(&input)
        .finalize();
    let mut out = [0u8; REPORT_DATA_LEN];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// Generate the M2 X25519 ephemeral keypair for one migration attempt.
pub fn generate_ephemeral_keypair() -> Result<([u8; 32], [u8; 32]), MigrationError> {
    Err(MigrationError::NoImpl(
        "X25519 ephemeral key generation is not implemented",
    ))
}

/// Encrypt the 32-byte seed to M2's ephemeral public key.
pub fn encrypt_seed(
    _ephemeral_pubkey: &[u8; 32],
    _seed: &[u8; 32],
) -> Result<Vec<u8>, MigrationError> {
    Err(MigrationError::NoImpl(
        "seed encryption to the M2 ephemeral key is not implemented",
    ))
}

/// Decrypt a seed ciphertext with M2's ephemeral secret key.
pub fn decrypt_seed(
    _ephemeral_secret: &[u8; 32],
    _ciphertext: &[u8],
) -> Result<[u8; 32], MigrationError> {
    Err(MigrationError::NoImpl("seed decryption is not implemented"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MigrationOffer {
        MigrationOffer {
            ephemeral_pubkey: [0x44; 32],
            nonce: [0x55; 32],
            manifest_hash: [0x66; 32],
        }
    }

    #[test]
    fn report_data_binds_each_offer_field() {
        let offer = sample();
        let bound = migration_report_data(&offer);

        let mut other_key = offer;
        other_key.ephemeral_pubkey[0] ^= 0x01;
        let mut other_nonce = offer;
        other_nonce.nonce[0] ^= 0x01;
        let mut other_manifest = offer;
        other_manifest.manifest_hash[0] ^= 0x01;

        assert_ne!(migration_report_data(&other_key), bound);
        assert_ne!(migration_report_data(&other_nonce), bound);
        assert_ne!(migration_report_data(&other_manifest), bound);
    }

    #[test]
    fn the_seed_handoff_is_not_implemented() {
        assert!(matches!(
            generate_ephemeral_keypair(),
            Err(MigrationError::NoImpl(_))
        ));
        assert!(matches!(
            encrypt_seed(&[0; 32], &[0; 32]),
            Err(MigrationError::NoImpl(_))
        ));
        assert!(matches!(
            decrypt_seed(&[0; 32], &[]),
            Err(MigrationError::NoImpl(_))
        ));
    }
}
