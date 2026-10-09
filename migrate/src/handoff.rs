//! Channel encoding and the reports that bind a migration attempt.
//!
//! The X25519 seed wrap lives in `zns-canon`: `generate_ephemeral_keypair`,
//! `encrypt_seed`, and `decrypt_seed`. This module checks the receipt and
//! builds the source, transfer, and receipt reports.

use blake2b_simd::Params as Blake2bParams;
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;
use zns_canon::attestation::REPORT_DATA_LEN;
use zns_canon::capsule::{CIPHERTEXT_LEN, NONCE_LEN, SEED_LEN};
use zns_canon::migration::{EncryptedSeedTransfer, MigrationOffer};
use zns_canon::upgrade::{self, UpgradeManifest};

pub use zns_canon::migration::TRANSFER_LEN;

/// Domain separation for [`source_report_data`].
///
/// Distinct from the offer, transfer, and receipt domains. The source
/// requests this report before unsealing and does not publish it.
pub const SOURCE_REPORT_DOMAIN: &[u8] = b"ZNS_MIGRATION_SOURCE_V1";

/// Domain separation for [`transfer_report_data`].
///
/// Distinct from `ZNS_MIGRATION_V1`, which binds only the target's offer.
pub const TRANSFER_REPORT_DOMAIN: &[u8] = b"ZNS_MIGRATION_TRANSFER_V1";

/// Domain separation for [`receipt_report_data`].
///
/// Distinct from the offer and transfer domains, so those reports cannot
/// be presented as a receipt.
pub const RECEIPT_REPORT_DOMAIN: &[u8] = b"ZNS_MIGRATION_RECEIPT_V1";

/// `ephemeral_pubkey || nonce || manifest_hash`.
pub const OFFER_LEN: usize = 32 + 32 + 32;

/// `manifest_hash || new_capsule_hash || seed_fingerprint`.
pub const RECEIPT_LEN: usize = 32 + 32 + 32;

/// What M2 sends after it has resealed the seed and reopened that capsule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationReceipt {
    pub manifest_hash: [u8; 32],
    pub new_capsule_hash: [u8; 32],
    pub seed_fingerprint: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandoffError {
    #[error("migration offer is {actual} bytes, expected {expected}")]
    BadOffer { actual: usize, expected: usize },

    #[error("encrypted seed is {actual} bytes, expected {expected}")]
    BadTransfer { actual: usize, expected: usize },

    #[error("migration receipt is {actual} bytes, expected {expected}")]
    BadReceipt { actual: usize, expected: usize },

    #[error("reopened capsule does not hold the migrated seed")]
    SeedMismatch,

    #[error("migration receipt manifest hash does not match")]
    ReceiptManifest,

    #[error("migration receipt seed fingerprint does not match the source capsule")]
    ReceiptFingerprint,

    #[error("migration receipt names the source capsule, not a resealed capsule")]
    ReceiptUnchanged,

    #[error("migration receipt capsule hash is empty")]
    ReceiptEmpty,
}

/// `BLAKE2b-512(b"ZNS_MIGRATION_SOURCE_V1" || offer)`.
///
/// The source passes this to `get_attestation` before unsealing. The
/// report's measurement must equal `from_measurement`. This report is not
/// written to the channel. The published source attestation is
/// [`transfer_report_data`], which also binds the ciphertext.
pub fn source_report_data(offer: &MigrationOffer) -> [u8; REPORT_DATA_LEN] {
    let offer_bytes = encode_offer(offer);
    let mut input = Vec::with_capacity(SOURCE_REPORT_DOMAIN.len() + offer_bytes.len());
    input.extend_from_slice(SOURCE_REPORT_DOMAIN);
    input.extend_from_slice(&offer_bytes);
    blake2b_512(&input)
}

/// `BLAKE2b-512(b"ZNS_MIGRATION_TRANSFER_V1" || offer || transfer)`.
///
/// The source passes this to `get_attestation` after building the
/// ciphertext. The target accepts a transfer only when its report matches
/// these exact bytes, so a writer who encrypts some other seed to the
/// published offer cannot reuse or omit that attestation.
pub fn transfer_report_data(
    offer: &MigrationOffer,
    transfer: &EncryptedSeedTransfer,
) -> [u8; REPORT_DATA_LEN] {
    let offer_bytes = encode_offer(offer);
    let transfer_bytes = encode_transfer(transfer);
    let mut input =
        Vec::with_capacity(TRANSFER_REPORT_DOMAIN.len() + offer_bytes.len() + transfer_bytes.len());
    input.extend_from_slice(TRANSFER_REPORT_DOMAIN);
    input.extend_from_slice(&offer_bytes);
    input.extend_from_slice(&transfer_bytes);
    blake2b_512(&input)
}

/// `BLAKE2b-512(b"ZNS_MIGRATION_RECEIPT_V1" || offer || receipt)`.
///
/// The target passes this to `get_attestation` after the resealed
/// capsule is on disk. The source accepts a receipt only when its report
/// matches these exact bytes, so a writer who knows the seed fingerprint
/// cannot finish the attempt with a receipt the target did not produce.
pub fn receipt_report_data(
    offer: &MigrationOffer,
    receipt: &MigrationReceipt,
) -> [u8; REPORT_DATA_LEN] {
    let offer_bytes = encode_offer(offer);
    let receipt_bytes = encode_receipt(receipt);
    let mut input =
        Vec::with_capacity(RECEIPT_REPORT_DOMAIN.len() + offer_bytes.len() + receipt_bytes.len());
    input.extend_from_slice(RECEIPT_REPORT_DOMAIN);
    input.extend_from_slice(&offer_bytes);
    input.extend_from_slice(&receipt_bytes);
    blake2b_512(&input)
}

pub fn ensure_same_seed(
    left: &Secret<[u8; SEED_LEN]>,
    right: &Secret<[u8; SEED_LEN]>,
) -> Result<(), HandoffError> {
    if ct_eq(left.expose_secret(), right.expose_secret()) {
        Ok(())
    } else {
        Err(HandoffError::SeedMismatch)
    }
}

/// BLAKE2b-256 of the on-disk capsule bytes.
///
/// Same construction as `zns-keygen`'s `capsule_hash_blake2b256`: the raw
/// capsule, with no extra domain string.
pub fn hash_capsule(bytes: &[u8]) -> [u8; 32] {
    blake2b_256(bytes)
}

pub fn verify_receipt(
    receipt: &MigrationReceipt,
    manifest: &UpgradeManifest,
    source_capsule_bytes: &[u8],
    source_fingerprint: &[u8; 32],
) -> Result<(), HandoffError> {
    if receipt.manifest_hash != upgrade::manifest_hash(manifest) {
        return Err(HandoffError::ReceiptManifest);
    }
    if !ct_eq(&receipt.seed_fingerprint, source_fingerprint) {
        return Err(HandoffError::ReceiptFingerprint);
    }
    if receipt.new_capsule_hash == [0u8; 32] {
        return Err(HandoffError::ReceiptEmpty);
    }
    if ct_eq(
        &receipt.new_capsule_hash,
        &hash_capsule(source_capsule_bytes),
    ) {
        return Err(HandoffError::ReceiptUnchanged);
    }
    Ok(())
}

pub fn encode_offer(offer: &MigrationOffer) -> [u8; OFFER_LEN] {
    let mut out = [0u8; OFFER_LEN];
    out[..32].copy_from_slice(&offer.ephemeral_pubkey);
    out[32..64].copy_from_slice(&offer.nonce);
    out[64..].copy_from_slice(&offer.manifest_hash);
    out
}

pub fn decode_offer(bytes: &[u8]) -> Result<MigrationOffer, HandoffError> {
    if bytes.len() != OFFER_LEN {
        return Err(HandoffError::BadOffer {
            actual: bytes.len(),
            expected: OFFER_LEN,
        });
    }
    let mut offer = MigrationOffer {
        ephemeral_pubkey: [0u8; 32],
        nonce: [0u8; 32],
        manifest_hash: [0u8; 32],
    };
    offer.ephemeral_pubkey.copy_from_slice(&bytes[..32]);
    offer.nonce.copy_from_slice(&bytes[32..64]);
    offer.manifest_hash.copy_from_slice(&bytes[64..]);
    Ok(offer)
}

pub fn encode_transfer(transfer: &EncryptedSeedTransfer) -> [u8; TRANSFER_LEN] {
    let mut out = [0u8; TRANSFER_LEN];
    out[..32].copy_from_slice(&transfer.sender_ephemeral_pubkey);
    out[32..32 + NONCE_LEN].copy_from_slice(&transfer.nonce);
    out[32 + NONCE_LEN..].copy_from_slice(&transfer.ciphertext);
    out
}

pub fn decode_transfer(bytes: &[u8]) -> Result<EncryptedSeedTransfer, HandoffError> {
    if bytes.len() != TRANSFER_LEN {
        return Err(HandoffError::BadTransfer {
            actual: bytes.len(),
            expected: TRANSFER_LEN,
        });
    }
    let mut transfer = EncryptedSeedTransfer {
        sender_ephemeral_pubkey: [0u8; 32],
        nonce: [0u8; NONCE_LEN],
        ciphertext: [0u8; CIPHERTEXT_LEN],
    };
    transfer
        .sender_ephemeral_pubkey
        .copy_from_slice(&bytes[..32]);
    transfer.nonce.copy_from_slice(&bytes[32..32 + NONCE_LEN]);
    transfer
        .ciphertext
        .copy_from_slice(&bytes[32 + NONCE_LEN..]);
    Ok(transfer)
}

pub fn encode_receipt(receipt: &MigrationReceipt) -> [u8; RECEIPT_LEN] {
    let mut out = [0u8; RECEIPT_LEN];
    out[..32].copy_from_slice(&receipt.manifest_hash);
    out[32..64].copy_from_slice(&receipt.new_capsule_hash);
    out[64..].copy_from_slice(&receipt.seed_fingerprint);
    out
}

pub fn decode_receipt(bytes: &[u8]) -> Result<MigrationReceipt, HandoffError> {
    if bytes.len() != RECEIPT_LEN {
        return Err(HandoffError::BadReceipt {
            actual: bytes.len(),
            expected: RECEIPT_LEN,
        });
    }
    let mut receipt = MigrationReceipt {
        manifest_hash: [0u8; 32],
        new_capsule_hash: [0u8; 32],
        seed_fingerprint: [0u8; 32],
    };
    receipt.manifest_hash.copy_from_slice(&bytes[..32]);
    receipt.new_capsule_hash.copy_from_slice(&bytes[32..64]);
    receipt.seed_fingerprint.copy_from_slice(&bytes[64..]);
    Ok(receipt)
}

fn blake2b_512(input: &[u8]) -> [u8; REPORT_DATA_LEN] {
    let digest = Blake2bParams::new()
        .hash_length(REPORT_DATA_LEN)
        .to_state()
        .update(input)
        .finalize();
    let mut out = [0u8; REPORT_DATA_LEN];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let digest = Blake2bParams::new()
        .hash_length(32)
        .to_state()
        .update(input)
        .finalize();
    digest.as_bytes()[..32]
        .try_into()
        .expect("BLAKE2b-256 length")
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use zns_canon::upgrade::UpgradeManifest;

    fn seed() -> Secret<[u8; SEED_LEN]> {
        let mut bytes = [0u8; SEED_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        Secret::new(bytes)
    }

    fn manifest() -> UpgradeManifest {
        UpgradeManifest {
            version: 1,
            sequence: 3,
            from_measurement: [0x11; 48],
            to_measurement: [0x22; 48],
            from_guest_policy: 0x30000,
            to_guest_policy: 0x30000,
            seed_fingerprint: [0x44; 32],
            source_capsule_hash: [0x55; 32],
            artifact_hash: [0x33; 32],
            release: "v0.1.2".to_string(),
        }
    }

    #[test]
    fn transfer_report_binds_the_offer_and_the_ciphertext() {
        let offer = MigrationOffer {
            ephemeral_pubkey: [1u8; 32],
            nonce: [2u8; 32],
            manifest_hash: [3u8; 32],
        };
        let transfer = EncryptedSeedTransfer {
            sender_ephemeral_pubkey: [4u8; 32],
            nonce: [5u8; NONCE_LEN],
            ciphertext: [6u8; CIPHERTEXT_LEN],
        };
        let bound = transfer_report_data(&offer, &transfer);
        assert_ne!(bound, zns_canon::migration::migration_report_data(&offer));

        let mut other_sender = transfer;
        other_sender.sender_ephemeral_pubkey[0] ^= 1;
        assert_ne!(transfer_report_data(&offer, &other_sender), bound);

        let mut other_ciphertext = transfer;
        other_ciphertext.ciphertext[0] ^= 1;
        assert_ne!(transfer_report_data(&offer, &other_ciphertext), bound);

        let mut other_offer = offer;
        other_offer.nonce[0] ^= 1;
        assert_ne!(transfer_report_data(&other_offer, &transfer), bound);
        assert_ne!(bound, source_report_data(&offer));
    }

    #[test]
    fn source_report_binds_this_offer_and_no_ciphertext() {
        let offer = MigrationOffer {
            ephemeral_pubkey: [1u8; 32],
            nonce: [2u8; 32],
            manifest_hash: [3u8; 32],
        };
        let bound = source_report_data(&offer);
        assert_ne!(bound, zns_canon::migration::migration_report_data(&offer));

        let mut other_offer = offer;
        other_offer.nonce[0] ^= 1;
        assert_ne!(source_report_data(&other_offer), bound);
    }

    #[test]
    fn receipt_report_binds_this_offer_and_this_receipt() {
        let offer = MigrationOffer {
            ephemeral_pubkey: [1u8; 32],
            nonce: [2u8; 32],
            manifest_hash: [3u8; 32],
        };
        let receipt = MigrationReceipt {
            manifest_hash: [3u8; 32],
            new_capsule_hash: [4u8; 32],
            seed_fingerprint: [5u8; 32],
        };
        let bound = receipt_report_data(&offer, &receipt);
        assert_ne!(bound, zns_canon::migration::migration_report_data(&offer));
        assert_ne!(
            bound,
            transfer_report_data(
                &offer,
                &EncryptedSeedTransfer {
                    sender_ephemeral_pubkey: [4u8; 32],
                    nonce: [5u8; NONCE_LEN],
                    ciphertext: [6u8; CIPHERTEXT_LEN],
                }
            )
        );

        let mut other_offer = offer;
        other_offer.nonce[0] ^= 1;
        assert_ne!(receipt_report_data(&other_offer, &receipt), bound);

        let mut other_capsule = receipt;
        other_capsule.new_capsule_hash[0] ^= 1;
        assert_ne!(receipt_report_data(&offer, &other_capsule), bound);
    }

    #[test]
    fn encodings_are_fixed_length() {
        let offer = MigrationOffer {
            ephemeral_pubkey: [1u8; 32],
            nonce: [2u8; 32],
            manifest_hash: [3u8; 32],
        };
        let bytes = encode_offer(&offer);
        assert_eq!(bytes.len(), OFFER_LEN);
        assert_eq!(decode_offer(&bytes).unwrap(), offer);
        assert!(decode_offer(&bytes[..bytes.len() - 1]).is_err());

        let receipt = MigrationReceipt {
            manifest_hash: [4u8; 32],
            new_capsule_hash: [5u8; 32],
            seed_fingerprint: [6u8; 32],
        };
        assert_eq!(decode_receipt(&encode_receipt(&receipt)).unwrap(), receipt);
        assert!(decode_receipt(&[0u8; RECEIPT_LEN + 1]).is_err());

        let transfer = EncryptedSeedTransfer {
            sender_ephemeral_pubkey: [7u8; 32],
            nonce: [8u8; NONCE_LEN],
            ciphertext: [9u8; CIPHERTEXT_LEN],
        };
        assert_eq!(
            decode_transfer(&encode_transfer(&transfer)).unwrap(),
            transfer
        );
        assert!(decode_transfer(&[0u8; TRANSFER_LEN + 1]).is_err());
    }

    #[test]
    fn canonical_wrap_roundtrips_through_the_transfer_encoding() {
        use rand::rngs::OsRng;
        use zns_canon::migration::{self, MigrationError};

        let mut rng = OsRng;
        let keypair = migration::generate_ephemeral_keypair(&mut rng);
        let offer = MigrationOffer {
            ephemeral_pubkey: keypair.public,
            nonce: [0x44; 32],
            manifest_hash: [0x66; 32],
        };
        let transfer = migration::encrypt_seed(&seed(), &offer, &mut rng).unwrap();
        let decoded = decode_transfer(&encode_transfer(&transfer)).unwrap();
        assert_eq!(decoded, transfer);

        let opened = migration::decrypt_seed(&keypair.secret, &offer, &decoded).unwrap();
        assert_eq!(opened.expose_secret(), seed().expose_secret());

        let mut other_nonce = offer;
        other_nonce.nonce[0] ^= 1;
        assert!(matches!(
            migration::decrypt_seed(&keypair.secret, &other_nonce, &decoded),
            Err(MigrationError::Decrypt)
        ));

        let mut other_hash = offer;
        other_hash.manifest_hash[0] ^= 1;
        assert!(matches!(
            migration::decrypt_seed(&keypair.secret, &other_hash, &decoded),
            Err(MigrationError::Decrypt)
        ));

        let mut tampered = encode_transfer(&transfer);
        tampered[32 + NONCE_LEN] ^= 1;
        let tampered = decode_transfer(&tampered).unwrap();
        assert!(matches!(
            migration::decrypt_seed(&keypair.secret, &offer, &tampered),
            Err(MigrationError::Decrypt)
        ));
    }

    #[test]
    fn receipt_must_match_manifest_fingerprint_and_a_new_capsule() {
        let manifest = manifest();
        let source = b"source-capsule-bytes";
        let fingerprint = [0x9u8; 32];
        let good = MigrationReceipt {
            manifest_hash: upgrade::manifest_hash(&manifest),
            new_capsule_hash: [0xabu8; 32],
            seed_fingerprint: fingerprint,
        };
        verify_receipt(&good, &manifest, source, &fingerprint).unwrap();

        let mut wrong_manifest = good;
        wrong_manifest.manifest_hash[0] ^= 1;
        assert_eq!(
            verify_receipt(&wrong_manifest, &manifest, source, &fingerprint),
            Err(HandoffError::ReceiptManifest)
        );

        let mut wrong_fingerprint = good;
        wrong_fingerprint.seed_fingerprint[0] ^= 1;
        assert_eq!(
            verify_receipt(&wrong_fingerprint, &manifest, source, &fingerprint),
            Err(HandoffError::ReceiptFingerprint)
        );

        let mut empty = good;
        empty.new_capsule_hash = [0u8; 32];
        assert_eq!(
            verify_receipt(&empty, &manifest, source, &fingerprint),
            Err(HandoffError::ReceiptEmpty)
        );

        let mut unchanged = good;
        unchanged.new_capsule_hash = hash_capsule(source);
        assert_eq!(
            verify_receipt(&unchanged, &manifest, source, &fingerprint),
            Err(HandoffError::ReceiptUnchanged)
        );
    }

    #[test]
    fn same_seed_check_rejects_a_different_opening() {
        let left = seed();
        let mut other = [0u8; SEED_LEN];
        other[0] = 0xff;
        let right = Secret::new(other);
        assert!(ensure_same_seed(&left, &left).is_ok());
        assert_eq!(
            ensure_same_seed(&left, &right),
            Err(HandoffError::SeedMismatch)
        );
    }
}
