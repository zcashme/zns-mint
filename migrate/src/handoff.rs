//! Seed wrap for one migration attempt.
//!
//! `zns-canon` binds the offer into SNP `report_data`, but
//! `generate_ephemeral_keypair`, `encrypt_seed`, and `decrypt_seed` still
//! return [`zns_canon::migration::MigrationError::NoImpl`]. Those signatures
//! also omit the offer nonce and manifest hash. This module is the prototype
//! wrap until that crate takes it over: X25519, then an AEAD key that is
//! unique to this offer.
//!
//! ```text
//! shared = X25519(sender_secret, target_public)
//! key = BLAKE2b-256(
//!     "ZNS_MIGRATION_WRAP_V1" || shared || sender_public || target_public
//!         || offer_nonce || manifest_hash)
//! ciphertext = XChaCha20Poly1305(key, seed; aad = the same transcript
//!     without the shared secret)
//! ```
//!
//! A shared secret of all zeros is rejected. That is the contributory check
//! from RFC 7748, so a low-order target key does not wrap the seed.

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;
use zns_canon::capsule::SEED_LEN;
use zns_canon::migration::MigrationOffer;
use zns_canon::upgrade::{self, UpgradeManifest};

/// Domain separation for the wrap key and its AEAD associated data.
pub const WRAP_DOMAIN: &[u8] = b"ZNS_MIGRATION_WRAP_V1";

const AEAD_NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN;

/// `ephemeral_pubkey || nonce || manifest_hash`.
pub const OFFER_LEN: usize = 32 + 32 + 32;

/// `sender_ephemeral_pubkey || aead_nonce || ciphertext`.
pub const TRANSFER_LEN: usize = 32 + AEAD_NONCE_LEN + CIPHERTEXT_LEN;

/// `manifest_hash || new_capsule_hash || seed_fingerprint`.
pub const RECEIPT_LEN: usize = 32 + 32 + 32;

/// One-time X25519 key. `secret` is wiped when this value is dropped.
pub struct EphemeralKeypair {
    pub secret: Secret<[u8; 32]>,
    pub public: [u8; 32],
}

/// Ciphertext M1 writes for the attested M2 key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedSeedTransfer {
    pub sender_ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub ciphertext: [u8; CIPHERTEXT_LEN],
}

/// What M2 sends after it has resealed the seed and reopened that capsule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationReceipt {
    pub manifest_hash: [u8; 32],
    pub new_capsule_hash: [u8; 32],
    pub seed_fingerprint: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandoffError {
    #[error("ephemeral public key is all zeros")]
    ZeroPublicKey,

    #[error("X25519 shared secret was not contributory")]
    NonContributory,

    #[error("ephemeral secret does not match the migration offer")]
    SecretOfferMismatch,

    #[error("seed encryption failed")]
    Seal,

    #[error("seed decryption failed")]
    Decrypt,

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

pub fn generate_ephemeral_keypair<R>(rng: &mut R) -> EphemeralKeypair
where
    R: RngCore + CryptoRng,
{
    let secret = StaticSecret::random_from_rng(&mut *rng);
    let public = PublicKey::from(&secret).to_bytes();
    let mut raw = secret.to_bytes();
    let stored = Secret::new(raw);
    raw.zeroize();
    drop(secret);
    EphemeralKeypair {
        secret: stored,
        public,
    }
}

pub fn encrypt_seed_for_target<R>(
    seed: &Secret<[u8; SEED_LEN]>,
    ephemeral_pubkey: [u8; 32],
    offer_nonce: [u8; 32],
    manifest_hash: [u8; 32],
    rng: &mut R,
) -> Result<EncryptedSeedTransfer, HandoffError>
where
    R: RngCore + CryptoRng,
{
    if ephemeral_pubkey == [0u8; 32] {
        return Err(HandoffError::ZeroPublicKey);
    }
    let sender = StaticSecret::random_from_rng(&mut *rng);
    let sender_public = PublicKey::from(&sender).to_bytes();
    if sender_public == [0u8; 32] {
        return Err(HandoffError::ZeroPublicKey);
    }
    let target_public = PublicKey::from(ephemeral_pubkey);
    let shared = sender.diffie_hellman(&target_public);
    let mut shared_bytes = *shared.as_bytes();
    drop(shared);
    drop(sender);
    if shared_bytes == [0u8; 32] {
        shared_bytes.zeroize();
        return Err(HandoffError::NonContributory);
    }

    let mut aead_nonce = [0u8; AEAD_NONCE_LEN];
    rng.fill_bytes(&mut aead_nonce);
    let aad = wrap_aad(
        &sender_public,
        &ephemeral_pubkey,
        &offer_nonce,
        &manifest_hash,
    );
    let ciphertext = {
        let mut key = wrap_key(
            &shared_bytes,
            &sender_public,
            &ephemeral_pubkey,
            &offer_nonce,
            &manifest_hash,
        );
        shared_bytes.zeroize();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("wrap key is 32 bytes");
        let result = cipher.encrypt(
            XNonce::from_slice(&aead_nonce),
            Payload {
                msg: seed.expose_secret(),
                aad: &aad,
            },
        );
        key.zeroize();
        result.map_err(|_| HandoffError::Seal)?
    };
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(HandoffError::Seal);
    }
    let mut out = [0u8; CIPHERTEXT_LEN];
    out.copy_from_slice(&ciphertext);
    Ok(EncryptedSeedTransfer {
        sender_ephemeral_pubkey: sender_public,
        nonce: aead_nonce,
        ciphertext: out,
    })
}

pub fn decrypt_transfer(
    ephemeral_secret: &Secret<[u8; 32]>,
    offer: &MigrationOffer,
    transfer: &EncryptedSeedTransfer,
) -> Result<Secret<[u8; SEED_LEN]>, HandoffError> {
    if offer.ephemeral_pubkey == [0u8; 32] || transfer.sender_ephemeral_pubkey == [0u8; 32] {
        return Err(HandoffError::ZeroPublicKey);
    }
    let secret = StaticSecret::from(*ephemeral_secret.expose_secret());
    let derived_public = PublicKey::from(&secret).to_bytes();
    if !ct_eq(&derived_public, &offer.ephemeral_pubkey) {
        return Err(HandoffError::SecretOfferMismatch);
    }
    let sender_public = PublicKey::from(transfer.sender_ephemeral_pubkey);
    let shared = secret.diffie_hellman(&sender_public);
    let mut shared_bytes = *shared.as_bytes();
    drop(shared);
    drop(secret);
    if shared_bytes == [0u8; 32] {
        shared_bytes.zeroize();
        return Err(HandoffError::NonContributory);
    }

    let aad = wrap_aad(
        &transfer.sender_ephemeral_pubkey,
        &offer.ephemeral_pubkey,
        &offer.nonce,
        &offer.manifest_hash,
    );
    let mut plaintext = {
        let mut key = wrap_key(
            &shared_bytes,
            &transfer.sender_ephemeral_pubkey,
            &offer.ephemeral_pubkey,
            &offer.nonce,
            &offer.manifest_hash,
        );
        shared_bytes.zeroize();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("wrap key is 32 bytes");
        let result = cipher.decrypt(
            XNonce::from_slice(&transfer.nonce),
            Payload {
                msg: &transfer.ciphertext,
                aad: &aad,
            },
        );
        key.zeroize();
        result.map_err(|_| HandoffError::Decrypt)?
    };
    if plaintext.len() != SEED_LEN {
        plaintext.zeroize();
        return Err(HandoffError::Decrypt);
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&plaintext);
    plaintext.zeroize();
    let secret = Secret::new(seed);
    seed.zeroize();
    Ok(secret)
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
    out[32..32 + AEAD_NONCE_LEN].copy_from_slice(&transfer.nonce);
    out[32 + AEAD_NONCE_LEN..].copy_from_slice(&transfer.ciphertext);
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
        nonce: [0u8; AEAD_NONCE_LEN],
        ciphertext: [0u8; CIPHERTEXT_LEN],
    };
    transfer
        .sender_ephemeral_pubkey
        .copy_from_slice(&bytes[..32]);
    transfer
        .nonce
        .copy_from_slice(&bytes[32..32 + AEAD_NONCE_LEN]);
    transfer
        .ciphertext
        .copy_from_slice(&bytes[32 + AEAD_NONCE_LEN..]);
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

fn wrap_key(
    shared: &[u8; 32],
    sender_public: &[u8; 32],
    target_public: &[u8; 32],
    offer_nonce: &[u8; 32],
    manifest_hash: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(WRAP_DOMAIN.len() + 32 * 5);
    input.extend_from_slice(WRAP_DOMAIN);
    input.extend_from_slice(shared);
    input.extend_from_slice(sender_public);
    input.extend_from_slice(target_public);
    input.extend_from_slice(offer_nonce);
    input.extend_from_slice(manifest_hash);
    let key = blake2b_256(&input);
    input.zeroize();
    key
}

fn wrap_aad(
    sender_public: &[u8; 32],
    target_public: &[u8; 32],
    offer_nonce: &[u8; 32],
    manifest_hash: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_DOMAIN.len() + 32 * 4);
    aad.extend_from_slice(WRAP_DOMAIN);
    aad.extend_from_slice(sender_public);
    aad.extend_from_slice(target_public);
    aad.extend_from_slice(offer_nonce);
    aad.extend_from_slice(manifest_hash);
    aad
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
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use zns_canon::upgrade::UpgradeManifest;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(11)
    }

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
            artifact_hash: [0x33; 32],
            release: "guest-2".to_string(),
        }
    }

    #[test]
    fn wrap_roundtrip_and_offer_binding() {
        let mut rng = rng();
        let keypair = generate_ephemeral_keypair(&mut rng);
        let offer_nonce = [0x44; 32];
        let manifest_hash = upgrade::manifest_hash(&manifest());
        let transfer = encrypt_seed_for_target(
            &seed(),
            keypair.public,
            offer_nonce,
            manifest_hash,
            &mut rng,
        )
        .unwrap();
        let encoded = encode_transfer(&transfer);
        assert!(
            !encoded
                .windows(SEED_LEN)
                .any(|window| window == seed().expose_secret()),
            "seed bytes must not appear in the transfer"
        );

        let offer = MigrationOffer {
            ephemeral_pubkey: keypair.public,
            nonce: offer_nonce,
            manifest_hash,
        };
        let opened =
            decrypt_transfer(&keypair.secret, &offer, &decode_transfer(&encoded).unwrap()).unwrap();
        assert_eq!(opened.expose_secret(), seed().expose_secret());

        let mut other_nonce = offer;
        other_nonce.nonce[0] ^= 1;
        assert!(matches!(
            decrypt_transfer(&keypair.secret, &other_nonce, &transfer),
            Err(HandoffError::Decrypt)
        ));
        let mut other_manifest = offer;
        other_manifest.manifest_hash[0] ^= 1;
        assert!(matches!(
            decrypt_transfer(&keypair.secret, &other_manifest, &transfer),
            Err(HandoffError::Decrypt)
        ));

        let mut tampered = transfer;
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            decrypt_transfer(&keypair.secret, &offer, &tampered),
            Err(HandoffError::Decrypt)
        ));

        let other = generate_ephemeral_keypair(&mut rng);
        assert!(matches!(
            decrypt_transfer(&other.secret, &offer, &transfer),
            Err(HandoffError::SecretOfferMismatch)
        ));
    }

    #[test]
    fn all_zero_target_key_is_rejected() {
        let mut rng = rng();
        let error = encrypt_seed_for_target(&seed(), [0u8; 32], [1u8; 32], [2u8; 32], &mut rng)
            .unwrap_err();
        assert_eq!(error, HandoffError::ZeroPublicKey);
    }

    #[test]
    fn low_order_target_key_is_not_contributory() {
        let mut rng = rng();
        // u-coordinate 1 is a low-order X25519 point.
        let mut public = [0u8; 32];
        public[0] = 1;
        let error =
            encrypt_seed_for_target(&seed(), public, [1u8; 32], [2u8; 32], &mut rng).unwrap_err();
        assert_eq!(error, HandoffError::NonContributory);
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
