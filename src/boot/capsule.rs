//! Sealed seed capsule: the seed's on-disk form.
//!
//! Format is unchanged from the pre-refactor inlined codec: postcard-serialised
//! `{ magic, fingerprint, nonce, ciphertext }`, magic = `b"ZNS_SEED"`, 24-byte
//! `XChaCha20Poly1305` nonce, AAD = `magic || fingerprint`, plaintext = the
//! 32-byte ZIP-32 seed. The sealing key comes from the [`crate::boot::tee::Tee`]
//! seam so integration tests can substitute [`crate::boot::tee::FakeTee`] without
//! forking the crypto.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;
use zip32::fingerprint::SeedFingerprint;

use crate::boot::tee::{Tee, TeeError};

/// The capsule magic; the first 8 bytes of every ZNS seed capsule.
pub const MAGIC: [u8; 8] = *b"ZNS_SEED";

/// The `XChaCha20Poly1305` nonce length.
pub const NONCE_LEN: usize = 24;

/// The ZIP-32 seed length in bytes.
pub const SEED_LEN: usize = 32;

/// Poly1305 tag appended to the seed.
const TAG_LEN: usize = 16;

/// Ciphertext is the seed plus its tag.
pub const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN;

/// On-disk size: magic, fingerprint, nonce, ciphertext, and the two
/// postcard length bytes. A longer file is not a capsule.
pub const CAPSULE_LEN: usize = MAGIC.len() + 32 + 1 + NONCE_LEN + 1 + CIPHERTEXT_LEN;

/// The context string passed to [`Tee::derive_sealing_key`] for capsule
/// AEAD. A single well-known context today; extra contexts are cheap to add.
pub const CAPSULE_KEY_CONTEXT: &[u8] = b"ZNS_SEED/capsule/v1";

/// Errors from capsule sealing, parsing, and unsealing.
#[derive(Debug, Error)]
pub enum CapsuleError {
    #[error("invalid capsule format")]
    BadCapsule,

    #[error("capsule file unreadable: {0}")]
    Read(#[from] std::io::Error),

    #[error("capsule parse failed: {0}")]
    Parse(String),

    #[error("capsule decryption failed (tampered ciphertext, wrong TEE, or wrong AAD)")]
    Decrypt,

    #[error("capsule sealing failed")]
    Seal,

    #[error("decrypted seed is not exactly {SEED_LEN} bytes")]
    BadSeedSize,

    #[error("capsule fingerprint does not match the seed it holds")]
    FingerprintMismatch,

    #[error("TEE error: {0}")]
    Tee(#[from] TeeError),
}

/// The on-disk sealed seed envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capsule {
    pub magic: [u8; 8],
    pub fingerprint: [u8; 32],
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Reads at most one byte past [`CAPSULE_LEN`]. A different length is
/// refused before the bytes are parsed.
pub fn read_capsule_file(path: impl AsRef<Path>) -> Result<Vec<u8>, CapsuleError> {
    let file = File::open(path)?;
    let mut limited = file.take((CAPSULE_LEN + 1) as u64);
    let mut buf = Vec::with_capacity(CAPSULE_LEN + 1);
    limited.read_to_end(&mut buf)?;
    if buf.len() != CAPSULE_LEN {
        return Err(CapsuleError::BadCapsule);
    }
    Ok(buf)
}

impl Capsule {
    /// Parses postcard bytes, checking the blob and field lengths.
    pub fn parse(blob: &[u8]) -> Result<Self, CapsuleError> {
        if blob.len() != CAPSULE_LEN {
            return Err(CapsuleError::BadCapsule);
        }
        let capsule: Self =
            postcard::from_bytes(blob).map_err(|e| CapsuleError::Parse(e.to_string()))?;
        capsule.validate_lengths()?;
        Ok(capsule)
    }

    /// Checks nonce and ciphertext lengths before decryption.
    fn validate_lengths(&self) -> Result<(), CapsuleError> {
        if self.nonce.len() != NONCE_LEN {
            return Err(CapsuleError::BadCapsule);
        }
        if self.ciphertext.len() != CIPHERTEXT_LEN {
            return Err(CapsuleError::BadCapsule);
        }
        Ok(())
    }

    /// Serialises the capsule to postcard bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, CapsuleError> {
        postcard::to_allocvec(self).map_err(|e| CapsuleError::Parse(e.to_string()))
    }

    /// Seals a seed with the TEE key, authenticating its fingerprint as AAD.
    pub fn seal<T, R>(
        tee: &T,
        seed: &Secret<[u8; SEED_LEN]>,
        rng: &mut R,
    ) -> Result<Self, CapsuleError>
    where
        T: Tee + ?Sized,
        R: RngCore,
    {
        let fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
            .expect("ZIP-32 accepts 32-byte seeds")
            .to_bytes();

        let mut raw_key = tee.derive_sealing_key(CAPSULE_KEY_CONTEXT)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&raw_key).expect("sealing key is exactly 32 bytes");

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);

        let mut aad = Vec::with_capacity(MAGIC.len() + fingerprint.len());
        aad.extend_from_slice(&MAGIC);
        aad.extend_from_slice(&fingerprint);

        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: seed.expose_secret(),
                    aad: &aad,
                },
            )
            .map_err(|_| CapsuleError::Seal);
        raw_key.zeroize();
        let ciphertext = ciphertext?;

        Ok(Self {
            magic: MAGIC,
            fingerprint,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    /// Checks magic, lengths, AEAD, seed length, and fingerprint, in order.
    /// The returned [`Secret`] wipes on drop.
    pub fn unseal<T: Tee + ?Sized>(&self, tee: &T) -> Result<Secret<[u8; SEED_LEN]>, CapsuleError> {
        if self.magic != MAGIC {
            return Err(CapsuleError::BadCapsule);
        }
        self.validate_lengths()?;

        let mut raw_key = tee.derive_sealing_key(CAPSULE_KEY_CONTEXT)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&raw_key).expect("sealing key is exactly 32 bytes");

        let mut aad = Vec::with_capacity(MAGIC.len() + self.fingerprint.len());
        aad.extend_from_slice(&self.magic);
        aad.extend_from_slice(&self.fingerprint);

        let plaintext = cipher.decrypt(
            XNonce::from_slice(&self.nonce),
            Payload {
                msg: &self.ciphertext,
                aad: &aad,
            },
        );
        raw_key.zeroize();
        let mut plaintext = plaintext.map_err(|_| CapsuleError::Decrypt)?;

        if plaintext.len() != SEED_LEN {
            plaintext.zeroize();
            return Err(CapsuleError::BadSeedSize);
        }
        let mut seed_bytes = [0u8; SEED_LEN];
        seed_bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();

        let actual = SeedFingerprint::from_seed(&seed_bytes)
            .expect("ZIP-32 accepts 32-byte seeds")
            .to_bytes();
        if actual != self.fingerprint {
            seed_bytes.zeroize();
            return Err(CapsuleError::FingerprintMismatch);
        }

        Ok(Secret::new(seed_bytes))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "fake-tee"))]
mod tests {
    use super::*;
    use crate::boot::tee::FakeTee;
    use rand::rngs::OsRng;

    fn a_seed() -> Secret<[u8; SEED_LEN]> {
        Secret::new([7u8; SEED_LEN])
    }

    /// Round-trip: what seal writes, unseal reads back byte-for-byte.
    #[test]
    fn seal_unseal_roundtrip() {
        let tee = FakeTee;
        let seed = a_seed();
        let capsule = Capsule::seal(&tee, &seed, &mut OsRng).expect("seal");
        let out = capsule.unseal(&tee).expect("unseal");
        assert_eq!(out.expose_secret(), seed.expose_secret());
    }

    /// Wrong magic is rejected before decryption.
    #[test]
    fn bad_magic_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = Capsule::seal(&tee, &seed, &mut OsRng).expect("seal");
        capsule.magic[0] ^= 0xFF;
        assert!(matches!(
            capsule.unseal(&tee),
            Err(CapsuleError::BadCapsule)
        ));
    }

    /// AEAD integrity: any ciphertext bit-flip fails the Poly1305 tag.
    #[test]
    fn flipped_ciphertext_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = Capsule::seal(&tee, &seed, &mut OsRng).expect("seal");
        capsule.ciphertext[0] ^= 0xFF;
        assert!(matches!(capsule.unseal(&tee), Err(CapsuleError::Decrypt)));
    }

    /// AAD binding: tampering with the fingerprint changes the AAD, so
    /// decrypt fails before the explicit fingerprint cross-check runs.
    #[test]
    fn tampered_fingerprint_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = Capsule::seal(&tee, &seed, &mut OsRng).expect("seal");
        capsule.fingerprint[0] ^= 0xFF;
        assert!(matches!(capsule.unseal(&tee), Err(CapsuleError::Decrypt)));
    }

    /// A capsule with a wrong-length nonce is rejected before the TEE is
    /// ever asked for a sealing key.
    #[test]
    fn bad_nonce_length_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = Capsule::seal(&tee, &seed, &mut OsRng).expect("seal");
        capsule.nonce.truncate(NONCE_LEN - 1);
        assert!(matches!(
            capsule.unseal(&tee),
            Err(CapsuleError::BadCapsule)
        ));
    }

    /// postcard round-trip: on-disk bytes decode back to the same struct.
    #[test]
    fn on_disk_serialisation_roundtrip() {
        let tee = FakeTee;
        let seed = a_seed();
        let capsule = Capsule::seal(&tee, &seed, &mut OsRng).expect("seal");
        let bytes = capsule.serialize().expect("serialize");
        let parsed = Capsule::parse(&bytes).expect("parse");
        assert_eq!(parsed, capsule);
        let out = parsed.unseal(&tee).expect("unseal");
        assert_eq!(out.expose_secret(), seed.expose_secret());
    }
}

#[cfg(test)]
mod bounds {
    use super::*;
    use std::io::Write;

    fn envelope() -> Capsule {
        Capsule {
            magic: MAGIC,
            fingerprint: [1u8; 32],
            nonce: vec![2u8; NONCE_LEN],
            ciphertext: vec![3u8; CIPHERTEXT_LEN],
        }
    }

    #[test]
    fn a_capsule_serialises_to_the_fixed_length() {
        let bytes = envelope().serialize().expect("serialize");
        assert_eq!(bytes.len(), CAPSULE_LEN);
        assert_eq!(Capsule::parse(&bytes).expect("parse"), envelope());
    }

    #[test]
    fn parse_rejects_the_wrong_file_length() {
        let bytes = envelope().serialize().expect("serialize");
        assert!(matches!(
            Capsule::parse(&bytes[..bytes.len() - 1]),
            Err(CapsuleError::BadCapsule)
        ));
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(
            Capsule::parse(&long),
            Err(CapsuleError::BadCapsule)
        ));
    }

    #[test]
    fn parse_rejects_a_short_ciphertext_inside_a_fixed_blob() {
        let mut bytes = envelope().serialize().expect("serialize");
        // Ciphertext length byte sits after magic, fingerprint, and nonce.
        let len_at = MAGIC.len() + 32 + 1 + NONCE_LEN;
        bytes[len_at] = (CIPHERTEXT_LEN - 1) as u8;
        assert!(matches!(
            Capsule::parse(&bytes),
            Err(CapsuleError::BadCapsule)
        ));
    }

    #[test]
    fn read_rejects_an_oversized_file() {
        let path = std::env::temp_dir().join(format!("zns-capsule-bound-{}", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("temp file");
        file.write_all(&[0u8; CAPSULE_LEN + 8]).expect("write");
        drop(file);
        assert!(matches!(
            read_capsule_file(&path),
            Err(CapsuleError::BadCapsule)
        ));
        let _ = std::fs::remove_file(&path);
    }
}
