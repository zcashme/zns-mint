//! Sealed seed capsule: the seed's on-disk form.
//!
//! Format is unchanged from the pre-refactor inlined codec: postcard-serialised
//! `{ magic, fingerprint, nonce, ciphertext }`, magic = `b"ZNS_SEED"`, 24-byte
//! `XChaCha20Poly1305` nonce, AAD = `magic || fingerprint`, plaintext = the
//! 32-byte ZIP-32 seed. The sealing key comes from the [`crate::tee::Tee`]
//! seam so integration tests can substitute [`crate::tee::FakeTee`] without
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

use crate::tee::{Tee, TeeError};

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
    #[error("capsule magic mismatch (not a ZNS seed capsule)")]
    BadMagic,

    #[error("capsule nonce length {actual} != expected {expected}")]
    BadNonce { actual: usize, expected: usize },

    #[error("capsule length {actual} != expected {expected}")]
    BadLength { actual: usize, expected: usize },

    #[error("capsule ciphertext length {actual} != expected {expected}")]
    BadCiphertext { actual: usize, expected: usize },

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
        return Err(CapsuleError::BadLength {
            actual: buf.len(),
            expected: CAPSULE_LEN,
        });
    }
    Ok(buf)
}

/// Deserialises a capsule from its on-disk bytes (postcard).
/// The blob and both variable fields must be the fixed lengths.
pub fn parse_capsule(blob: &[u8]) -> Result<Capsule, CapsuleError> {
    if blob.len() != CAPSULE_LEN {
        return Err(CapsuleError::BadLength {
            actual: blob.len(),
            expected: CAPSULE_LEN,
        });
    }
    let capsule: Capsule =
        postcard::from_bytes(blob).map_err(|e| CapsuleError::Parse(e.to_string()))?;
    fixed_fields(&capsule)?;
    Ok(capsule)
}

/// Nonce and ciphertext are fixed sizes. Checked before decryption.
fn fixed_fields(capsule: &Capsule) -> Result<(), CapsuleError> {
    if capsule.nonce.len() != NONCE_LEN {
        return Err(CapsuleError::BadNonce {
            actual: capsule.nonce.len(),
            expected: NONCE_LEN,
        });
    }
    if capsule.ciphertext.len() != CIPHERTEXT_LEN {
        return Err(CapsuleError::BadCiphertext {
            actual: capsule.ciphertext.len(),
            expected: CIPHERTEXT_LEN,
        });
    }
    Ok(())
}

/// Serialises a capsule to its on-disk bytes (postcard).
pub fn serialize_capsule(capsule: &Capsule) -> Result<Vec<u8>, CapsuleError> {
    postcard::to_allocvec(capsule).map_err(|e| CapsuleError::Parse(e.to_string()))
}

/// Seals a 32-byte seed into a capsule using the TEE's sealing key.
///
/// The capsule's fingerprint field is computed from the seed itself (so
/// `unseal_seed` can re-derive and cross-check) and is bound into the AEAD
/// as additional authenticated data; any tampering with either fails
/// decryption.
pub fn seal_seed<T, R>(
    tee: &T,
    seed: &Secret<[u8; SEED_LEN]>,
    rng: &mut R,
) -> Result<Capsule, CapsuleError>
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

    Ok(Capsule {
        magic: MAGIC,
        fingerprint,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Unseals a capsule with the TEE's sealing key.
///
/// Verifies (in order): the magic, the nonce and ciphertext lengths,
/// the AEAD tag with AAD = `magic || fingerprint`, the decrypted seed
/// length, and the fingerprint the seed derives to. The returned
/// [`Secret`] wipes on drop.
pub fn unseal_seed<T: Tee + ?Sized>(
    tee: &T,
    capsule: &Capsule,
) -> Result<Secret<[u8; SEED_LEN]>, CapsuleError> {
    if capsule.magic != MAGIC {
        return Err(CapsuleError::BadMagic);
    }
    fixed_fields(capsule)?;

    let mut raw_key = tee.derive_sealing_key(CAPSULE_KEY_CONTEXT)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&raw_key).expect("sealing key is exactly 32 bytes");

    let mut aad = Vec::with_capacity(MAGIC.len() + capsule.fingerprint.len());
    aad.extend_from_slice(&capsule.magic);
    aad.extend_from_slice(&capsule.fingerprint);

    let plaintext = cipher.decrypt(
        XNonce::from_slice(&capsule.nonce),
        Payload {
            msg: &capsule.ciphertext,
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

    // Cross-check: the capsule's declared fingerprint must match what the
    // seed derives to. AEAD-with-AAD already forces this — tampering with
    // the fingerprint changes the AAD, so decrypt would have failed — but
    // an explicit check makes the invariant visible at the callsite.
    let actual = SeedFingerprint::from_seed(&seed_bytes)
        .expect("ZIP-32 accepts 32-byte seeds")
        .to_bytes();
    if actual != capsule.fingerprint {
        seed_bytes.zeroize();
        return Err(CapsuleError::FingerprintMismatch);
    }

    Ok(Secret::new(seed_bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "fake-tee"))]
mod tests {
    use super::*;
    use crate::tee::FakeTee;
    use rand::rngs::OsRng;

    fn a_seed() -> Secret<[u8; SEED_LEN]> {
        Secret::new([7u8; SEED_LEN])
    }

    /// Round-trip: what seal_seed writes, unseal_seed reads back byte-for-byte.
    #[test]
    fn seal_unseal_roundtrip() {
        let tee = FakeTee;
        let seed = a_seed();
        let capsule = seal_seed(&tee, &seed, &mut OsRng).expect("seal");
        let out = unseal_seed(&tee, &capsule).expect("unseal");
        assert_eq!(out.expose_secret(), seed.expose_secret());
    }

    /// A capsule whose magic no longer says `ZNS_SEED` never even reaches
    /// AEAD — we fail fast with `BadMagic`.
    #[test]
    fn bad_magic_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = seal_seed(&tee, &seed, &mut OsRng).expect("seal");
        capsule.magic[0] ^= 0xFF;
        assert!(matches!(
            unseal_seed(&tee, &capsule),
            Err(CapsuleError::BadMagic)
        ));
    }

    /// AEAD integrity: any ciphertext bit-flip fails the Poly1305 tag.
    #[test]
    fn flipped_ciphertext_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = seal_seed(&tee, &seed, &mut OsRng).expect("seal");
        capsule.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            unseal_seed(&tee, &capsule),
            Err(CapsuleError::Decrypt)
        ));
    }

    /// AAD binding: tampering with the fingerprint changes the AAD, so
    /// decrypt fails before the explicit fingerprint cross-check runs.
    #[test]
    fn tampered_fingerprint_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = seal_seed(&tee, &seed, &mut OsRng).expect("seal");
        capsule.fingerprint[0] ^= 0xFF;
        assert!(matches!(
            unseal_seed(&tee, &capsule),
            Err(CapsuleError::Decrypt)
        ));
    }

    /// A capsule with a wrong-length nonce is rejected before the TEE is
    /// ever asked for a sealing key.
    #[test]
    fn bad_nonce_length_rejected() {
        let tee = FakeTee;
        let seed = a_seed();
        let mut capsule = seal_seed(&tee, &seed, &mut OsRng).expect("seal");
        capsule.nonce.truncate(NONCE_LEN - 1);
        assert!(matches!(
            unseal_seed(&tee, &capsule),
            Err(CapsuleError::BadNonce { .. })
        ));
    }

    /// postcard round-trip: on-disk bytes decode back to the same struct.
    #[test]
    fn on_disk_serialisation_roundtrip() {
        let tee = FakeTee;
        let seed = a_seed();
        let capsule = seal_seed(&tee, &seed, &mut OsRng).expect("seal");
        let bytes = serialize_capsule(&capsule).expect("serialize");
        let parsed = parse_capsule(&bytes).expect("parse");
        assert_eq!(parsed, capsule);
        let out = unseal_seed(&tee, &parsed).expect("unseal");
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
        let bytes = serialize_capsule(&envelope()).expect("serialize");
        assert_eq!(bytes.len(), CAPSULE_LEN);
        assert_eq!(parse_capsule(&bytes).expect("parse"), envelope());
    }

    #[test]
    fn parse_rejects_the_wrong_file_length() {
        let bytes = serialize_capsule(&envelope()).expect("serialize");
        assert!(matches!(
            parse_capsule(&bytes[..bytes.len() - 1]),
            Err(CapsuleError::BadLength { .. })
        ));
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(
            parse_capsule(&long),
            Err(CapsuleError::BadLength { .. })
        ));
    }

    #[test]
    fn parse_rejects_a_short_ciphertext_inside_a_fixed_blob() {
        let mut bytes = serialize_capsule(&envelope()).expect("serialize");
        // Ciphertext length byte sits after magic, fingerprint, and nonce.
        let len_at = MAGIC.len() + 32 + 1 + NONCE_LEN;
        bytes[len_at] = (CIPHERTEXT_LEN - 1) as u8;
        assert!(matches!(
            parse_capsule(&bytes),
            Err(CapsuleError::BadCiphertext { .. })
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
            Err(CapsuleError::BadLength {
                actual: n,
                ..
            }) if n == CAPSULE_LEN + 1
        ));
        let _ = std::fs::remove_file(&path);
    }
}
