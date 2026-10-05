//! Authorized measurement change between two guest images.
//!
//! A migration may unseal a capsule only for the measurement named here.
//! Signature verification is not implemented: the maintainer key scheme and
//! the 2-of-3 policy are not fixed yet.

use blake2b_simd::Params as Blake2bParams;
use thiserror::Error;

/// Domain separation for [`manifest_hash`].
pub const UPGRADE_DOMAIN: &[u8] = b"ZNS_UPGRADE_V1";

/// One approved step from a measured guest image to the next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeManifest {
    pub version: u32,
    pub sequence: u64,
    pub from_measurement: [u8; 48],
    pub to_measurement: [u8; 48],
    pub artifact_hash: [u8; 32],
    pub release: String,
}

/// One maintainer signature over the canonical manifest bytes.
///
/// The public-key and signature encodings are not chosen yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintainerSignature {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpgradeError {
    #[error("no impl: {0}")]
    NoImpl(&'static str),
}

/// Suggested canonical bytes for [`manifest_hash`].
///
/// `version || sequence || from_measurement || to_measurement || artifact_hash
/// || release_len || release_utf8`, with integers little-endian.
pub fn canonical_encoding(manifest: &UpgradeManifest) -> Vec<u8> {
    let release = manifest.release.as_bytes();
    let release_len = u32::try_from(release.len()).expect("upgrade release name fits in u32 bytes");
    let mut out = Vec::with_capacity(4 + 8 + 48 + 48 + 32 + 4 + release.len());
    out.extend_from_slice(&manifest.version.to_le_bytes());
    out.extend_from_slice(&manifest.sequence.to_le_bytes());
    out.extend_from_slice(&manifest.from_measurement);
    out.extend_from_slice(&manifest.to_measurement);
    out.extend_from_slice(&manifest.artifact_hash);
    out.extend_from_slice(&release_len.to_le_bytes());
    out.extend_from_slice(release);
    out
}

/// `BLAKE2b-256(b"ZNS_UPGRADE_V1" || canonical_encoding(manifest))`.
///
/// This is the `manifest_hash` carried in a [`crate::migration::MigrationOffer`].
pub fn manifest_hash(manifest: &UpgradeManifest) -> [u8; 32] {
    let body = canonical_encoding(manifest);
    let mut input = Vec::with_capacity(UPGRADE_DOMAIN.len() + body.len());
    input.extend_from_slice(UPGRADE_DOMAIN);
    input.extend_from_slice(&body);
    let digest = Blake2bParams::new()
        .hash_length(32)
        .to_state()
        .update(&input)
        .finalize();
    digest.as_bytes()[..32]
        .try_into()
        .expect("BLAKE2b-256 length")
}

/// Check that at least two of three maintainers signed this manifest.
///
/// Not implemented. The signature algorithm and the maintainer key set are
/// still open.
pub fn verify_manifest_signatures(
    _manifest: &UpgradeManifest,
    _signatures: &[MaintainerSignature],
) -> Result<(), UpgradeError> {
    Err(UpgradeError::NoImpl(
        "2-of-3 maintainer signature verification is not implemented",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> UpgradeManifest {
        UpgradeManifest {
            version: 1,
            sequence: 7,
            from_measurement: [0xA1; 48],
            to_measurement: [0xB2; 48],
            artifact_hash: [0xC3; 32],
            release: "guest-1".to_string(),
        }
    }

    #[test]
    fn manifest_hash_changes_when_the_destination_measurement_changes() {
        let manifest = sample();
        let mut other = sample();
        other.to_measurement[0] ^= 0x01;
        assert_ne!(manifest_hash(&manifest), manifest_hash(&other));
    }

    #[test]
    fn signature_verification_is_not_implemented() {
        let error = verify_manifest_signatures(&sample(), &[]).unwrap_err();
        assert!(matches!(error, UpgradeError::NoImpl(_)));
    }
}
