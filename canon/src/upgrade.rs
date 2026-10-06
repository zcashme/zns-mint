//! Authorized measurement change between two guest images.
//!
//! A migration may unseal a capsule only for the measurement named here.
//! That measurement is authorized when the manifest's canonical bytes are a
//! GitHub artifact attestation from the `zcashme` organization
//! ([`ZCASHME_ORG_ID`]). This crate holds no maintainer key.
//!
//! Verification is offline, against the Sigstore public-good trust root.
//! The bundle must be SLSA provenance v1 from `actions/attest-build-provenance`.
//! GitHub's release predicate (`https://in-toto.io/attestation/release/v0.2`)
//! is not accepted. The caller names the repository inside `zcashme` and the
//! workflow that signed. The owner login and owner id are fixed. The git ref
//! is not pinned: any ref is accepted until a release tag is fixed.

use std::sync::OnceLock;

use attestation_verify::{
    Bundle, BundleSet, CheckpointOriginPolicy, GithubPolicy, RefPolicy, RepositoryIdentity,
    SignerPolicy, SourcePolicy, Subject, TrustStore, Verifier, WorkflowPath,
    WorkflowRevisionPolicy,
};
use blake2b_simd::Params as Blake2bParams;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separation for [`manifest_hash`].
pub const UPGRADE_DOMAIN: &[u8] = b"ZNS_UPGRADE_V1";

/// GitHub organization login whose releases may authorize an upgrade.
pub const ZCASHME_ORG: &str = "zcashme";

/// Numeric id of [`ZCASHME_ORG`]. A recreated organization with the same
/// login does not match.
pub const ZCASHME_ORG_ID: u64 = 241_353_095;

/// Signed-note origin of the public-good Rekor v1 log embedded in
/// `attestation-verify`.
const REKOR_V1_ORIGIN: &str = "rekor.sigstore.dev - 1193050959916656506";

const REKOR_V1_URL: &str = "https://rekor.sigstore.dev";

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

/// A zcashme release asset's Sigstore bundle.
///
/// `repository` is the name inside [`ZCASHME_ORG`], not `owner/name`.
/// `workflow` is the Actions workflow that signed, for example
/// `.github/workflows/release.yml`. The signing workflow must live in that
/// same repository. `bundle` is one Sigstore bundle, or the JSONL written by
/// `gh attestation download`.
#[derive(Clone, Copy, Debug)]
pub struct ZcashmeRelease<'a> {
    pub repository: &'a str,
    pub workflow: &'a str,
    pub bundle: &'a [u8],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpgradeError {
    #[error("repository must be a name inside the zcashme org")]
    Repository,

    #[error("manifest bytes are not the canonical encoding")]
    ManifestBytes,

    #[error("artifact sha256 does not match the manifest artifact_hash")]
    ArtifactHash,

    #[error("GitHub attestation: {0}")]
    Attestation(String),
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

/// Verify that a zcashme workflow attested `asset`. Returns SHA-256(`asset`).
///
/// # Errors
///
/// Returns [`UpgradeError::Repository`] when `release.repository` is empty,
/// `.`, `..`, or contains a slash or whitespace. Returns
/// [`UpgradeError::Attestation`] when the bundle does not verify under the
/// pinned `zcashme` owner id.
pub fn verify_zcashme_asset(
    asset: &[u8],
    release: &ZcashmeRelease<'_>,
) -> Result<[u8; 32], UpgradeError> {
    let digest = sha256(asset);
    verify_zcashme_digest(&digest, release)?;
    Ok(digest)
}

/// Verify that a zcashme workflow attested this SHA-256 digest.
///
/// # Errors
///
/// Same as [`verify_zcashme_asset`].
pub fn verify_zcashme_digest(
    sha256: &[u8; 32],
    release: &ZcashmeRelease<'_>,
) -> Result<(), UpgradeError> {
    repository_name(release.repository)?;
    let verifier = verifier(release.repository, release.workflow)?;
    let subject = Subject::from_digest_hex(&hex::encode(sha256)).map_err(attest)?;
    let bundles = bundles(release.bundle)?;
    let mut last_error = None;
    for bundle in &bundles {
        match verifier.verify_digest(&subject, bundle) {
            Ok(_) => return Ok(()),
            Err(err) => last_error = Some(attest(err)),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        UpgradeError::Attestation("bundle contained no attestation".to_string())
    }))
}

/// Accept `manifest` when `document` is its canonical encoding and a zcashme
/// workflow attested those bytes.
///
/// Attesting the manifest, rather than only the guest image, keeps
/// `to_measurement` inside the signed asset.
///
/// # Errors
///
/// Returns [`UpgradeError::ManifestBytes`] before any signature check when
/// `document` is not [`canonical_encoding`]. Other errors match
/// [`verify_zcashme_asset`].
pub fn authorize_manifest(
    manifest: &UpgradeManifest,
    document: &[u8],
    release: &ZcashmeRelease<'_>,
) -> Result<(), UpgradeError> {
    if document != canonical_encoding(manifest) {
        return Err(UpgradeError::ManifestBytes);
    }
    verify_zcashme_asset(document, release)?;
    Ok(())
}

/// Accept `artifact` when its SHA-256 equals `manifest.artifact_hash` and a
/// zcashme workflow attested that digest.
///
/// # Errors
///
/// Returns [`UpgradeError::ArtifactHash`] before any signature check when the
/// digest differs. Other errors match [`verify_zcashme_asset`].
pub fn authorize_artifact(
    manifest: &UpgradeManifest,
    artifact: &[u8],
    release: &ZcashmeRelease<'_>,
) -> Result<(), UpgradeError> {
    let digest = sha256(artifact);
    if digest != manifest.artifact_hash {
        return Err(UpgradeError::ArtifactHash);
    }
    verify_zcashme_digest(&digest, release)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn repository_name(name: &str) -> Result<(), UpgradeError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains(char::is_whitespace)
    {
        return Err(UpgradeError::Repository);
    }
    Ok(())
}

fn bundles(bytes: &[u8]) -> Result<Vec<Bundle>, UpgradeError> {
    match Bundle::from_json(bytes) {
        Ok(bundle) => Ok(vec![bundle]),
        Err(json_err) => match BundleSet::from_json_lines(bytes) {
            Ok(set) => Ok(set.bundles),
            Err(_) => Err(attest(json_err)),
        },
    }
}

fn verifier(repository: &str, workflow: &str) -> Result<Verifier, UpgradeError> {
    let source = RepositoryIdentity::new(ZCASHME_ORG, repository)
        .map_err(attest)?
        .with_owner_id(ZCASHME_ORG_ID);
    let signer = RepositoryIdentity::new(ZCASHME_ORG, repository).map_err(attest)?;
    let policy = GithubPolicy::builder()
        .source(SourcePolicy {
            repository: source,
            git_ref: RefPolicy::Glob("*".to_owned()),
            commit: None,
        })
        .signer(SignerPolicy {
            repository: signer,
            path: WorkflowPath::new(workflow).map_err(attest)?,
            revision: WorkflowRevisionPolicy::Any,
        })
        .build()
        .map_err(attest)?;

    let trust = trust_store()?;
    let rekor = trust
        .tlogs
        .iter()
        .find(|log| log.base_url == REKOR_V1_URL)
        .ok_or_else(|| {
            UpgradeError::Attestation("embedded trust root has no rekor.sigstore.dev log".into())
        })?;
    let origin = CheckpointOriginPolicy::builder()
        .allow_origin(rekor, REKOR_V1_ORIGIN)
        .map_err(attest)?
        .build()
        .map_err(attest)?;
    Verifier::builder()
        .trust_store(trust.clone())
        .github_policy(policy)
        .checkpoint_origin_policy(origin)
        .build()
        .map_err(attest)
}

fn trust_store() -> Result<&'static TrustStore, UpgradeError> {
    static STORE: OnceLock<Result<TrustStore, String>> = OnceLock::new();
    let stored =
        STORE.get_or_init(|| TrustStore::embedded_public_good().map_err(|err| err.to_string()));
    stored
        .as_ref()
        .map_err(|err| UpgradeError::Attestation(err.clone()))
}

fn attest(err: impl ToString) -> UpgradeError {
    UpgradeError::Attestation(err.to_string())
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

    fn release<'a>(repository: &'a str, workflow: &'a str, bundle: &'a [u8]) -> ZcashmeRelease<'a> {
        ZcashmeRelease {
            repository,
            workflow,
            bundle,
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
    fn a_repository_outside_a_bare_name_is_rejected() {
        let bundle = b"{}";
        for name in ["", ".", "..", "zcashme/guest", "guest image", "a\\b"] {
            let err =
                verify_zcashme_digest(&[0; 32], &release(name, "release.yml", bundle)).unwrap_err();
            assert_eq!(err, UpgradeError::Repository, "{name}");
        }
    }

    #[test]
    fn an_empty_workflow_is_rejected() {
        let err = verify_zcashme_digest(&[0; 32], &release("guest", "", b"{}")).unwrap_err();
        assert!(matches!(err, UpgradeError::Attestation(_)), "{err}");
    }

    #[test]
    fn a_garbage_bundle_is_rejected() {
        let err =
            verify_zcashme_digest(&[0; 32], &release("guest", "release.yml", b"{}")).unwrap_err();
        assert!(matches!(err, UpgradeError::Attestation(_)), "{err}");
    }

    #[test]
    fn manifest_bytes_must_be_the_canonical_encoding() {
        let err = authorize_manifest(&sample(), b"not-the-manifest", &release("guest", "w", b""))
            .unwrap_err();
        assert_eq!(err, UpgradeError::ManifestBytes);
    }

    #[test]
    fn artifact_hash_must_be_the_sha256_of_the_image() {
        let err = authorize_artifact(&sample(), b"image", &release("guest", "w", b"")).unwrap_err();
        assert_eq!(err, UpgradeError::ArtifactHash);
    }

    #[test]
    fn a_signed_release_from_another_org_is_rejected() {
        // Real `cli/cli` v2.96.0 SLSA provenance. Cryptography verifies; the
        // zcashme owner pin must still reject it.
        const BUNDLE: &[u8] = include_bytes!("testdata/cli-slsa-provenance.json");
        const DIGEST: &str = "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60";
        let digest: [u8; 32] = hex::decode(DIGEST).unwrap().try_into().unwrap();
        let err = verify_zcashme_digest(
            &digest,
            &release("cli", ".github/workflows/deployment.yml", BUNDLE),
        )
        .unwrap_err();
        let UpgradeError::Attestation(message) = err else {
            panic!("expected an attestation failure");
        };
        assert!(
            message.contains("source repository mismatch")
                && message.contains("zcashme/cli")
                && message.contains("cli/cli"),
            "{message}"
        );
    }
}
