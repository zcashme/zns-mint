//! Authorized measurement change between two guest images.
//!
//! A migration may unseal a capsule only for the measurement named here.
//! That measurement is authorized when the manifest's canonical bytes are a
//! GitHub artifact attestation from the `zcashme` organization
//! ([`ZCASHME_ORG_ID`]). This crate holds no maintainer key.
//!
//! Verification is offline. A GitHub artifact attestation is a Sigstore bundle,
//! checked with `sigstore-verify` against the embedded public-good trust root
//! in `sigstore-trust-root`. That is the log public `zcashme` releases are
//! written to. The transparency-log check stays on: the sample that calls
//! `skip_tlog_unsafe` is for GitHub's private-repository instance, which is a
//! different Fulcio and is not used here.
//!
//! The bundle must be an in-toto statement whose predicate is SLSA provenance
//! v1. GitHub's release predicate
//! (`https://in-toto.io/attestation/release/v0.2`) is not accepted. The caller
//! names the repository inside `zcashme` and the workflow path that signed.
//! The owner login and owner id are fixed. The git ref must be `refs/tags/`
//! plus [`UpgradeManifest::release`]. `release` is a `v*` tag name, and this
//! crate adds the `refs/tags/` prefix. A branch run does not match.

use std::sync::OnceLock;

use blake2b_simd::Params as Blake2bParams;
use sha2::{Digest, Sha256};
use sigstore_trust_root::{SigstoreInstance, TrustedRoot};
use sigstore_verify::types::{Bundle, Sha256Hash, SignatureContent, Statement};
use sigstore_verify::{SubjectAltName, VerificationPolicy, VerificationResult, Verifier};
use thiserror::Error;

/// Domain separation for [`manifest_hash`].
pub const UPGRADE_DOMAIN: &[u8] = b"ZNS_UPGRADE_V1";

/// GitHub organization login whose releases may authorize an upgrade.
pub const ZCASHME_ORG: &str = "zcashme";

/// Numeric id of [`ZCASHME_ORG`]. A recreated organization with the same
/// login does not match.
pub const ZCASHME_ORG_ID: u64 = 241_353_095;

/// in-toto statement type carried by `actions/attest-build-provenance`.
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

/// The only predicate this check accepts.
const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// OIDC issuer of a GitHub Actions workload certificate.
const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// One approved step from a measured guest image to the next.
///
/// `from_guest_policy` and `to_guest_policy` are the SEV-SNP guest policies
/// of the two images. The launch measurement does not cover policy.
/// `seed_fingerprint` is the ZIP-32 fingerprint stored in the capsule header.
/// `source_capsule_hash` is BLAKE2b-256 of the on-disk capsule bytes, with no
/// domain string. `release` is the `v*` tag the signing workflow ran on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeManifest {
    pub version: u32,
    pub sequence: u64,
    pub from_measurement: [u8; 48],
    pub to_measurement: [u8; 48],
    pub from_guest_policy: u64,
    pub to_guest_policy: u64,
    pub seed_fingerprint: [u8; 32],
    pub source_capsule_hash: [u8; 32],
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

/// Canonical bytes for [`manifest_hash`].
///
/// `version || sequence || from_measurement || to_measurement ||
/// from_guest_policy || to_guest_policy || seed_fingerprint ||
/// source_capsule_hash || artifact_hash || release_len || release_utf8`,
/// with integers little-endian.
pub fn canonical_encoding(manifest: &UpgradeManifest) -> Vec<u8> {
    let release = manifest.release.as_bytes();
    let release_len = u32::try_from(release.len()).expect("upgrade release name fits in u32 bytes");
    let mut out = Vec::with_capacity(4 + 8 + 48 + 48 + 8 + 8 + 32 + 32 + 32 + 4 + release.len());
    out.extend_from_slice(&manifest.version.to_le_bytes());
    out.extend_from_slice(&manifest.sequence.to_le_bytes());
    out.extend_from_slice(&manifest.from_measurement);
    out.extend_from_slice(&manifest.to_measurement);
    out.extend_from_slice(&manifest.from_guest_policy.to_le_bytes());
    out.extend_from_slice(&manifest.to_guest_policy.to_le_bytes());
    out.extend_from_slice(&manifest.seed_fingerprint);
    out.extend_from_slice(&manifest.source_capsule_hash);
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
/// [`UpgradeError::Attestation`] when `tag` is not a `v*` tag name, or when
/// the bundle does not verify under the pinned `zcashme` owner id and
/// `refs/tags/{tag}`.
pub fn verify_zcashme_asset(
    asset: &[u8],
    release: &ZcashmeRelease<'_>,
    tag: &str,
) -> Result<[u8; 32], UpgradeError> {
    let digest = sha256(asset);
    verify_zcashme_digest(&digest, release, tag)?;
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
    tag: &str,
) -> Result<(), UpgradeError> {
    repository_name(release.repository)?;
    workflow_path(release.workflow)?;
    release_tag(tag)?;
    let verifier = verifier()?;
    let bundles = bundles(release.bundle)?;
    let mut last_error = None;
    for bundle in &bundles {
        match authorize_bundle(verifier, sha256, bundle, release, tag) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err),
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
    verify_zcashme_asset(document, release, &manifest.release)?;
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
    verify_zcashme_digest(&digest, release, &manifest.release)
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

fn workflow_path(workflow: &str) -> Result<(), UpgradeError> {
    let bad = workflow.is_empty()
        || workflow.starts_with('/')
        || workflow.contains('@')
        || workflow.contains('\\')
        || workflow.contains(char::is_whitespace)
        || workflow
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if bad {
        return Err(UpgradeError::Attestation(
            "workflow path is empty or not a relative path".into(),
        ));
    }
    Ok(())
}

fn bundles(bytes: &[u8]) -> Result<Vec<Bundle>, UpgradeError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| UpgradeError::Attestation("bundle is not utf-8".into()))?;
    if let Ok(bundle) = Bundle::from_json(text) {
        return Ok(vec![bundle]);
    }
    let mut parsed = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        parsed.push(Bundle::from_json(line).map_err(attest)?);
    }
    if parsed.is_empty() {
        return Err(UpgradeError::Attestation(
            "bundle contained no attestation".into(),
        ));
    }
    Ok(parsed)
}

/// Public releases chain to public-good Fulcio and are included in public
/// Rekor. `SigstoreInstance::GitHub` is the private-repository instance; its
/// certificates do not chain here and it has no transparency log.
fn verifier() -> Result<&'static Verifier, UpgradeError> {
    static SLOT: OnceLock<Result<Verifier, String>> = OnceLock::new();
    let stored = SLOT.get_or_init(|| {
        let root = TrustedRoot::from_embedded(SigstoreInstance::PublicGood)
            .map_err(|err| err.to_string())?;
        Verifier::new(&root).map_err(|err| err.to_string())
    });
    match stored {
        Ok(verifier) => Ok(verifier),
        Err(err) => Err(UpgradeError::Attestation(err.clone())),
    }
}

fn policy() -> VerificationPolicy {
    // `any_identity` leaves the transparency log and the SCT check on.
    // The signer is authorized afterwards. An identity matcher is exact, and
    // the tag comes from the manifest, so the full certificate identity is
    // checked in `require_zcashme`.
    VerificationPolicy::any_identity().require_issuer(GITHUB_ACTIONS_ISSUER)
}

fn release_tag(tag: &str) -> Result<(), UpgradeError> {
    let Some(rest) = tag.strip_prefix('v') else {
        return Err(UpgradeError::Attestation(
            "release must be a v* tag, not a git ref".into(),
        ));
    };
    let plain = !rest.is_empty()
        && !rest.contains("..")
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
    if plain {
        return Ok(());
    }
    Err(UpgradeError::Attestation(
        "release must be a v* tag, not a git ref".into(),
    ))
}

fn workflow_identity(repository: &str, workflow: &str, tag: &str) -> String {
    format!("https://github.com/{ZCASHME_ORG}/{repository}/{workflow}@refs/tags/{tag}")
}

fn authorize_bundle(
    verifier: &Verifier,
    sha256: &[u8; 32],
    bundle: &Bundle,
    release: &ZcashmeRelease<'_>,
    tag: &str,
) -> Result<(), UpgradeError> {
    let result = verifier
        .verify(Sha256Hash::new(*sha256), bundle, &policy())
        .map_err(attest)?;
    require_checked(&result)?;
    require_slsa(bundle)?;
    require_zcashme(&result, release.repository, release.workflow, tag)
}

fn require_checked(result: &VerificationResult) -> Result<(), UpgradeError> {
    if result.certificate_verified()
        && result.sct_verified()
        && result.tlog_verified()
        && result.identity_policy_checked()
        && result.issuer() == Some(GITHUB_ACTIONS_ISSUER)
    {
        return Ok(());
    }
    Err(UpgradeError::Attestation(
        "attestation was not checked against the certificate and the transparency log".into(),
    ))
}

fn require_slsa(bundle: &Bundle) -> Result<(), UpgradeError> {
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(UpgradeError::Attestation(
            "bundle is not a SLSA provenance statement".into(),
        ));
    };
    let statement: Statement =
        serde_json::from_slice(envelope.payload.as_bytes()).map_err(attest)?;
    if statement.type_ == IN_TOTO_STATEMENT_V1 && statement.predicate_type == SLSA_PROVENANCE_V1 {
        return Ok(());
    }
    Err(UpgradeError::Attestation(format!(
        "expected SLSA provenance {SLSA_PROVENANCE_V1}, found {}",
        statement.predicate_type
    )))
}

fn require_zcashme(
    result: &VerificationResult,
    repository: &str,
    workflow: &str,
    tag: &str,
) -> Result<(), UpgradeError> {
    let claims = result
        .certificate()
        .map(|cert| &cert.ci_claims)
        .ok_or_else(|| {
            UpgradeError::Attestation("attestation has no signing certificate".into())
        })?;
    let found = source_repository(claims);
    let expected = format!("{ZCASHME_ORG}/{repository}");
    if found != expected {
        return Err(UpgradeError::Attestation(format!(
            "source repository mismatch: expected {expected}, found {found}"
        )));
    }
    let owner_id = ZCASHME_ORG_ID.to_string();
    if claims.source_repository_owner_identifier.as_deref() != Some(owner_id.as_str()) {
        return Err(UpgradeError::Attestation(format!(
            "source repository owner id mismatch: expected {owner_id}"
        )));
    }
    let expected_san = workflow_identity(repository, workflow, tag);
    let san = result.identity().map(SubjectAltName::as_str).unwrap_or("");
    if san != expected_san {
        return Err(UpgradeError::Attestation(format!(
            "workflow identity mismatch: expected {expected_san}, found {san}"
        )));
    }
    if claims
        .build_signer_uri
        .as_deref()
        .is_some_and(|uri| uri != san)
    {
        return Err(UpgradeError::Attestation(
            "build signer uri does not match the certificate identity".into(),
        ));
    }
    Ok(())
}

fn source_repository(claims: &sigstore_verify::crypto::FulcioCiClaims) -> String {
    let from_uri = claims.source_repository_uri.as_deref().map(|uri| {
        uri.strip_prefix("https://github.com/")
            .unwrap_or(uri)
            .to_string()
    });
    let from_deprecated = claims
        .deprecated_github
        .workflow_repository
        .as_deref()
        .map(str::to_string);
    match (from_uri, from_deprecated) {
        (Some(uri), Some(old)) if uri != old => format!("{uri} (also {old})"),
        (Some(uri), _) => uri,
        (None, Some(old)) => old,
        (None, None) => "absent".to_string(),
    }
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
            from_guest_policy: 0x1111_1111_1111_1111,
            to_guest_policy: 0x2222_2222_2222_2222,
            seed_fingerprint: [0xD4; 32],
            source_capsule_hash: [0xE5; 32],
            artifact_hash: [0xC3; 32],
            release: "v1.2.3".to_string(),
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
    fn encoding_lays_out_the_fixed_fields() {
        let bytes = canonical_encoding(&sample());
        let release = b"v1.2.3";
        let fixed = 4 + 8 + 48 + 48 + 8 + 8 + 32 + 32 + 32;
        assert_eq!(bytes.len(), fixed + 4 + release.len());
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(&bytes[4..12], &7u64.to_le_bytes());
        assert_eq!(&bytes[12..60], &[0xA1; 48]);
        assert_eq!(&bytes[60..108], &[0xB2; 48]);
        assert_eq!(&bytes[108..116], &0x1111_1111_1111_1111u64.to_le_bytes());
        assert_eq!(&bytes[116..124], &0x2222_2222_2222_2222u64.to_le_bytes());
        assert_eq!(&bytes[124..156], &[0xD4; 32]);
        assert_eq!(&bytes[156..188], &[0xE5; 32]);
        assert_eq!(&bytes[188..220], &[0xC3; 32]);
        let release_len = u32::try_from(release.len()).unwrap();
        assert_eq!(&bytes[220..224], &release_len.to_le_bytes());
        assert_eq!(&bytes[224..], release);
    }

    #[test]
    fn manifest_hash_changes_when_the_destination_measurement_changes() {
        let manifest = sample();
        let mut other = sample();
        other.to_measurement[0] ^= 0x01;
        assert_ne!(manifest_hash(&manifest), manifest_hash(&other));
    }

    #[test]
    fn manifest_hash_covers_policy_and_the_named_capsule() {
        let baseline = manifest_hash(&sample());
        let mut from_policy = sample();
        from_policy.from_guest_policy ^= 1;
        let mut to_policy = sample();
        to_policy.to_guest_policy ^= 1;
        let mut fingerprint = sample();
        fingerprint.seed_fingerprint[0] ^= 1;
        let mut capsule = sample();
        capsule.source_capsule_hash[0] ^= 1;
        assert_ne!(manifest_hash(&from_policy), baseline);
        assert_ne!(manifest_hash(&to_policy), baseline);
        assert_ne!(manifest_hash(&fingerprint), baseline);
        assert_ne!(manifest_hash(&capsule), baseline);
    }

    #[test]
    fn a_repository_outside_a_bare_name_is_rejected() {
        let bundle = b"{}";
        for name in ["", ".", "..", "zcashme/guest", "guest image", "a\\b"] {
            let err =
                verify_zcashme_digest(&[0; 32], &release(name, "release.yml", bundle), "v1.2.3")
                    .unwrap_err();
            assert_eq!(err, UpgradeError::Repository, "{name}");
        }
    }

    #[test]
    fn an_empty_workflow_is_rejected() {
        let err =
            verify_zcashme_digest(&[0; 32], &release("guest", "", b"{}"), "v1.2.3").unwrap_err();
        assert!(matches!(err, UpgradeError::Attestation(_)), "{err}");
    }

    #[test]
    fn a_garbage_bundle_is_rejected() {
        let err =
            verify_zcashme_digest(&[0; 32], &release("guest", "release.yml", b"{}"), "v1.2.3")
                .unwrap_err();
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
    fn a_release_name_that_is_not_a_tag_is_rejected() {
        for tag in [
            "guest-1",
            "refs/tags/v1.2.3",
            "refs/heads/main",
            "v1/2",
            "v..1",
        ] {
            let err = verify_zcashme_digest(&[0; 32], &release("guest", "release.yml", b"{}"), tag)
                .unwrap_err();
            let UpgradeError::Attestation(message) = err else {
                panic!("{tag}: {err}");
            };
            assert!(message.contains("v* tag"), "{tag}: {message}");
        }
    }

    #[test]
    fn authorize_manifest_uses_the_release_field_as_the_tag() {
        let mut manifest = sample();
        manifest.release = "guest-1".into();
        let document = canonical_encoding(&manifest);
        let err = authorize_manifest(
            &manifest,
            &document,
            &release("guest", "release.yml", b"{}"),
        )
        .unwrap_err();
        let UpgradeError::Attestation(message) = err else {
            panic!("{err}");
        };
        assert!(message.contains("v* tag"), "{message}");
    }

    #[test]
    fn the_certificate_identity_includes_the_tag() {
        assert_eq!(
            workflow_identity(
                "zns-deployment",
                ".github/workflows/release.yml",
                "v0.1.4"
            ),
            "https://github.com/zcashme/zns-deployment/.github/workflows/release.yml@refs/tags/v0.1.4"
        );
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
            "v2.96.0",
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
