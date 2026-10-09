//! Upgrade manifest file.
//!
//! The TOML file is the operator's view. GitHub attests
//! [`zns_canon::upgrade::canonical_encoding`] of those same fields. Both
//! sides call [`authorize`] on that document and its Sigstore bundle before
//! a sealing key is derived. The attestation must come from
//! [`ATTESTATION_REPOSITORY`] workflow [`ATTESTATION_WORKFLOW`].

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use zns_canon::upgrade::{self, UpgradeManifest, ZcashmeRelease};

use crate::error::MigrateError;

pub const ATTESTATION_REPOSITORY: &str = "zns-deployment";

pub const ATTESTATION_WORKFLOW: &str = ".github/workflows/release.yml";

const MANIFEST_VERSION: u32 = 1;
const MAX_BYTES: u64 = 64 * 1024;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;
const MAX_RELEASE_LEN: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    version: u32,
    sequence: u64,
    from_measurement: String,
    to_measurement: String,
    from_guest_policy: u64,
    to_guest_policy: u64,
    seed_fingerprint: String,
    source_capsule_hash: String,
    artifact_hash: String,
    release: String,
}

pub fn load(path: &Path) -> Result<UpgradeManifest, MigrateError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(MigrateError::manifest(format!(
                "{} is a symlink",
                path.display()
            )));
        }
        Ok(meta) if !meta.is_file() => {
            return Err(MigrateError::manifest(format!(
                "{} is not a file",
                path.display()
            )));
        }
        Ok(meta) if meta.len() > MAX_BYTES => {
            return Err(MigrateError::manifest(format!(
                "{} is larger than {MAX_BYTES} bytes",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) => {
            return Err(MigrateError::io(format!("read {}", path.display()), error));
        }
    }

    let text = fs::read_to_string(path)
        .map_err(|error| MigrateError::io(format!("read {}", path.display()), error))?;
    let file: ManifestFile = toml::from_str(&text)
        .map_err(|error| MigrateError::manifest(format!("{}: {error}", path.display())))?;
    if file.version != MANIFEST_VERSION {
        return Err(MigrateError::manifest(format!(
            "version {} is not supported",
            file.version
        )));
    }
    let release = file.release;
    if release.is_empty()
        || release.len() > MAX_RELEASE_LEN
        || release.chars().any(|c| c.is_control())
    {
        return Err(MigrateError::manifest(
            "release must be one non-empty line of at most 256 bytes",
        ));
    }
    let from_measurement = decode_hex("from_measurement", &file.from_measurement)?;
    let to_measurement = decode_hex("to_measurement", &file.to_measurement)?;
    if from_measurement == [0u8; 48] || to_measurement == [0u8; 48] {
        return Err(MigrateError::manifest("measurement must not be all zeros"));
    }
    if file.from_guest_policy == 0 || file.to_guest_policy == 0 {
        return Err(MigrateError::manifest("guest policy must not be zero"));
    }
    let seed_fingerprint = decode_hex("seed_fingerprint", &file.seed_fingerprint)?;
    let source_capsule_hash = decode_hex("source_capsule_hash", &file.source_capsule_hash)?;
    if seed_fingerprint == [0u8; 32] || source_capsule_hash == [0u8; 32] {
        return Err(MigrateError::manifest(
            "seed fingerprint and source capsule hash must not be all zeros",
        ));
    }
    Ok(UpgradeManifest {
        version: file.version,
        sequence: file.sequence,
        from_measurement,
        to_measurement,
        from_guest_policy: file.from_guest_policy,
        to_guest_policy: file.to_guest_policy,
        seed_fingerprint,
        source_capsule_hash,
        artifact_hash: decode_hex("artifact_hash", &file.artifact_hash)?,
        release,
    })
}

/// Require that `document` is the canonical encoding of `manifest` and that
/// the zns-deployment release workflow attested those bytes.
pub fn authorize(
    manifest: &UpgradeManifest,
    document: &Path,
    bundle: &Path,
) -> Result<(), MigrateError> {
    let document = read_regular(document, MAX_BYTES)?;
    let bundle = read_regular(bundle, MAX_BUNDLE_BYTES)?;
    let release = ZcashmeRelease {
        repository: ATTESTATION_REPOSITORY,
        workflow: ATTESTATION_WORKFLOW,
        bundle: &bundle,
    };
    upgrade::authorize_manifest(manifest, &document, &release)?;
    Ok(())
}

fn read_regular(path: &Path, max_bytes: u64) -> Result<Vec<u8>, MigrateError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(MigrateError::manifest(format!(
                "{} is a symlink",
                path.display()
            )));
        }
        Ok(meta) if !meta.is_file() => {
            return Err(MigrateError::manifest(format!(
                "{} is not a file",
                path.display()
            )));
        }
        Ok(meta) if meta.len() > max_bytes => {
            return Err(MigrateError::manifest(format!(
                "{} is larger than {max_bytes} bytes",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) => {
            return Err(MigrateError::io(format!("read {}", path.display()), error));
        }
    }
    let file = File::open(path)
        .map_err(|error| MigrateError::io(format!("read {}", path.display()), error))?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| MigrateError::io(format!("read {}", path.display()), error))?;
    if bytes.len() as u64 > max_bytes {
        return Err(MigrateError::manifest(format!(
            "{} is larger than {max_bytes} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn decode_hex<const N: usize>(field: &str, text: &str) -> Result<[u8; N], MigrateError> {
    let bytes = hex::decode(text.trim())
        .map_err(|_| MigrateError::manifest(format!("{field} is not hex")))?;
    if bytes.len() != N {
        return Err(MigrateError::manifest(format!(
            "{field} is {} bytes, expected {N}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        format!(
            "\
version = 1
sequence = 7
from_measurement = \"{}\"
to_measurement = \"{}\"
from_guest_policy = 0x30000
to_guest_policy = 0x30000
seed_fingerprint = \"{}\"
source_capsule_hash = \"{}\"
artifact_hash = \"{}\"
release = \"guest-2\"
",
            "11".repeat(48),
            "22".repeat(48),
            "44".repeat(32),
            "55".repeat(32),
            "33".repeat(32),
        )
    }

    fn write(name: &str, text: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zns-migrate-manifest-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("upgrade.toml");
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn loads_a_version_one_manifest() {
        let path = write("ok", &sample());
        let manifest = load(&path).unwrap();
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.sequence, 7);
        assert_eq!(manifest.release, "guest-2");
        assert_eq!(manifest.to_measurement, [0x22; 48]);
        assert_eq!(manifest.from_guest_policy, 0x30000);
        assert_eq!(manifest.to_guest_policy, 0x30000);
        assert_eq!(manifest.seed_fingerprint, [0x44; 32]);
        assert_eq!(manifest.source_capsule_hash, [0x55; 32]);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rejects_unknown_fields_wrong_version_and_zero_measurement() {
        let extra = write("extra", &format!("{}extra = 1\n", sample()));
        assert!(load(&extra).unwrap_err().to_string().contains("manifest"));

        let version = sample().replacen("version = 1", "version = 2", 1);
        let path = write("version", &version);
        assert!(load(&path)
            .unwrap_err()
            .to_string()
            .contains("not supported"));

        let zeros = sample().replacen(&"22".repeat(48), &"00".repeat(48), 1);
        let path = write("zeros", &zeros);
        assert!(load(&path).unwrap_err().to_string().contains("all zeros"));

        let policy = sample().replacen("from_guest_policy = 0x30000", "from_guest_policy = 0", 1);
        let path = write("policy", &policy);
        assert!(load(&path)
            .unwrap_err()
            .to_string()
            .contains("guest policy"));

        let fingerprint = sample().replacen(&"44".repeat(32), &"00".repeat(32), 1);
        let path = write("fingerprint", &fingerprint);
        assert!(load(&path)
            .unwrap_err()
            .to_string()
            .contains("seed fingerprint"));
    }

    #[test]
    fn a_document_that_is_not_canonical_is_rejected() {
        let manifest = load(&write("auth-doc", &sample())).unwrap();
        let dir = manifest_dir("auth-doc");
        let document = dir.join("upgrade.bin");
        let bundle = dir.join("bundle.json");
        fs::write(&document, b"not-the-canonical-document").unwrap();
        fs::write(&bundle, b"{}").unwrap();
        let err = authorize(&manifest, &document, &bundle).unwrap_err();
        assert!(err.to_string().contains("canonical"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_matching_document_is_rejected_without_a_real_attestation() {
        let manifest = load(&write("auth-bundle", &sample())).unwrap();
        let dir = manifest_dir("auth-bundle");
        let document = dir.join("upgrade.bin");
        let bundle = dir.join("bundle.json");
        fs::write(&document, upgrade::canonical_encoding(&manifest)).unwrap();
        fs::write(&bundle, b"{}").unwrap();
        let err = authorize(&manifest, &document, &bundle).unwrap_err();
        assert!(
            err.to_string().contains("attestation") || err.to_string().contains("GitHub"),
            "{err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_document_larger_than_the_limit_is_rejected() {
        let manifest = load(&write("big", &sample())).unwrap();
        let dir = manifest_dir("big");
        let document = dir.join("upgrade.bin");
        let bundle = dir.join("bundle.json");
        fs::write(&document, vec![0u8; (MAX_BYTES as usize) + 1]).unwrap();
        fs::write(&bundle, b"{}").unwrap();
        let err = authorize(&manifest, &document, &bundle).unwrap_err();
        assert!(err.to_string().contains("larger"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_deployment_release_bundle_is_accepted() {
        // v0.1.2 attested this measurement file, not a canonical upgrade
        // document, so `authorize` cannot accept this bundle yet. The
        // constants below are the ones `authorize` passes to canon.
        // TODO: when a release attests canonical upgrade bytes, replace this
        // fixture with that document and its bundle and call `authorize`.
        const ASSET: &[u8] = include_bytes!("testdata/v0.1.2-snp-measurement.txt");
        const BUNDLE: &[u8] = include_bytes!("testdata/v0.1.2-snp-measurement.bundle.jsonl");
        let release = ZcashmeRelease {
            repository: ATTESTATION_REPOSITORY,
            workflow: ATTESTATION_WORKFLOW,
            bundle: BUNDLE,
        };
        let digest = upgrade::verify_zcashme_asset(ASSET, &release, "v0.1.2").unwrap();
        assert_eq!(
            hex::encode(digest),
            "fd97164c2798585f391edf4a6445cedceb37b0cec7f1af0136f7846b52ca1e0a"
        );
    }

    fn manifest_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "zns-migrate-manifest-{}-{}",
            std::process::id(),
            name
        ))
    }
}
