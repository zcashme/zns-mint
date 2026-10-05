//! Upgrade manifest file.
//!
//! TODO: require maintainer signatures before this file authorizes
//! `to_measurement`. `zns_canon::upgrade::verify_manifest_signatures` still
//! returns `NoImpl` ("m-of-n maintainer signature verification"). Inventing
//! that scheme here would pretend the check had happened. Until it is
//! called, replacing this file before startup selects the guest that
//! receives the seed. The attestation checks only show that the target
//! matches the file.
//!
//! This loader only checks that the file is a version-1 manifest with
//! fixed-width fields.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use zns_canon::upgrade::UpgradeManifest;

use crate::error::MigrateError;

const MANIFEST_VERSION: u32 = 1;
const MAX_BYTES: u64 = 64 * 1024;
const MAX_RELEASE_LEN: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    version: u32,
    sequence: u64,
    from_measurement: String,
    to_measurement: String,
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
    Ok(UpgradeManifest {
        version: file.version,
        sequence: file.sequence,
        from_measurement,
        to_measurement,
        artifact_hash: decode_hex("artifact_hash", &file.artifact_hash)?,
        release,
    })
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
artifact_hash = \"{}\"
release = \"guest-2\"
",
            "11".repeat(48),
            "22".repeat(48),
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
    }
}
