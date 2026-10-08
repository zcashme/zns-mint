use std::path::PathBuf;
use std::time::Duration;

use crate::error::MigrateError;

pub const USAGE: &str = "\
zns-migrate — move a sealed ZNS seed to the next measured guest

USAGE:
    zns-migrate source --manifest <TOML> --upgrade-document <BYTES> \\
                       --attestation-bundle <BUNDLE> --transport-dir <DIR> \\
                       --input-capsule <PATH>
    zns-migrate target --manifest <TOML> --upgrade-document <BYTES> \\
                       --attestation-bundle <BUNDLE> --transport-dir <DIR> \\
                       --output-capsule <PATH> [--replace-after-verified-migration]

Source and target may start in either order. Target waits until source marks
the transport directory, then publishes an attested offer before source
unseals anything. The directory is an untrusted one-shot channel:

    source.ready
    offer.bin
    attestation.bin
    encrypted_seed.bin
    source_attestation.bin
    receipt.bin
    receipt_attestation.bin

Use a fresh directory for each attempt. The capsule stays outside it.
Target will not overwrite an existing capsule unless
--replace-after-verified-migration is set.

--transport dir:<DIR> is the same channel as --transport-dir.
--transport unix:<PATH> is not implemented.
--timeout-secs <N> is how long to wait for the peer (default 120, max 86400).

The manifest TOML, the canonical upgrade document, and the Sigstore bundle
stay outside the transport directory. Both sides require the zns-deployment
release workflow to have attested that document before a sealing key is
derived. Source requires the target report's measurement to equal
to_measurement. Target requires the source report's measurement to equal
from_measurement, and that report must bind the offer and the ciphertext,
before it installs a capsule. Source accepts the receipt only when
receipt_attestation.bin binds that offer and that receipt, and the report
measurement equals to_measurement.
";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Source,
    Target,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub role: Role,
    pub manifest: PathBuf,
    pub upgrade_document: PathBuf,
    pub attestation_bundle: PathBuf,
    pub transport_dir: PathBuf,
    pub input_capsule: Option<PathBuf>,
    pub output_capsule: Option<PathBuf>,
    pub replace_after_verified_migration: bool,
    pub timeout: Duration,
}

#[derive(Debug)]
pub enum Command {
    Help,
    Run(Args),
}

pub fn parse<I, S>(args: I) -> Result<Command, MigrateError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter().map(|arg| arg.as_ref().to_string());
    let _program = args.next();
    let role = match args.next().as_deref() {
        None => return Err(MigrateError::usage("missing role: source or target")),
        Some("-h" | "--help") => return Ok(Command::Help),
        Some("source") => Role::Source,
        Some("target") => Role::Target,
        Some(other) => {
            return Err(MigrateError::usage(format!(
                "unknown role {other}; expected source or target"
            )));
        }
    };

    let mut manifest = None;
    let mut upgrade_document = None;
    let mut attestation_bundle = None;
    let mut transport_dir = None;
    let mut input_capsule = None;
    let mut output_capsule = None;
    let mut replace = false;
    let mut timeout = DEFAULT_TIMEOUT;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--manifest" => set_once(&mut manifest, "--manifest", value("--manifest", &mut args)?)?,
            "--upgrade-document" => set_once(
                &mut upgrade_document,
                "--upgrade-document",
                value("--upgrade-document", &mut args)?,
            )?,
            "--attestation-bundle" => set_once(
                &mut attestation_bundle,
                "--attestation-bundle",
                value("--attestation-bundle", &mut args)?,
            )?,
            "--transport-dir" => set_once(
                &mut transport_dir,
                "transport",
                value("--transport-dir", &mut args)?,
            )?,
            "--transport" => {
                let spec = value("--transport", &mut args)?;
                set_once(&mut transport_dir, "transport", parse_transport(&spec)?)?;
            }
            "--input-capsule" => set_once(
                &mut input_capsule,
                "--input-capsule",
                value("--input-capsule", &mut args)?,
            )?,
            "--output-capsule" => set_once(
                &mut output_capsule,
                "--output-capsule",
                value("--output-capsule", &mut args)?,
            )?,
            "--replace-after-verified-migration" => {
                if replace {
                    return Err(MigrateError::usage(
                        "--replace-after-verified-migration was given twice",
                    ));
                }
                replace = true;
            }
            "--timeout-secs" => {
                let text = value("--timeout-secs", &mut args)?;
                let secs: u64 = text.parse().map_err(|_| {
                    MigrateError::usage(format!("--timeout-secs {text} is not an integer"))
                })?;
                if secs == 0 || secs > MAX_TIMEOUT_SECS {
                    return Err(MigrateError::usage(format!(
                        "--timeout-secs must be 1..={MAX_TIMEOUT_SECS}"
                    )));
                }
                timeout = Duration::from_secs(secs);
            }
            other => {
                return Err(MigrateError::usage(format!("unknown argument {other}")));
            }
        }
    }

    let manifest = manifest.ok_or_else(|| MigrateError::usage("--manifest is required"))?;
    let upgrade_document =
        upgrade_document.ok_or_else(|| MigrateError::usage("--upgrade-document is required"))?;
    let attestation_bundle = attestation_bundle
        .ok_or_else(|| MigrateError::usage("--attestation-bundle is required"))?;
    let transport_dir =
        transport_dir.ok_or_else(|| MigrateError::usage("--transport-dir is required"))?;

    match role {
        Role::Source => {
            if output_capsule.is_some() {
                return Err(MigrateError::usage("source does not take --output-capsule"));
            }
            if replace {
                return Err(MigrateError::usage(
                    "source does not take --replace-after-verified-migration",
                ));
            }
            if input_capsule.is_none() {
                return Err(MigrateError::usage("--input-capsule is required"));
            }
        }
        Role::Target => {
            if input_capsule.is_some() {
                return Err(MigrateError::usage("target does not take --input-capsule"));
            }
            if output_capsule.is_none() {
                return Err(MigrateError::usage("--output-capsule is required"));
            }
        }
    }

    Ok(Command::Run(Args {
        role,
        manifest: PathBuf::from(manifest),
        upgrade_document: PathBuf::from(upgrade_document),
        attestation_bundle: PathBuf::from(attestation_bundle),
        transport_dir: PathBuf::from(transport_dir),
        input_capsule: input_capsule.map(PathBuf::from),
        output_capsule: output_capsule.map(PathBuf::from),
        replace_after_verified_migration: replace,
        timeout,
    }))
}

fn set_once(slot: &mut Option<String>, flag: &str, value: String) -> Result<(), MigrateError> {
    if slot.is_some() {
        return Err(MigrateError::usage(format!("{flag} was given twice")));
    }
    *slot = Some(value);
    Ok(())
}

fn value(flag: &str, args: &mut impl Iterator<Item = String>) -> Result<String, MigrateError> {
    let Some(value) = args.next() else {
        return Err(MigrateError::usage(format!("{flag} needs a value")));
    };
    if value.starts_with('-') || value.is_empty() {
        return Err(MigrateError::usage(format!(
            "{flag} needs a value, got {value}"
        )));
    }
    Ok(value)
}

fn parse_transport(spec: &str) -> Result<String, MigrateError> {
    if let Some(path) = spec.strip_prefix("dir:") {
        if path.is_empty() {
            return Err(MigrateError::usage("--transport dir: needs a directory"));
        }
        return Ok(path.to_string());
    }
    if spec.starts_with("unix:") {
        return Err(MigrateError::usage(
            "unix transport is not implemented; use --transport-dir",
        ));
    }
    Err(MigrateError::usage(format!(
        "--transport {spec} is not a dir: path"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_source_and_target() {
        let Command::Run(args) = parse([
            "zns-migrate",
            "source",
            "--manifest",
            "upgrade.toml",
            "--upgrade-document",
            "upgrade.bin",
            "--attestation-bundle",
            "bundle.jsonl",
            "--transport",
            "dir:/migration",
            "--input-capsule",
            "/state/keys/zns_seed.capsule",
            "--timeout-secs",
            "30",
        ])
        .unwrap() else {
            panic!("source command");
        };
        assert_eq!(args.role, Role::Source);
        assert_eq!(args.transport_dir, PathBuf::from("/migration"));
        assert_eq!(args.timeout, Duration::from_secs(30));

        let Command::Run(args) = parse([
            "zns-migrate",
            "target",
            "--output-capsule",
            "/state/keys/zns_seed.capsule",
            "--manifest",
            "upgrade.toml",
            "--upgrade-document",
            "upgrade.bin",
            "--attestation-bundle",
            "bundle.jsonl",
            "--transport-dir",
            "/migration",
            "--replace-after-verified-migration",
        ])
        .unwrap() else {
            panic!("target command");
        };
        assert!(args.replace_after_verified_migration);
        assert!(matches!(
            parse(["zns-migrate", "--help"]).unwrap(),
            Command::Help
        ));
    }

    #[test]
    fn rejects_unix_transport_and_a_source_overwrite_flag() {
        let err = parse([
            "zns-migrate",
            "target",
            "--transport",
            "unix:/migration/zns-migrate.sock",
        ])
        .unwrap_err();
        assert!(err.is_usage());
        assert!(err
            .to_string()
            .contains("unix transport is not implemented"));

        let err = parse([
            "zns-migrate",
            "source",
            "--manifest",
            "m",
            "--upgrade-document",
            "d",
            "--attestation-bundle",
            "b",
            "--transport-dir",
            "t",
            "--input-capsule",
            "c",
            "--replace-after-verified-migration",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("does not take"));
    }
}
