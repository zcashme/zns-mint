//! Directory transport.
//!
//! The directory is a one-shot channel, not trusted state. Readers open each
//! path once, without following a symlink or blocking on a FIFO, and accept
//! the descriptor only when it is a regular file of the expected length.
//! Source writes `source.ready`
//! after seeing an empty channel; target waits for that latch before it
//! publishes an offer. A leftover offer from a crashed attempt is refused
//! instead of being answered with the seed.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::MigrateError;
use crate::handoff::{OFFER_LEN, RECEIPT_LEN, TRANSFER_LEN};

pub const OFFER_FILE: &str = "offer.bin";
pub const ATTESTATION_FILE: &str = "attestation.bin";
pub const ENCRYPTED_SEED_FILE: &str = "encrypted_seed.bin";
pub const SOURCE_ATTESTATION_FILE: &str = "source_attestation.bin";
pub const RECEIPT_FILE: &str = "receipt.bin";
pub const RECEIPT_ATTESTATION_FILE: &str = "receipt_attestation.bin";
pub const SOURCE_READY_FILE: &str = "source.ready";

const READY_MAGIC: &[u8] = b"ZNS_MIGRATE_READY_V1";
const ATTESTATION_MAX: usize = 4096;
const POLL: Duration = Duration::from_millis(20);

const PROTOCOL_FILES: &[&str] = &[
    OFFER_FILE,
    ATTESTATION_FILE,
    ENCRYPTED_SEED_FILE,
    SOURCE_ATTESTATION_FILE,
    RECEIPT_FILE,
    RECEIPT_ATTESTATION_FILE,
];

pub struct DirTransport {
    dir: PathBuf,
    timeout: Duration,
}

impl DirTransport {
    pub fn open(dir: &Path, timeout: Duration) -> Result<Self, MigrateError> {
        if timeout.is_zero() {
            return Err(MigrateError::transport("timeout must be non-zero"));
        }
        match fs::symlink_metadata(dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(MigrateError::transport(format!(
                    "{} is a symlink",
                    dir.display()
                )));
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(MigrateError::transport(format!(
                    "{} is not a directory",
                    dir.display()
                )));
            }
            Ok(_) => {}
            Err(error) => {
                return Err(MigrateError::io(format!("open {}", dir.display()), error));
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            timeout,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Source latch. Fails if this channel was already used.
    pub fn source_begin(&self) -> Result<(), MigrateError> {
        self.refuse_existing(PROTOCOL_FILES)?;
        self.refuse_existing(&[SOURCE_READY_FILE])?;
        self.write_new(SOURCE_READY_FILE, READY_MAGIC)
    }

    /// Target latch. Waits until the source of this attempt is watching.
    pub fn target_begin(&self) -> Result<(), MigrateError> {
        self.refuse_existing(PROTOCOL_FILES)?;
        let ready = self.wait_file(
            SOURCE_READY_FILE,
            Some(READY_MAGIC.len()),
            READY_MAGIC.len(),
        )?;
        if ready != READY_MAGIC {
            return Err(MigrateError::transport(
                "source.ready does not belong to this protocol",
            ));
        }
        Ok(())
    }

    pub fn publish_offer(&self, bytes: &[u8]) -> Result<(), MigrateError> {
        exact("offer", bytes, OFFER_LEN)?;
        self.write_new(OFFER_FILE, bytes)
    }

    pub fn wait_offer(&self) -> Result<Vec<u8>, MigrateError> {
        self.wait_file(OFFER_FILE, Some(OFFER_LEN), OFFER_LEN)
    }

    pub fn publish_attestation(&self, bytes: &[u8]) -> Result<(), MigrateError> {
        bounded_attestation(bytes)?;
        self.write_new(ATTESTATION_FILE, bytes)
    }

    pub fn wait_attestation(&self) -> Result<Vec<u8>, MigrateError> {
        self.wait_file(ATTESTATION_FILE, None, ATTESTATION_MAX)
    }

    pub fn publish_encrypted_seed(&self, bytes: &[u8]) -> Result<(), MigrateError> {
        exact("encrypted seed", bytes, TRANSFER_LEN)?;
        self.write_new(ENCRYPTED_SEED_FILE, bytes)
    }

    pub fn publish_source_attestation(&self, bytes: &[u8]) -> Result<(), MigrateError> {
        bounded_attestation(bytes)?;
        self.write_new(SOURCE_ATTESTATION_FILE, bytes)
    }

    pub fn wait_source_attestation(&self) -> Result<Vec<u8>, MigrateError> {
        self.wait_file(SOURCE_ATTESTATION_FILE, None, ATTESTATION_MAX)
    }

    pub fn wait_encrypted_seed(&self) -> Result<Vec<u8>, MigrateError> {
        self.wait_file(ENCRYPTED_SEED_FILE, Some(TRANSFER_LEN), TRANSFER_LEN)
    }

    pub fn publish_receipt(&self, bytes: &[u8]) -> Result<(), MigrateError> {
        exact("receipt", bytes, RECEIPT_LEN)?;
        self.write_new(RECEIPT_FILE, bytes)
    }

    pub fn wait_receipt(&self) -> Result<Vec<u8>, MigrateError> {
        self.wait_file(RECEIPT_FILE, Some(RECEIPT_LEN), RECEIPT_LEN)
    }

    pub fn publish_receipt_attestation(&self, bytes: &[u8]) -> Result<(), MigrateError> {
        bounded_attestation(bytes)?;
        self.write_new(RECEIPT_ATTESTATION_FILE, bytes)
    }

    pub fn wait_receipt_attestation(&self) -> Result<Vec<u8>, MigrateError> {
        self.wait_file(RECEIPT_ATTESTATION_FILE, None, ATTESTATION_MAX)
    }

    fn refuse_existing(&self, names: &[&str]) -> Result<(), MigrateError> {
        for name in names {
            match fs::symlink_metadata(self.dir.join(name)) {
                Ok(_) => {
                    return Err(MigrateError::transport(format!(
                        "{} already contains {name}; use a fresh directory",
                        self.dir.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(MigrateError::io(format!("inspect {name}"), error));
                }
            }
        }
        Ok(())
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), MigrateError> {
        let dest = self.dir.join(name);
        match fs::symlink_metadata(&dest) {
            Ok(_) => {
                return Err(MigrateError::transport(format!(
                    "{} already exists",
                    dest.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(MigrateError::io(
                    format!("inspect {}", dest.display()),
                    error,
                ))
            }
        }
        let tmp = self.dir.join(format!(".{name}.{}.tmp", std::process::id()));
        let write_result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|error| MigrateError::io(format!("create {}", tmp.display()), error))?;
            file.write_all(bytes)
                .map_err(|error| MigrateError::io(format!("write {}", tmp.display()), error))?;
            file.sync_all()
                .map_err(|error| MigrateError::io(format!("sync {}", tmp.display()), error))?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
        fs::rename(&tmp, &dest).map_err(|error| {
            let _ = fs::remove_file(&tmp);
            MigrateError::io(
                format!("rename {} to {}", tmp.display(), dest.display()),
                error,
            )
        })?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    fn wait_file(
        &self,
        name: &str,
        exact: Option<usize>,
        max: usize,
    ) -> Result<Vec<u8>, MigrateError> {
        let path = self.dir.join(name);
        let deadline = Instant::now() + self.timeout;
        loop {
            match open_channel_file(&path)? {
                Some(file) => return read_bounded(file, &path, exact, max),
                None => {
                    if Instant::now() >= deadline {
                        return Err(MigrateError::transport(format!(
                            "timed out waiting for {name}"
                        )));
                    }
                    thread::sleep(POLL);
                }
            }
        }
    }
}

fn bounded_attestation(bytes: &[u8]) -> Result<(), MigrateError> {
    if bytes.is_empty() || bytes.len() > ATTESTATION_MAX {
        return Err(MigrateError::transport(format!(
            "attestation is {} bytes",
            bytes.len()
        )));
    }
    Ok(())
}

fn exact(label: &str, bytes: &[u8], len: usize) -> Result<(), MigrateError> {
    if bytes.len() == len {
        Ok(())
    } else {
        Err(MigrateError::transport(format!(
            "{label} is {} bytes, expected {len}",
            bytes.len()
        )))
    }
}

/// Open `path` and keep that descriptor. A later replacement of the directory
/// entry cannot turn this read into a symlink or a FIFO.
fn open_channel_file(path: &Path) -> Result<Option<File>, MigrateError> {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path);
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(MigrateError::transport(format!(
                "{} is a symlink",
                path.display()
            )));
        }
        Err(error) => {
            return Err(MigrateError::io(format!("open {}", path.display()), error));
        }
    };
    let meta = file
        .metadata()
        .map_err(|error| MigrateError::io(format!("stat {}", path.display()), error))?;
    if !meta.is_file() {
        return Err(MigrateError::transport(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(Some(file))
}

fn read_bounded(
    file: File,
    path: &Path,
    exact: Option<usize>,
    max: usize,
) -> Result<Vec<u8>, MigrateError> {
    let mut limited = file.take((max as u64).saturating_add(1));
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|error| MigrateError::io(format!("read {}", path.display()), error))?;
    if let Some(len) = exact {
        if buf.len() != len {
            return Err(MigrateError::transport(format!(
                "{} is {} bytes, expected {len}",
                path.display(),
                buf.len()
            )));
        }
    } else if buf.is_empty() || buf.len() > max {
        return Err(MigrateError::transport(format!(
            "{} is {} bytes",
            path.display(),
            buf.len()
        )));
    }
    Ok(buf)
}

fn sync_dir(dir: &Path) -> Result<(), MigrateError> {
    File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(|error| MigrateError::io(format!("sync {}", dir.display()), error))
}

/// The capsule is trusted state. It must not be one of the channel files.
pub fn capsule_outside_transport(capsule: &Path, transport_dir: &Path) -> Result<(), MigrateError> {
    trusted_outside_transport(capsule, transport_dir, "capsule")?;
    let name = capsule.file_name().ok_or_else(|| {
        MigrateError::transport(format!("{} has no file name", capsule.display()))
    })?;
    if PROTOCOL_FILES.contains(&name.to_str().unwrap_or("")) || name == SOURCE_READY_FILE {
        return Err(MigrateError::transport(format!(
            "capsule file name {} is reserved by the transport",
            name.to_string_lossy()
        )));
    }
    Ok(())
}

/// A file the operator mounts in. It must not live in the channel directory.
pub fn trusted_outside_transport(
    path: &Path,
    transport_dir: &Path,
    kind: &str,
) -> Result<(), MigrateError> {
    let transport = fs::canonicalize(transport_dir).map_err(|error| {
        MigrateError::io(format!("canonicalize {}", transport_dir.display()), error)
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        return Err(MigrateError::transport(format!(
            "{kind} directory {} does not exist",
            parent.display()
        )));
    }
    let parent = fs::canonicalize(parent)
        .map_err(|error| MigrateError::io(format!("canonicalize {}", parent.display()), error))?;
    let name = path
        .file_name()
        .ok_or_else(|| MigrateError::transport(format!("{} has no file name", path.display())))?;
    let full = parent.join(name);
    if full.starts_with(&transport) {
        return Err(MigrateError::transport(format!(
            "{kind} {} is inside the transport directory",
            path.display()
        )));
    }
    Ok(())
}

pub fn require_regular_file(path: &Path) -> Result<(), MigrateError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(MigrateError::transport(format!(
            "{} is a symlink",
            path.display()
        ))),
        Ok(meta) if meta.is_file() => Ok(()),
        Ok(_) => Err(MigrateError::transport(format!(
            "{} is not a file",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(MigrateError::transport(
            format!("{} does not exist", path.display()),
        )),
        Err(error) => Err(MigrateError::io(
            format!("inspect {}", path.display()),
            error,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zns-migrate-transport-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn offer_roundtrip_and_timeout() {
        let dir = scratch("round");
        let transport = DirTransport::open(&dir, Duration::from_millis(80)).unwrap();
        let err = transport.wait_offer().unwrap_err();
        assert!(err.to_string().contains("timed out waiting for offer.bin"));

        let bytes = vec![7u8; OFFER_LEN];
        transport.publish_offer(&bytes).unwrap();
        assert_eq!(transport.wait_offer().unwrap(), bytes);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_offer_and_symlink_are_refused() {
        let dir = scratch("stale");
        let transport = DirTransport::open(&dir, Duration::from_millis(50)).unwrap();
        fs::write(dir.join(OFFER_FILE), [1u8; OFFER_LEN]).unwrap();
        let err = transport.source_begin().unwrap_err();
        assert!(err.to_string().contains("already contains offer.bin"));

        let other = scratch("link");
        let transport = DirTransport::open(&other, Duration::from_millis(50)).unwrap();
        std::os::unix::fs::symlink(dir.join(OFFER_FILE), other.join(OFFER_FILE)).unwrap();
        let err = transport.wait_offer().unwrap_err();
        assert!(err.to_string().contains("symlink"));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&other);
    }

    #[test]
    fn a_fifo_does_not_block_past_the_open() {
        let dir = scratch("fifo");
        let offer = dir.join(OFFER_FILE);
        let status = std::process::Command::new("mkfifo")
            .arg(&offer)
            .status()
            .expect("mkfifo");
        assert!(status.success());
        let transport = DirTransport::open(&dir, Duration::from_secs(30)).unwrap();
        let started = Instant::now();
        let err = transport.wait_offer().unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "open blocked for {:?}",
            started.elapsed()
        );
        assert!(err.to_string().contains("not a regular file"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserved_names_apply_to_capsules_only() {
        let root = scratch("names");
        let channel = root.join("channel");
        let state = root.join("state");
        fs::create_dir(&channel).unwrap();
        fs::create_dir(&state).unwrap();
        let named = state.join(ATTESTATION_FILE);
        let err = capsule_outside_transport(&named, &channel).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
        trusted_outside_transport(&named, &channel, "attestation bundle").unwrap();
        let inside = channel.join("upgrade.bin");
        let err = trusted_outside_transport(&inside, &channel, "upgrade document").unwrap_err();
        assert!(err.to_string().contains("inside"), "{err}");
        let _ = fs::remove_dir_all(&root);
    }
}
