//! Install a capsule without leaving a short file in its place.
//!
//! The bytes are synced to a temporary sibling first. The caller reopens that
//! sibling and unseals it before this module links the sibling into the final
//! name. `--replace-after-verified-migration` is the only path that renames
//! over an existing regular file.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::MigrateError;

pub struct StagedCapsule {
    temp: PathBuf,
}

impl StagedCapsule {
    pub fn path(&self) -> &Path {
        &self.temp
    }

    pub fn install(self, dest: &Path, replace: bool) -> Result<(), MigrateError> {
        match fs::symlink_metadata(dest) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(MigrateError::transport(format!(
                    "{} is a symlink",
                    dest.display()
                )));
            }
            Ok(meta) if !meta.is_file() => {
                return Err(MigrateError::transport(format!(
                    "{} is not a file",
                    dest.display()
                )));
            }
            Ok(_) if !replace => {
                return Err(MigrateError::transport(format!(
                    "{} already exists; pass --replace-after-verified-migration to overwrite it",
                    dest.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(MigrateError::io(
                    format!("inspect {}", dest.display()),
                    error,
                ));
            }
        }

        if replace {
            fs::rename(&self.temp, dest).map_err(|error| {
                MigrateError::io(
                    format!("rename {} to {}", self.temp.display(), dest.display()),
                    error,
                )
            })?;
        } else {
            fs::hard_link(&self.temp, dest).map_err(|error| {
                MigrateError::io(
                    format!("link {} to {}", self.temp.display(), dest.display()),
                    error,
                )
            })?;
            let _ = fs::remove_file(&self.temp);
        }
        sync_parent(dest)?;
        Ok(())
    }
}

impl Drop for StagedCapsule {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temp);
    }
}

pub fn stage(dest: &Path, bytes: &[u8]) -> Result<StagedCapsule, MigrateError> {
    let temp = temp_sibling(dest);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| MigrateError::io(format!("create {}", temp.display()), error))?;
    let write = (|| {
        file.write_all(bytes)
            .map_err(|error| MigrateError::io(format!("write {}", temp.display()), error))?;
        file.sync_all()
            .map_err(|error| MigrateError::io(format!("sync {}", temp.display()), error))?;
        Ok(())
    })();
    if let Err(error) = write {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    Ok(StagedCapsule { temp })
}

/// Refuse to start a target that would destroy an existing capsule by typo.
pub fn guard_output(path: &Path, replace: bool) -> Result<(), MigrateError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(MigrateError::transport(format!(
            "{} is a symlink",
            path.display()
        ))),
        Ok(meta) if !meta.is_file() => Err(MigrateError::transport(format!(
            "{} is not a file",
            path.display()
        ))),
        Ok(_) if !replace => Err(MigrateError::transport(format!(
            "{} already exists; pass --replace-after-verified-migration to overwrite it",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(MigrateError::io(
            format!("inspect {}", path.display()),
            error,
        )),
    }
}

fn temp_sibling(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(tmp)
}

fn sync_parent(path: &Path) -> Result<(), MigrateError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| MigrateError::io(format!("sync {}", parent.display()), error))
}
