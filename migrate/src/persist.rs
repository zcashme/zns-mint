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
    stage_mode(dest, bytes, 0o600)
}

/// Write `bytes` to a temporary sibling of `dest`. The caller links it into
/// place with [`commit_files`].
pub fn stage_file(dest: &Path, bytes: &[u8], mode: u32) -> Result<StagedCapsule, MigrateError> {
    stage_mode(dest, bytes, mode)
}

struct Placed {
    dest: PathBuf,
    backup: Option<PathBuf>,
}

/// Link every staged file into place. A failure removes the files this call
/// created and restores anything `--replace` had moved aside.
pub fn commit_files(
    files: Vec<(StagedCapsule, PathBuf)>,
    replace: bool,
) -> Result<(), MigrateError> {
    for (_, dest) in &files {
        guard_output(dest, replace)?;
    }
    let mut placed = Vec::new();
    for (staged, dest) in files {
        let backup = match relocate_existing(&dest, replace) {
            Ok(backup) => backup,
            Err(error) => {
                return finish_rollback(error, &placed);
            }
        };
        if let Err(error) = staged.install(&dest, false) {
            if let Some(backup) = backup {
                if let Err(restore_error) = restore(&dest, &backup) {
                    return Err(rollback_error(error, restore_error));
                }
            }
            return finish_rollback(error, &placed);
        }
        placed.push(Placed { dest, backup });
    }
    for item in &placed {
        if let Some(backup) = &item.backup {
            let _ = fs::remove_file(backup);
        }
    }
    Ok(())
}

fn finish_rollback(error: MigrateError, placed: &[Placed]) -> Result<(), MigrateError> {
    if let Err(undo_error) = undo(placed) {
        return Err(rollback_error(error, undo_error));
    }
    Err(error)
}

fn rollback_error(error: MigrateError, undo_error: MigrateError) -> MigrateError {
    MigrateError::transport(format!("{error}; rollback failed: {undo_error}"))
}

fn relocate_existing(dest: &Path, replace: bool) -> Result<Option<PathBuf>, MigrateError> {
    if !replace {
        return Ok(None);
    }
    match fs::symlink_metadata(dest) {
        Ok(meta) if meta.is_file() => {
            let backup = backup_path(dest);
            fs::rename(dest, &backup).map_err(|error| {
                MigrateError::io(
                    format!("rename {} to {}", dest.display(), backup.display()),
                    error,
                )
            })?;
            Ok(Some(backup))
        }
        Ok(_) => Err(MigrateError::transport(format!(
            "{} is not a file",
            dest.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(MigrateError::io(
            format!("inspect {}", dest.display()),
            error,
        )),
    }
}

fn restore(dest: &Path, backup: &Path) -> Result<(), MigrateError> {
    fs::rename(backup, dest).map_err(|error| {
        MigrateError::io(
            format!("restore {} from {}", dest.display(), backup.display()),
            error,
        )
    })?;
    sync_parent(dest)
}

fn undo(placed: &[Placed]) -> Result<(), MigrateError> {
    for item in placed.iter().rev() {
        fs::remove_file(&item.dest)
            .map_err(|error| MigrateError::io(format!("remove {}", item.dest.display()), error))?;
        if let Some(backup) = &item.backup {
            restore(&item.dest, backup)?;
        } else {
            sync_parent(&item.dest)?;
        }
    }
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    let mut backup = path.as_os_str().to_os_string();
    backup.push(format!(".{}.bak", std::process::id()));
    PathBuf::from(backup)
}

fn stage_mode(dest: &Path, bytes: &[u8], mode: u32) -> Result<StagedCapsule, MigrateError> {
    let temp = temp_sibling(dest);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
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

/// Directory that holds `path`. The parent of a bare relative filename is
/// empty, and that names the current directory.
pub fn containing_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn sync_parent(path: &Path) -> Result<(), MigrateError> {
    let parent = containing_dir(path);
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| MigrateError::io(format!("sync {}", parent.display()), error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zns-migrate-persist-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_bare_filename_is_in_the_current_directory() {
        assert_eq!(
            containing_dir(Path::new("zns_seed.capsule")),
            Path::new(".")
        );
        assert_eq!(
            containing_dir(Path::new("keys/zns_seed.capsule")),
            Path::new("keys")
        );
    }

    #[test]
    fn commit_files_links_every_staged_file() {
        let root = scratch("commit");
        let capsule = root.join("zns_seed.capsule");
        let mint = root.join("zns_mint.conf");
        let staged_capsule = stage(&capsule, b"capsule").unwrap();
        let staged_mint = stage_file(&mint, b"mint", 0o644).unwrap();
        commit_files(
            vec![
                (staged_capsule, capsule.clone()),
                (staged_mint, mint.clone()),
            ],
            false,
        )
        .unwrap();
        assert_eq!(fs::read(&capsule).unwrap(), b"capsule");
        assert_eq!(fs::read(&mint).unwrap(), b"mint");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_install_leaves_no_new_files() {
        let root = scratch("rollback");
        let keys = root.join("keys");
        let blocked = root.join("blocked");
        fs::create_dir(&keys).unwrap();
        fs::create_dir(&blocked).unwrap();
        let capsule = keys.join("zns_seed.capsule");
        let mint = blocked.join("zns_mint.conf");
        let staged_capsule = stage(&capsule, b"new-capsule").unwrap();
        let staged_mint = stage_file(&mint, b"network = test", 0o600).unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o555)).unwrap();
        let err = commit_files(
            vec![
                (staged_capsule, capsule.clone()),
                (staged_mint, mint.clone()),
            ],
            false,
        )
        .unwrap_err();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!capsule.exists(), "{err}");
        assert!(!mint.exists(), "{err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_replace_restores_the_previous_file() {
        let root = scratch("replace");
        let keys = root.join("keys");
        let blocked = root.join("blocked");
        fs::create_dir(&keys).unwrap();
        fs::create_dir(&blocked).unwrap();
        let capsule = keys.join("zns_seed.capsule");
        fs::write(&capsule, b"old-capsule").unwrap();
        let mint = blocked.join("zns_mint.conf");
        let staged_capsule = stage(&capsule, b"new-capsule").unwrap();
        let staged_mint = stage_file(&mint, b"network = test", 0o600).unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o555)).unwrap();
        let err = commit_files(
            vec![(staged_capsule, capsule.clone()), (staged_mint, mint)],
            true,
        )
        .unwrap_err();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(fs::read(&capsule).unwrap(), b"old-capsule", "{err}");
        let leftover = fs::read_dir(&keys).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".bak")
        });
        assert!(!leftover, "{err}");
        let _ = fs::remove_dir_all(&root);
    }
}
