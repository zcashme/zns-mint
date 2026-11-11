//! Locate sibling checkouts and on-disk binaries.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Directory of this crate (`integration-tests/`).
pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The workspace root: zns-mint builds here, into `target/`.
pub fn repo_root() -> PathBuf {
    crate_dir().join("..")
}

/// `$<env_var>` if it points at a file, else `name` on `$PATH`.
pub fn resolve_bin(env_var: &str, name: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_var) {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    which(name)
}

pub fn zebrad_bin() -> Option<PathBuf> {
    resolve_bin("ZEBRAD_BIN", "zebrad")
}

pub fn mint_bin_override() -> Option<PathBuf> {
    resolve_bin("ZNS_MINT_BIN", "zns-mint")
}

/// The `zallet` binary: a backend binary (`zallet-zebra`), which shares
/// zallet's full CLI surface.
pub fn zallet_bin() -> Option<PathBuf> {
    resolve_bin("ZALLET_BIN", "zallet-zebra")
}

fn which(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
    })
}

/// `cargo <cargo_flags> build --bin <bin> <extra_args>` in `dir`, returning
/// `target/debug/<bin>`.
pub fn cargo_build_bin(
    dir: &Path,
    bin: &str,
    extra_args: &[&str],
    cargo_flags: &[&str],
) -> Result<PathBuf> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let mut cmd = Command::new("cargo");
    cmd.current_dir(dir)
        .args(cargo_flags)
        .arg("build")
        .arg("--bin")
        .arg(bin)
        .args(extra_args);
    let status = cmd
        .status()
        .with_context(|| format!("spawn cargo build for {bin} in {}", dir.display()))?;
    if !status.success() {
        bail!(
            "cargo build --bin {bin} failed in {} ({status})",
            dir.display()
        );
    }
    let path = dir.join("target/debug").join(bin);
    if !path.is_file() {
        bail!("cargo build succeeded but {} is missing", path.display());
    }
    Ok(path)
}
