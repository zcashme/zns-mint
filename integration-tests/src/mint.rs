//! Spawn `zns-mint` built with `--features regtest` — the local
//! spawner, so the harness owns the whole `keys/` contract it feeds the
//! mint: capsule, conf, and custody manifest.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tempfile::TempDir;

use crate::child::ChildProcess;

/// Halo2 in a debug mint binary is too slow for the vault sweep. Regtest
/// selects non-tee, which release builds refuse, so raise opt-level on
/// the proving crates.
const MINT_DEV_OPT: &[&str] = &[
    "--config",
    "profile.dev.package.orchard.opt-level=3",
    "--config",
    "profile.dev.package.halo2_proofs.opt-level=3",
    "--config",
    "profile.dev.package.halo2_gadgets.opt-level=3",
];

pub struct Mint {
    child: ChildProcess,
    _dir: TempDir,
}

impl Mint {
    /// Build (unless `ZNS_MINT_BIN` is set) the regtest mint binary.
    pub fn build() -> Result<PathBuf> {
        if let Some(bin) = std::env::var_os("ZNS_MINT_BIN") {
            let bin = PathBuf::from(bin);
            if bin.is_file() {
                return Ok(bin);
            }
            bail!("ZNS_MINT_BIN is set but is not a file: {}", bin.display());
        }
        // This crate lives at <mint root>/integration-tests.
        let mint_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let status = Command::new("cargo")
            .current_dir(&mint_dir)
            .args(MINT_DEV_OPT)
            .args([
                "build",
                "--locked",
                "--bin",
                "zns-mint",
                "--features",
                "regtest",
            ])
            .status()
            .context("spawn cargo build for zns-mint")?;
        if !status.success() {
            bail!("cargo build zns-mint failed ({status})");
        }
        Ok(mint_dir.join("target/debug/zns-mint"))
    }

    /// `birthday` is the ceremony tip and `txid` the anchor it mined;
    /// both land in the mint's `keys/` contract.
    pub fn start(bin: PathBuf, birthday: u32, txid: &str) -> Result<Self> {
        let dir = tempfile::tempdir().context("create mint dir")?;
        let keys = dir.path().join("keys");
        // The dev keys/ contract, one writer.
        zns_canon::regtest::write_dev_keys(&keys, birthday).context("write dev keys/")?;
        // The custody manifest boot verifies against the chain.
        std::fs::write(
            keys.join("zns_custody_manifest.toml"),
            format!("anchor_txid = \"{txid}\"\nbirthday = {birthday}\n"),
        )
        .context("write custody manifest")?;

        let log = dir.path().join("mint.stderr");
        let file = std::fs::File::create(&log).context("create mint.stderr")?;
        let file2 = file.try_clone().context("clone mint.stderr")?;

        let child = Command::new(&bin)
            .current_dir(dir.path())
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "zns_mint=debug".into()),
            )
            .stdout(Stdio::from(file))
            .stderr(Stdio::from(file2))
            .spawn()
            .context("spawn zns-mint")?;

        Ok(Self {
            child: ChildProcess::new("mint", child, Some(log)),
            _dir: dir,
        })
    }

    pub fn is_running(&mut self) -> bool {
        self.child.is_running()
    }

    pub fn log_text(&self) -> String {
        self.child.log_text()
    }

    pub fn exit_detail(&self) -> String {
        self.child.exit_detail()
    }

    /// Boot finished and the run loop is waiting for tips (`live_from` is set).
    pub async fn wait_until_live(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            let log = self.log_text();
            if log.contains("mint awaiting Zebra tips") {
                return Ok(());
            }
            if log.contains("FATAL") {
                bail!("mint fatal during boot:\n{}", self.exit_detail());
            }
            if !self.is_running() {
                bail!("mint exited before becoming live:\n{}", self.exit_detail());
            }
            if Instant::now() >= deadline {
                bail!(
                    "mint did not reach run loop within 300s:\n{}",
                    self.exit_detail()
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
