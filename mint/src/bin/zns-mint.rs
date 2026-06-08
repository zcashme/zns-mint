//! `zns-mint` — the ZNS minting daemon.
//!
//! Boot-and-run-forever: load config, construct the [`Registry`], then poll
//! lightwalletd for incoming notes and dispatch each through the registry
//! (CLAIM mints immediately; UPDATE/RELEASE issue + relay an OTP challenge;
//! confirm notes complete the mint). No CLI — config comes from a file +
//! `ZNS_*` env. A `tokio-graceful-shutdown` supervision tree and a `jsonrpsee`
//! control plane land on top of this loop; this is the intake→dispatch core.

use std::time::Duration;

use zns_mint::{scan_incoming_all, MintContext, ProcessResult, Registry, ScannerConfig};

/// How often to poll lightwalletd for new blocks.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: load from the `config` crate (file + ZNS_* env), init tracing+metrics.
    let cfg = DaemonConfig::placeholder();

    let registry = Registry::new(&cfg.db_path, &cfg.lwd_url)?;
    let scanner = cfg.scanner();
    let ctx = cfg.mint_context()?;

    eprintln!(
        "zns-mint: polling {} every {}s (db: {})",
        cfg.lwd_url,
        POLL_INTERVAL.as_secs(),
        cfg.db_path,
    );

    let mut tick = tokio::time::interval(POLL_INTERVAL);
    loop {
        tick.tick().await;

        let notes = match scan_incoming_all(&scanner).await {
            Ok(notes) => notes,
            Err(e) => {
                eprintln!("zns-mint: scan error: {e:#}");
                continue; // transient — retry on the next tick
            }
        };
        if notes.is_empty() {
            continue;
        }

        for result in registry.process_notes(&notes, &ctx).await {
            match result {
                ProcessResult::Ok(outcome) => eprintln!("zns-mint: {outcome:?}"),
                ProcessResult::Skipped(why) => eprintln!("zns-mint: skipped ({why})"),
                ProcessResult::Err(name, err) => {
                    eprintln!("zns-mint: error on '{name}': {err}")
                }
            }
        }
    }
}

/// Daemon configuration. Currently hard-coded placeholders; the `config` crate
/// (file + `ZNS_*` env) populates this at boot.
struct DaemonConfig {
    db_path: String,
    lwd_url: String,
    ufvk: String,
    network: zcash_protocol::consensus::Network,
    birthday: u32,
}

impl DaemonConfig {
    fn placeholder() -> Self {
        Self {
            db_path: "zns-mint.sqlite".into(),
            lwd_url: "http://127.0.0.1:9067".into(),
            ufvk: String::new(),
            network: zcash_protocol::consensus::Network::MainNetwork,
            birthday: 0,
        }
    }

    fn scanner(&self) -> ScannerConfig {
        ScannerConfig {
            ufvk: self.ufvk.clone(),
            network: self.network,
            birthday: self.birthday,
            lwd_url: self.lwd_url.clone(),
        }
    }

    /// Build the Orchard key material the registry mints under.
    ///
    /// TODO: derive the registry FVK + recipient from the configured spend seed
    /// (over the signer boundary), and source the anchor + tip height from the
    /// scanner's note-state DB rather than the empty-tree default.
    fn mint_context(&self) -> anyhow::Result<MintContext> {
        anyhow::bail!("mint_context: registry key material not configured yet")
    }
}
