//! `zns-mintd` — the ZNS minting daemon.
//!
//! Boot-and-run-forever: load config, construct the [`Registry`], run subsystems
//! (scanner → minter → broadcaster, plus auth-gc and the RPC control plane)
//! under a supervision tree until SIGTERM. No CLI — config comes from a file +
//! `ZNS_*` env. The supervision tree (`tokio-graceful-shutdown`) and control
//! plane (`jsonrpsee`) are wired as those subsystems land; this is the scaffold.

use zns_host::Registry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: load config (`config` crate: file + ZNS_* env), init tracing+metrics.
    let _registry = Registry::new("zns-mint.sqlite", "http://127.0.0.1:9067")?;

    // TODO: under tokio-graceful-shutdown, spawn:
    //   scanner   — view-key chain + mempool reader (custom librustzcash + shardtree)
    //   minter    — build bundle, request signature over the signer boundary
    //   broadcast — tonic → zebrad, with tower timeout/retry
    //   auth-gc   — OTP session expiry
    //   rpc       — jsonrpsee status / rescan / mempool
    eprintln!("zns-mintd: scaffold up — subsystems not yet wired");
    Ok(())
}
