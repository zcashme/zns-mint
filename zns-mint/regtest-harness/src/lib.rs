use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

/// Pick an unused loopback TCP port (bind `:0`, read the port, release it).
pub fn pick_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

/// Resolve a required external binary from `$<env_var>`, returning `None` if unset.
pub fn resolve_bin(env_var: &str) -> Option<PathBuf> {
    std::env::var(env_var)
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

// =============================== zebrad (Regtest validator) ===============================

const NU6_2_ACTIVATION_HEIGHT: u32 = 4;
const LOCKBOX_DISBURSEMENT_ADDR: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const LOCKBOX_DISBURSEMENT_ZATS: u64 = 1;

/// A throwaway transparent address used as zebra's coinbase recipient if needed.
const DEFAULT_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";

/// A running `zebrad` Regtest node.
pub struct Zebrad {
    child: Child,
    pub rpc_port: u16,
    pub indexer_port: u16,
    net_port: u16,
    bin: PathBuf,
    config_path: PathBuf,
    _dir: tempfile::TempDir,
}

fn spawn_zebrad(bin: &Path, config_path: &Path) -> Result<Child> {
    let (out, err) = match std::env::var_os("ZEBRAD_STDERR") {
        Some(p) => {
            let f = std::fs::File::create(&p).context("create ZEBRAD_STDERR file")?;
            let f2 = f.try_clone().context("clone ZEBRAD_STDERR file")?;
            (Stdio::from(f), Stdio::from(f2))
        }
        None => (Stdio::null(), Stdio::null()),
    };
    let mut cmd = Command::new(bin);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("ZEBRA_") {
            cmd.env_remove(key);
        }
    }
    cmd.args(["--config", config_path.to_str().unwrap(), "start"])
        .stdout(out)
        .stderr(err)
        .spawn()
        .with_context(|| format!("spawn zebrad ({})", bin.display()))
}

impl Zebrad {
    /// Launch `zebrad` in Regtest mode on fixed ports to match `zns-mint`'s hardcoded URLs.
    pub async fn start(bin: &Path) -> Result<Zebrad> {
        Self::start_with_miner(bin, DEFAULT_MINER_ADDRESS).await
    }

    pub async fn start_with_miner(bin: &Path, miner_address: &str) -> Result<Zebrad> {
        let dir = tempfile::tempdir().context("create zebrad dir")?;
        // For zns-mint, we use the hardcoded ports it expects.
        let rpc_port = 8232;
        let indexer_port = 8230;
        let net_port = pick_port()?;
        let config_path = dir.path().join("zebrad.toml");
        let cache_dir = dir.path().join("state");
        std::fs::write(
            &config_path,
            zebrad_toml(
                net_port,
                rpc_port,
                indexer_port,
                miner_address,
                &cache_dir.to_string_lossy(),
            ),
        )
        .context("write zebrad.toml")?;
        let child = spawn_zebrad(bin, &config_path)?;
        let mut zebrad = Zebrad {
            child,
            rpc_port,
            indexer_port,
            net_port,
            bin: bin.to_path_buf(),
            config_path,
            _dir: dir,
        };
        zebrad.wait_until_rpc_up().await?;
        Ok(zebrad)
    }

    pub async fn restart_with_miner(&mut self, miner_address: &str) -> Result<()> {
        let _ = self.rpc("stop", serde_json::json!([])).await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        let cache_dir = self._dir.path().join("state");
        std::fs::write(
            &self.config_path,
            zebrad_toml(
                self.net_port,
                self.rpc_port,
                self.indexer_port,
                miner_address,
                &cache_dir.to_string_lossy(),
            ),
        )
        .context("rewrite zebrad.toml for restart")?;
        self.child = spawn_zebrad(&self.bin, &self.config_path)?;
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.rpc_port)
    }

    async fn wait_until_rpc_up(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut last_err = anyhow!("no getblocktemplate attempt completed");
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                bail!("zebrad exited during startup ({status})");
            }
            match self.rpc("getblocktemplate", json!([])).await {
                Ok(_) => return Ok(()),
                Err(e) => last_err = anyhow!("{e}"),
            }
            if Instant::now() >= deadline {
                bail!("zebrad did not become mineable within 120s; last error: {last_err:#}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = reqwest::Client::new()
            .post(self.rpc_url())
            .json(&body)
            .send()
            .await
            .context("zebra rpc request")?;
        let envelope: Value = resp.json().await.context("decode zebra rpc response")?;
        if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
            bail!("zebra rpc error from {method}: {err}");
        }
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn generate_blocks(&self, n: u32) -> Result<()> {
        let hashes = self.rpc("generate", json!([n])).await.context("generate")?;
        let mined = hashes.as_array().map(|a| a.len()).unwrap_or(0);
        if mined != n as usize {
            bail!("generate mined {mined} of {n} requested blocks: {hashes}");
        }
        Ok(())
    }
}

impl Drop for Zebrad {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn zebrad_toml(net_port: u16, rpc_port: u16, indexer_port: u16, miner_address: &str, cache_dir: &str) -> String {
    let nu6_2 = NU6_2_ACTIVATION_HEIGHT;
    let lockbox_addr = LOCKBOX_DISBURSEMENT_ADDR;
    let lockbox_amount = LOCKBOX_DISBURSEMENT_ZATS;
    format!(
        r#"[network]
network = "Regtest"
listen_addr = "127.0.0.1:{net_port}"

[network.testnet_parameters]
disable_pow = true

[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1
"NU6.1" = {nu6_2}
"NU6.2" = {nu6_2}
"NU6.3" = {nu6_2}

[[network.testnet_parameters.funding_streams]]
[network.testnet_parameters.funding_streams.height_range]
start = 1
end = 1_000_000
[[network.testnet_parameters.funding_streams.recipients]]
receiver = "Deferred"
numerator = 12
addresses = []

[[network.testnet_parameters.lockbox_disbursements]]
address = "{lockbox_addr}"
amount = {lockbox_amount}

[mining]
miner_address = "{miner_address}"

[state]
ephemeral = false
cache_dir = "{cache_dir}"

[rpc]
listen_addr = "127.0.0.1:{rpc_port}"
enable_cookie_auth = false

[indexer]
listen_addr = "127.0.0.1:{indexer_port}"
"#
    )
}

// =============================== zns-mint (the system under test) ===============================

pub fn zns_mint_bin() -> PathBuf {
    if let Ok(p) = std::env::var("ZNS_MINT_BIN") {
        return PathBuf::from(p);
    }
    
    // Automatically compile zns-mint with the required dev-seed feature
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent().unwrap();
    
    let status = Command::new("cargo")
        .current_dir(workspace_root)
        .args(["build", "--release", "--bin", "zns-mint", "--features", "dev-seed"])
        .status()
        .expect("failed to execute cargo build for zns-mint");
        
    assert!(status.success(), "cargo build --features dev-seed failed for zns-mint");

    workspace_root.join("target/release/zns-mint")
}

pub struct ZnsMint {
    child: Child,
}

impl ZnsMint {
    /// Launch the `zns-mint` daemon. It expects Zebra indexer and JSON-RPC to be on 8230 and 8232.
    pub async fn start() -> Result<ZnsMint> {
        let bin = zns_mint_bin();
        if !bin.exists() {
            bail!(
                "zns-mint binary not found at {} - build it first or set $ZNS_MINT_BIN",
                bin.display()
            );
        }

        let (out, err) = if std::env::var_os("ZNS_MINT_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };

        // Note: zns-mint strictly rejects RUST_LOG, RUST_BACKTRACE, and ZNS_ environment variables
        // during its `sanitize_environment` boot check. We must clear them from the child process.
        let mut cmd = Command::new(&bin);
        for (key, _) in std::env::vars_os() {
            let k_str = key.to_string_lossy();
            if k_str.starts_with("RUST_LOG") || k_str.starts_with("RUST_BACKTRACE") || k_str.starts_with("ZNS_") {
                cmd.env_remove(key);
            }
        }

        let mut child = cmd
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("spawn zns-mint daemon")?;

        // Wait for the mint to boot successfully by polling its Prometheus metrics.
        // It starts listening on port 9090 immediately, but `zns_mint_boot_success` is 
        // only set to 1 after the `boot::boot()` sequence finishes syncing the initial state.
        let rpc = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut booted = false;
        
        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                bail!("zns-mint exited prematurely during startup ({status})");
            }
            
            if let Ok(resp) = rpc.get("http://127.0.0.1:9090/metrics").send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains("zns_mint_boot_success 1") {
                        booted = true;
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        if !booted {
            let _ = child.kill();
            bail!("zns-mint failed to boot within 30s (zns_mint_boot_success metric not found)");
        }

        Ok(ZnsMint { child })
    }

    pub fn stop(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for ZnsMint {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// =============================== zecd (the system under test) ===============================

/// Locate the built `zecd` binary: `$ZECD_BIN` if set, else the parent crate's release build.
pub fn zecd_bin() -> PathBuf {
    if let Ok(p) = std::env::var("ZECD_BIN") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(|p| p.join("target/release/zecd"))
        .unwrap_or_else(|| PathBuf::from("zecd"))
}

/// Whether the extended ("big run") regtest tier is enabled: set `ZECD_REGTEST_EXTENDED=1`.
/// PR runs skip these tests (each spins a full zebra+lightwalletd stack); the scheduled and
/// manually dispatched workflow runs set the variable.
pub fn extended_enabled() -> bool {
    std::env::var("ZECD_REGTEST_EXTENDED").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Whether the **stress** regtest tier is enabled: set `ZECD_REGTEST_STRESS=1`. Distinct from
/// (and heavier than) the extended tier - building thousands of notes and timing multi-minute
/// sends would blow up even the weekly extended run - so it is gated separately and driven only
/// by an explicit workflow dispatch and a rare (monthly) schedule, never on push/PR.
pub fn stress_enabled() -> bool {
    std::env::var("ZECD_REGTEST_STRESS").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// How many notes the stress test should build before measuring a send, from
/// `ZECD_STRESS_NOTE_COUNT` (default 256). The dispatch can dial this from a quick smoke (a few
/// hundred) to a heavy soak (thousands) without code changes.
pub fn stress_note_count() -> usize {
    std::env::var("ZECD_STRESS_NOTE_COUNT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(256)
}

/// A running `zecd` daemon plus the HTTP client and credentials to drive it.
pub struct Zecd {
    child: Child,
    base_url: String,
    user: String,
    password: String,
    http: reqwest::Client,
    /// The default wallet's generated mnemonic, captured from `zecd init`'s stdout. `None`
    /// when the wallet was restored ([`ZecdConfig::restore_mnemonic`]) - a restore prints none.
    pub mnemonic: Option<String>,
    _datadir: tempfile::TempDir,
}

/// How `zecd` should reach the regtest chain (a local zebrad's JSON-RPC) and what RPC
/// port/creds to expose.
pub struct ZecdConfig {
    /// zebrad JSON-RPC port zecd connects to (`zebra://127.0.0.1:<port>`).
    pub zebra_rpc_port: u16,
    pub rpc_port: u16,
    pub rpc_user: String,
    pub rpc_password: String,
    /// `[sync] rebroadcast_secs` - tight by default so outage tests don't idle a minute.
    pub rebroadcast_secs: u64,
    /// Additional **spending** `[wallets.<name>]` entries beyond `default` (each gets its own
    /// `zecd init --wallet <name>` before the daemon starts). NB: zecd permits only ONE
    /// spending wallet, so configuring any of these alongside the spending `default` makes the
    /// daemon refuse to start - that refusal is what [`Zecd::start_expect_refusal`] asserts.
    pub extra_wallets: Vec<String>,
    /// Additional **watch-only** `[wallets.<name>]` entries, each created `--ufvk` from the
    /// `default` wallet's exported UFVK (a watch-only replica of the single spending wallet).
    /// Any number are allowed alongside the spending `default`.
    pub extra_watch_only_wallets: Vec<String>,
    /// Restore the default wallet from this mnemonic (`zecd init --restore`, phrase on stdin)
    /// instead of generating a fresh one.
    pub restore_mnemonic: Option<String>,
    /// Create the default wallet watch-only from this Unified Full Viewing Key
    /// (`zecd init --ufvk`) instead of a mnemonic.
    pub ufvk: Option<String>,
    /// `--birthday` for the restore/watch-only paths (a fresh init defaults near the tip on
    /// its own).
    pub birthday: Option<u32>,
    /// `[spend] cache_proving_key`: `Some(true/false)` writes the knob explicitly, `None`
    /// omits it (zecd defaults to `true`). The proving-key-cache benchmark runs one instance
    /// each way.
    pub cache_proving_key: Option<bool>,
    /// `[spend] pipeline_proving`: `Some(true/false)` writes the knob explicitly, `None` omits it
    /// (zecd defaults to `false`). The stress test runs with it on to exercise the off-actor
    /// proving pipeline (sync stays live during a send).
    pub pipeline_proving: Option<bool>,
    /// `[spend] orchard_action_limit`: `Some(n)` writes the cap (`0` disables it), `None` omits it
    /// (zecd defaults to 50). The stress test lifts the cap so its big fan-out/sweep sends aren't
    /// rejected.
    pub orchard_action_limit: Option<usize>,
    /// `[spend] privacy_policy`: `Some("AllowFullyTransparent")` etc. writes the knob explicitly,
    /// `None` omits it (zecd defaults to `AllowRevealedRecipients`). The fully-transparent spend
    /// e2e sets it to `AllowFullyTransparent`.
    pub privacy_policy: Option<String>,
    /// Optional `[pools]` section as `(enabled, default_receivers)`. `None` omits the section
    /// (the Orchard-only default). Used by the multi-pool (Sapling) e2e.
    pub pools: Option<(Vec<String>, Vec<String>)>,
    /// Write `[pools] transparent = true` so the wallet can hand out bare transparent addresses
    /// (`getnewaddress "" "transparent"`). Used by the transparent e2e. Emits a `[pools]` section
    /// even when `pools` is `None` (keeping the Orchard-only enabled default).
    pub transparent: bool,
    /// `[pools] transparent_gap_limit` - the external transparent gap limit, i.e. the
    /// stateless-restore scan depth. `None` omits it (zecd defaults to 20). Only meaningful with
    /// `transparent = true`. The transparent-gap restore e2e sets it small (a beyond-gap receive
    /// is missed) vs large (the same receive is recovered).
    pub transparent_gap_limit: Option<u32>,
    /// `[pools] transparent_initial_scan` - the initial scan depth (pre-expose + scan external
    /// indices `0..N` on startup, independent of the gap limit). `None` omits it (defaults to 0).
    /// The gap e2e uses it to prove a *small* gap plus a large initial scan still recovers a
    /// high-index receive.
    pub transparent_initial_scan: Option<u32>,
    /// `[pools] transparent_allow_beyond_recovery_window` - when `Some(false)`, `getnewaddress`
    /// fails closed once the recovery window is exhausted instead of issuing (warn-only) beyond it.
    /// `None` omits it (zecd defaults to `true`). Only meaningful with `transparent = true`.
    pub transparent_allow_beyond_recovery_window: Option<bool>,
    /// `[pools] transparent_gap_warn_threshold` - warn when fewer than this many in-window slots
    /// remain. `None` omits it (zecd defaults to 5). Only meaningful with `transparent = true`.
    pub transparent_gap_warn_threshold: Option<u32>,
    /// When `Some`, the spending `default` wallet is created passphrase-encrypted
    /// (`zecd init --encrypt`, passphrase supplied via `ZECD_WALLET_PASSPHRASE`): it starts
    /// locked and needs `walletpassphrase` before sending. `None` = unencrypted (identity model).
    pub encrypt_passphrase: Option<String>,
}

impl ZecdConfig {
    /// Test-friendly defaults: zecd points at the given zebrad JSON-RPC port, `user`/`pass`
    /// credentials, 2s rebroadcast, fast reconnect backoff (written by [`write_zecd_toml`]).
    pub fn new(zebra_rpc_port: u16, rpc_port: u16) -> ZecdConfig {
        ZecdConfig {
            zebra_rpc_port,
            rpc_port,
            rpc_user: "user".to_string(),
            rpc_password: "pass".to_string(),
            rebroadcast_secs: 2,
            extra_wallets: Vec::new(),
            extra_watch_only_wallets: Vec::new(),
            restore_mnemonic: None,
            ufvk: None,
            birthday: None,
            cache_proving_key: None,
            pipeline_proving: None,
            orchard_action_limit: None,
            privacy_policy: None,
            pools: None,
            transparent: false,
            transparent_gap_limit: None,
            transparent_initial_scan: None,
            transparent_allow_beyond_recovery_window: None,
            transparent_gap_warn_threshold: None,
            encrypt_passphrase: None,
        }
    }

    /// The `[health]` port (`/healthz`, `/readyz`, `/status`) the daemon is configured with -
    /// [`write_zecd_toml`]'s convention is the RPC port + 1.
    pub fn health_port(&self) -> u16 {
        self.rpc_port + 1
    }
}

impl Zecd {
    /// Write a regtest `zecd.toml`, run `zecd init` (retried while lightwalletd catches up to the
    /// chain tip), then spawn the daemon. Returns once the RPC is up; call
    /// [`Zecd::wait_until_synced`] to wait for the scan to reach the tip.
    pub async fn start(cfg: &ZecdConfig) -> Result<Zecd> {
        let (datadir, mnemonic) = Self::prepare_datadir(cfg).await?;

        // Set ZECD_STDERR (to any value) to stream the daemon's logs into the test output
        // (use with `--nocapture`); otherwise discard them. The daemon inherits RUST_LOG from
        // the environment, so `RUST_LOG=zecd=debug,info ZECD_STDERR=1` gives a full sync/rewind
        // trace in CI. Mirrors the ZEBRAD_STDERR hook above.
        let (out, err) = if std::env::var_os("ZECD_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        let child = Command::new(zecd_bin())
            .args([
                "--datadir",
                datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("spawn zecd daemon")?;

        let zecd = Zecd {
            child,
            base_url: format!("http://127.0.0.1:{}/", cfg.rpc_port),
            user: cfg.rpc_user.clone(),
            password: cfg.rpc_password.clone(),
            http: reqwest::Client::new(),
            mnemonic,
            _datadir: datadir,
        };

        zecd.wait_until_rpc_up().await?;
        Ok(zecd)
    }

    /// Set up a datadir with the spending `default` wallet, then attempt `zecd init --wallet
    /// <name>` for a **second spending** wallet, expecting zecd's init-time guard to refuse it
    /// (zecd allows only one spending wallet). `cfg.extra_wallets` must list `name` so the
    /// config the guard scans contains both wallets. Returns the refusal's stderr; errors if
    /// the second init unexpectedly succeeded.
    pub async fn init_second_spending_expect_refusal(
        cfg: &ZecdConfig,
        name: &str,
    ) -> Result<String> {
        let datadir = tempfile::tempdir().context("create zecd datadir")?;
        let bin = zecd_bin();
        if !bin.exists() {
            bail!(
                "zecd binary not found at {} - build it first (cargo build --release --bin zecd) \
                 or set $ZECD_BIN",
                bin.display()
            );
        }
        write_zecd_toml(datadir.path(), cfg).context("write zecd.toml")?;
        init_default_with_retry(&bin, datadir.path(), cfg).await?;

        // The guard runs before any network I/O, so this fails fast offline.
        let out = Command::new(&bin)
            .args([
                "--datadir",
                datadir.path().to_str().unwrap(),
                "--regtest",
                "init",
                "--wallet",
                name,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("spawn second zecd init")?;
        anyhow::ensure!(
            !out.status.success(),
            "zecd init of a second spending wallet was expected to fail but succeeded"
        );
        Ok(String::from_utf8_lossy(&out.stderr).into_owned())
    }

    /// Prepare a datadir: write `zecd.toml`, init the `default` wallet (retried while
    /// lightwalletd warms up), then init any watch-only replicas. (Only one spending wallet is
    /// permitted, so extra *spending* wallets are never initialised here.)
    async fn prepare_datadir(cfg: &ZecdConfig) -> Result<(tempfile::TempDir, Option<String>)> {
        let datadir = tempfile::tempdir().context("create zecd datadir")?;
        let bin = zecd_bin();
        if !bin.exists() {
            bail!(
                "zecd binary not found at {} - build it first (cargo build --release --bin zecd) \
                 or set $ZECD_BIN",
                bin.display()
            );
        }

        write_zecd_toml(datadir.path(), cfg).context("write zecd.toml")?;
        let mnemonic = init_default_with_retry(&bin, datadir.path(), cfg).await?;

        // Watch-only replicas derive from the default wallet's exported UFVK (read straight from
        // the on-disk DB; no running daemon needed). `init --ufvk` fetches GetTreeState(birthday-1),
        // so use the lowest height with a real block (2) when no birthday is configured.
        if !cfg.extra_watch_only_wallets.is_empty() {
            let ufvk = export_ufvk_from_datadir(datadir.path(), "default")
                .context("export default UFVK for watch-only replicas")?;
            let birthday = cfg.birthday.unwrap_or(2);
            for name in &cfg.extra_watch_only_wallets {
                run_zecd_init_watch_only(&bin, datadir.path(), name, &ufvk, Some(birthday))
                    .with_context(|| format!("init watch-only wallet '{name}'"))?;
            }
        }

        Ok((datadir, mnemonic))
    }

    /// Run `zecd export-ufvk` against this daemon's datadir and return the printed Unified
    /// Full Viewing Key (the last stdout line). Safe while the daemon runs: the command only
    /// reads the wallet DB.
    pub fn export_ufvk(&self, wallet: &str) -> Result<String> {
        export_ufvk_from_datadir(self._datadir.path(), wallet)
    }

    /// The daemon's data directory (owned by this handle; deleted when it drops). Lets tests
    /// inspect and tamper with on-disk wallet state (`keys.toml`, `data.sqlite`) around
    /// restarts, e.g. the account-to-keys binding e2e.
    pub fn datadir(&self) -> &Path {
        self._datadir.path()
    }

    /// Gracefully stop the daemon (the `stop` RPC, falling back to kill), keeping the data
    /// directory intact so a test can modify on-disk state and relaunch against it with
    /// [`Zecd::respawn`] or [`Zecd::respawn_expect_startup_failure`].
    pub async fn stop_keeping_datadir(&mut self) -> Result<()> {
        let _ = self.call("stop", json!([])).await;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Ok(());
                }
            }
        }
    }

    /// Relaunch the daemon on the kept data directory (after [`Zecd::stop_keeping_datadir`])
    /// with the same config, and wait for the RPC to come back up.
    pub async fn respawn(&mut self) -> Result<()> {
        let (out, err) = if std::env::var_os("ZECD_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        self.child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("respawn zecd")?;
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    /// Relaunch the daemon on the kept data directory and expect startup to FAIL: wait for
    /// the process to exit nonzero and return its stderr (for asserting on the refusal
    /// message). Errors if the daemon comes up or exits cleanly. Used by the binding e2e:
    /// a swapped `data.sqlite` must refuse to serve.
    pub async fn respawn_expect_startup_failure(&mut self) -> Result<String> {
        let mut child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("respawn zecd expecting a startup failure")?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stderr.take() {
                        use std::io::Read as _;
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    anyhow::ensure!(
                        !status.success(),
                        "zecd was expected to refuse startup but exited cleanly; stderr:\n\
                         {stderr}"
                    );
                    return Ok(stderr);
                }
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("zecd was expected to refuse startup but is still running after 60s");
                }
                Err(e) => return Err(anyhow!("waiting for zecd to exit: {e}")),
            }
        }
    }

    /// Stop the daemon, delete every wallet's `data.sqlite` (and the compact-block cache), and
    /// restart against the *same* data directory - simulating a disposable/empty data directory
    /// next to a preserved `keys.toml`. Exercises the Phase-1 bootstrap rebuild path on a real
    /// chain. `keys.toml`, the age identity, and `zecd.toml` are left untouched, so the daemon
    /// rebuilds the account from `keys.toml` (immediately for an auto-unlock wallet, at the first
    /// `walletpassphrase` for an encrypted one). The RPC port/credentials are unchanged.
    pub async fn restart_wiping_data_db(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Remove each wallet subdirectory's derived state, keeping its keys.toml.
        for entry in std::fs::read_dir(self._datadir.path()).context("read datadir for wipe")? {
            let path = entry.context("datadir entry")?.path();
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(path.join("blocks"));
                for name in ["data.sqlite", "data.sqlite-wal", "data.sqlite-shm"] {
                    let _ = std::fs::remove_file(path.join(name));
                }
            }
        }

        let (out, err) = if std::env::var_os("ZECD_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        let child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("respawn zecd on the wiped data directory")?;
        self.child = child;
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    /// Graceful shutdown via the `stop` RPC: asserts bitcoind's reply shape ("zecd stopping"),
    /// then waits for the process to exit cleanly (status 0).
    pub async fn shutdown(mut self) -> Result<()> {
        let reply = self
            .call("stop", json!([]))
            .await
            .map_err(|e| anyhow!("stop RPC failed: {e}"))?;
        anyhow::ensure!(
            reply == json!("zecd stopping"),
            "unexpected stop reply: {reply}"
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    anyhow::ensure!(status.success(), "zecd exited with {status} after stop");
                    return Ok(());
                }
                Ok(None) => {
                    anyhow::ensure!(
                        Instant::now() < deadline,
                        "zecd did not exit within 30s of the stop RPC"
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => return Err(anyhow!("waiting for zecd to exit: {e}")),
            }
        }
    }

    /// Gracefully stop the daemon (via the `stop` RPC) and relaunch it against the *same*
    /// datadir/wallet with a (possibly different) config - e.g. flipping
    /// `[spend] cache_proving_key`. The wallet DB, keys, and funds persist across the restart;
    /// `cfg` must keep the same RPC port so this handle's `base_url` stays valid. Used by the
    /// proving-key-cache benchmark to measure both paths on one funded wallet.
    pub async fn restart(&mut self, cfg: &ZecdConfig) -> Result<()> {
        let _ = self.call("stop", json!([])).await;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        write_zecd_toml(self._datadir.path(), cfg).context("rewrite zecd.toml for restart")?;
        self.child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("respawn zecd")?;
        self.base_url = format!("http://127.0.0.1:{}/", cfg.rpc_port);
        self.user = cfg.rpc_user.clone();
        self.password = cfg.rpc_password.clone();
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    /// Issue a JSON-RPC call, returning the `result` on success or an error carrying the
    /// Bitcoin Core error `code` (so tests can assert e.g. `-6` for insufficient funds).
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.call_at(self.base_url.clone(), method, params).await
    }

    /// Issue a JSON-RPC call against a named wallet's `/wallet/<name>` endpoint (multiwallet
    /// routing; the bare [`Zecd::call`] serves the default wallet).
    pub async fn call_wallet(
        &self,
        wallet: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, RpcError> {
        self.call_at(format!("{}wallet/{wallet}", self.base_url), method, params)
            .await
    }

    async fn call_at(&self, url: String, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({ "jsonrpc": "1.0", "id": "harness", "method": method, "params": params });
        let resp = self
            .http
            .post(url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcError::transport(e.to_string()))?;
        let envelope: Value = resp
            .json()
            .await
            .map_err(|e| RpcError::transport(format!("decoding response: {e}")))?;
        if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            return Err(RpcError::Rpc { code, message });
        }
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    /// The current best-block height as seen by zecd (`getblockcount`).
    pub async fn block_count(&self) -> Result<u64> {
        self.call("getblockcount", json!([]))
            .await
            .map_err(|e| anyhow!("{e}"))?
            .as_u64()
            .ok_or_else(|| anyhow!("getblockcount did not return a number"))
    }

    /// Poll until `getblockchaininfo.blocks` reaches `target` (zecd has scanned to the tip).
    pub async fn wait_until_synced(&self, target: u64, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(info) = self.call("getblockchaininfo", json!([])).await {
                let blocks = info.get("blocks").and_then(|b| b.as_u64()).unwrap_or(0);
                if blocks >= target {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                bail!("zecd did not sync to height {target} within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn wait_until_rpc_up(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.call("uptime", json!([])).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("zecd RPC did not come up within 30s");
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

impl Drop for Zecd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A JSON-RPC failure: either a transport problem or a Bitcoin-Core-style `{code, message}`.
#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    Rpc { code: i64, message: String },
}

impl RpcError {
    fn transport(s: String) -> Self {
        RpcError::Transport(s)
    }
    /// The Bitcoin Core error code, if this was an RPC-level error.
    pub fn code(&self) -> Option<i64> {
        match self {
            RpcError::Rpc { code, .. } => Some(*code),
            RpcError::Transport(_) => None,
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Transport(s) => write!(f, "transport error: {s}"),
            RpcError::Rpc { code, message } => write!(f, "rpc error {code}: {message}"),
        }
    }
}

impl std::error::Error for RpcError {}

// =============================== helpers ===============================

/// JSON-RPC 2.0 call to zebrad; returns the `result` or an error carrying the message.
async fn zebra_rpc_call(url: &str, method: &str, params: Value) -> Result<Value> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .context("zebra rpc request")?;
    let envelope: Value = resp.json().await.context("decode zebra rpc response")?;
    if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
        bail!("zebra rpc error from {method}: {err}");
    }
    Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
}

fn tail(s: &str, lines: usize) -> String {
    let all: Vec<&str> = s.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// Send a named signal (e.g. `STOP`, `CONT`) to a process via the portable `kill` binary
/// (avoids a libc dependency for the harness's two niche uses).
fn signal_process(pid: u32, sig: &str) -> Result<()> {
    let status = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .with_context(|| format!("spawn kill -{sig} {pid}"))?;
    anyhow::ensure!(status.success(), "kill -{sig} {pid} exited with {status}");
    Ok(())
}

fn reset_datadir(datadir: &Path, cfg: &ZecdConfig) -> Result<()> {
    for entry in std::fs::read_dir(datadir).context("read datadir for reset")? {
        let path = entry?.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
    write_zecd_toml(datadir, cfg)
}

/// Run `zecd init` for one wallet, returning the generated mnemonic (printed on stdout by a
/// fresh init; `None` on the restore path, which prints none). The restore path applies to
/// the default wallet only: the phrase from [`ZecdConfig::restore_mnemonic`] is fed on stdin
/// and `--birthday` is passed when set.
fn run_zecd_init(
    bin: &Path,
    datadir: &Path,
    wallet: &str,
    cfg: &ZecdConfig,
) -> Result<Option<String>> {
    let mut args: Vec<String> = vec![
        "--datadir".into(),
        datadir.to_str().unwrap().into(),
        "--regtest".into(),
        "init".into(),
        "--wallet".into(),
        wallet.into(),
    ];
    let restore = (wallet == "default")
        .then(|| cfg.restore_mnemonic.clone())
        .flatten();
    let ufvk = (wallet == "default").then(|| cfg.ufvk.clone()).flatten();
    if restore.is_some() {
        args.push("--restore".into());
    }
    if let Some(key) = &ufvk {
        args.push("--ufvk".into());
        args.push(key.clone());
    }
    if restore.is_some() || ufvk.is_some() {
        if let Some(b) = cfg.birthday {
            args.push("--birthday".into());
            args.push(b.to_string());
        }
    }
    // The spending `default` wallet may be created passphrase-encrypted; the passphrase is
    // passed out-of-band via `ZECD_WALLET_PASSPHRASE` (never on the command line). `--encrypt`
    // is incompatible with `--ufvk`, so it only applies to the seed-bearing default wallet.
    let encrypt = (wallet == "default" && ufvk.is_none())
        .then(|| cfg.encrypt_passphrase.clone())
        .flatten();
    if encrypt.is_some() {
        args.push("--encrypt".into());
    }
    let mut command = Command::new(bin);
    command
        .args(&args)
        .stdin(if restore.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(pass) = &encrypt {
        command.env("ZECD_WALLET_PASSPHRASE", pass);
    }
    let mut child = command.spawn().context("spawn zecd init")?;
    if let Some(phrase) = &restore {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(format!("{phrase}\n").as_bytes())
            .context("write the mnemonic to zecd init")?;
    }
    let out = child.wait_with_output().context("wait for zecd init")?;
    if !out.status.success() {
        bail!(
            "zecd init --wallet {wallet} failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let phrase = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((!phrase.is_empty()).then_some(phrase))
}

/// Init the `default` wallet, retried while lightwalletd catches up to the chain tip. Just
/// after launch lightwalletd may still be ingesting from zebrad, so `zecd init` (which contacts
/// it for `get_latest_block` + `get_tree_state`) is retried, resetting the datadir between
/// attempts so a partial init can't wedge the next one. Returns the generated mnemonic.
async fn init_default_with_retry(
    bin: &Path,
    datadir: &Path,
    cfg: &ZecdConfig,
) -> Result<Option<String>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match run_zecd_init(bin, datadir, "default", cfg) {
            Ok(mnemonic) => return Ok(mnemonic),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e.context("zecd init failed after retries"));
                }
                reset_datadir(datadir, cfg)?;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Run `zecd init --wallet <wallet> --ufvk <ufvk>` to create a watch-only wallet (no spending
/// material). `birthday` sets the scan start (`init --ufvk` fetches GetTreeState(birthday-1),
/// so genesis/height-1 are rejected - pass ≥ 2).
fn run_zecd_init_watch_only(
    bin: &Path,
    datadir: &Path,
    wallet: &str,
    ufvk: &str,
    birthday: Option<u32>,
) -> Result<()> {
    let mut args: Vec<String> = vec![
        "--datadir".into(),
        datadir.to_str().unwrap().into(),
        "--regtest".into(),
        "init".into(),
        "--wallet".into(),
        wallet.into(),
        "--ufvk".into(),
        ufvk.into(),
    ];
    if let Some(b) = birthday {
        args.push("--birthday".into());
        args.push(b.to_string());
    }
    let out = Command::new(bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn zecd init --ufvk")?
        .wait_with_output()
        .context("wait for zecd init --ufvk")?;
    if !out.status.success() {
        bail!(
            "zecd init --wallet {wallet} --ufvk failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Run `zecd export-ufvk --wallet <wallet>` against a datadir (reads the wallet DB directly; no
/// running daemon required) and return the printed Unified Full Viewing Key (the last non-empty
/// stdout line).
fn export_ufvk_from_datadir(datadir: &Path, wallet: &str) -> Result<String> {
    let out = Command::new(zecd_bin())
        .args([
            "--datadir",
            datadir.to_str().unwrap(),
            "--regtest",
            "export-ufvk",
            "--wallet",
            wallet,
        ])
        .output()
        .context("spawn zecd export-ufvk")?;
    if !out.status.success() {
        bail!(
            "zecd export-ufvk failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("export-ufvk printed nothing on stdout"))
}

fn write_zecd_toml(datadir: &Path, cfg: &ZecdConfig) -> Result<()> {
    // zecd is zebra-only: the single upstream is a local zebrad JSON-RPC endpoint.
    let server = format!("zebra://127.0.0.1:{}", cfg.zebra_rpc_port);
    // Optional `[spend]` knobs: `cache_proving_key` (the proving-key-cache benchmark) and
    // `privacy_policy` (the fully-transparent spend e2e). Emit the section if either is set.
    let spend_section = if cfg.cache_proving_key.is_some()
        || cfg.pipeline_proving.is_some()
        || cfg.orchard_action_limit.is_some()
        || cfg.privacy_policy.is_some()
    {
        let mut s = String::from("\n[spend]\n");
        if let Some(b) = cfg.cache_proving_key {
            s.push_str(&format!("cache_proving_key = {b}\n"));
        }
        if let Some(b) = cfg.pipeline_proving {
            s.push_str(&format!("pipeline_proving = {b}\n"));
        }
        if let Some(n) = cfg.orchard_action_limit {
            s.push_str(&format!("orchard_action_limit = {n}\n"));
        }
        if let Some(p) = &cfg.privacy_policy {
            s.push_str(&format!("privacy_policy = \"{p}\"\n"));
        }
        s
    } else {
        String::new()
    };
    // The default wallet plus any extra `[wallets.<name>]` entries (multiwallet tests).
    let mut wallets = format!(
        "[wallets.default]\ndir = \"{}/default\"\n",
        datadir.display()
    );
    for name in cfg
        .extra_wallets
        .iter()
        .chain(&cfg.extra_watch_only_wallets)
    {
        wallets.push_str(&format!(
            "\n[wallets.{name}]\ndir = \"{}/{name}\"\n",
            datadir.display()
        ));
    }
    // Optional [pools] section (multi-pool / Sapling e2e, and/or transparent receiving); omitted
    // entirely → Orchard-only, no transparent.
    let pools = if cfg.pools.is_some() || cfg.transparent {
        let mut s = String::from("\n[pools]\n");
        if let Some((enabled, receivers)) = &cfg.pools {
            let list = |v: &[String]| {
                v.iter()
                    .map(|p| format!("\"{p}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            s.push_str(&format!(
                "enabled = [{}]\ndefault_receivers = [{}]\n",
                list(enabled),
                list(receivers)
            ));
        }
        if cfg.transparent {
            s.push_str("transparent = true\n");
            if let Some(g) = cfg.transparent_gap_limit {
                s.push_str(&format!("transparent_gap_limit = {g}\n"));
            }
            if let Some(n) = cfg.transparent_initial_scan {
                s.push_str(&format!("transparent_initial_scan = {n}\n"));
            }
            if let Some(a) = cfg.transparent_allow_beyond_recovery_window {
                s.push_str(&format!("transparent_allow_beyond_recovery_window = {a}\n"));
            }
            if let Some(t) = cfg.transparent_gap_warn_threshold {
                s.push_str(&format!("transparent_gap_warn_threshold = {t}\n"));
            }
        }
        s
    } else {
        String::new()
    };
    wallets.push_str(&pools);
    // Fast reconnect backoff (1..2s) so outage-recovery tests converge quickly.
    let toml = format!(
        r#"network = "regtest"
datadir = "{datadir}"
default_wallet = "default"

{wallets}
[backend]
server = "{server}"
connect_timeout_secs = 5
reconnect_base_secs = 1
reconnect_max_secs = 2

[rpc]
bind = "127.0.0.1"
port = {rpc_port}
user = "{user}"
password = "{password}"

[keys]
auto_unlock = true

[sync]
interval_secs = 2
rebroadcast_secs = {rebroadcast}

[health]
enabled = true
bind = "127.0.0.1"
port = {health_port}
{spend_section}"#,
        datadir = datadir.display(),
        wallets = wallets,
        server = server,
        rpc_port = cfg.rpc_port,
        user = cfg.rpc_user,
        password = cfg.rpc_password,
        rebroadcast = cfg.rebroadcast_secs,
        health_port = cfg.health_port(),
        spend_section = spend_section,
    );
    std::fs::write(datadir.join("zecd.toml"), toml)?;
    Ok(())
}
