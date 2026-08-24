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
indexer_listen_addr = "127.0.0.1:{indexer_port}"
enable_cookie_auth = false
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
        .args(["build", "--bin", "zns-mint", "--features", "dev-regtest"])
        .status()
        .expect("failed to execute cargo build for zns-mint");
        
    assert!(status.success(), "cargo build --features dev-regtest failed for zns-mint");

    workspace_root.join("target/debug/zns-mint")
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

        let mut cmd = Command::new(&bin);

        let mut child = cmd
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("spawn zns-mint daemon")?;

        // Wait for the mint to settle. zns-mint exposes no externally
        // observable boot signal (the metrics endpoint was removed); boot
        // success here means "still running after a grace period". A stub
        // main cannot do better until the run loop lands.
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Ok(Some(status)) = child.try_wait() {
            bail!("zns-mint exited prematurely during startup ({status})");
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

// =============================== zallet (user wallet simulation) ===============================

/// Locate the `zallet` binary: `$ZALLET_BIN` if set, else expect it on `$PATH`.
fn zallet_bin() -> PathBuf {
    if let Ok(p) = std::env::var("ZALLET_BIN") {
        return PathBuf::from(p);
    }
    PathBuf::from("zallet")
}

/// Generates a `zallet.toml` for regtest mode using the `zaino` backend
/// (JSON-RPC only, no direct RocksDB access). Nuparams match the harness's
/// zebrad config: NU5/NU6 at height 1, NU6.1/6.2/6.3 at height 4.
fn zallet_toml(zebra_rpc_port: u16, zallet_rpc_port: u16) -> String {
    format!(
        r#"backend = "zaino"

[builder]
[builder.limits]

[consensus]
network = "regtest"
regtest_nuparams = [
    "c2d6d0b4:1",
    "c8e71055:1",
    "4dec4df0:4",
    "5437f330:4",
    "37a5165b:4",
]

[database]

[external]

[features]
as_of_version = "0.1.0-beta.1"

[features.deprecated]

[features.experimental]

[indexer]
validator_address = "127.0.0.1:{zebra_rpc_port}"

[keystore]

[note_management]

[rpc]
bind = ["127.0.0.1:{zallet_rpc_port}"]

[[rpc.auth]]
user = "user"
password = "pass"
"#
    )
}

/// A running `zallet` wallet daemon in regtest mode, simulating a ZNS user.
///
/// Holds the child process, RPC connection details, and the transparent miner
/// address captured during regtest account creation. The temp directory is
/// dropped (cleaned up) when this struct is dropped.
pub struct Zallet {
    child: Option<Child>,
    rpc_port: u16,
    http: reqwest::Client,
    /// Transparent address for mining coinbase to this wallet.
    pub miner_address: String,
    _dir: tempfile::TempDir,
}

impl Zallet {
    /// Initialize a Zallet wallet in regtest mode without starting the daemon.
    ///
    /// Creates a temp directory, writes `zallet.toml`, generates the
    /// encryption identity, initializes wallet encryption, generates a
    /// mnemonic, and creates a regtest account (capturing the miner address).
    /// Call [`Zallet::start_daemon`] afterwards to launch the RPC server.
    pub async fn init(zebra_rpc_port: u16) -> Result<Zallet> {
        let dir = tempfile::tempdir().context("create zallet datadir")?;
        let datadir = dir.path();
        let bin = zallet_bin();

        if !bin.exists() {
            bail!(
                "zallet binary not found at {} - set $ZALLET_BIN or install zallet on $PATH",
                bin.display()
            );
        }

        let rpc_port = 8234u16;
        std::fs::write(
            datadir.join("zallet.toml"),
            zallet_toml(zebra_rpc_port, rpc_port),
        )
        .context("write zallet.toml")?;

        // Generate the wallet's age encryption identity.
        let status = Command::new(&bin)
            .args(["--datadir", datadir.to_str().unwrap(), "generate-encryption-identity"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .context("spawn zallet generate-encryption-identity")?;
        if !status.success() {
            bail!("zallet generate-encryption-identity failed with {status}");
        }

        // Initialize wallet encryption (binds the identity to the wallet DB).
        let status = Command::new(&bin)
            .args(["--datadir", datadir.to_str().unwrap(), "init-wallet-encryption"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .context("spawn zallet init-wallet-encryption")?;
        if !status.success() {
            bail!("zallet init-wallet-encryption failed with {status}");
        }

        // Generate the wallet seed.
        let status = Command::new(&bin)
            .args(["--datadir", datadir.to_str().unwrap(), "generate-mnemonic"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .context("spawn zallet generate-mnemonic")?;
        if !status.success() {
            bail!("zallet generate-mnemonic failed with {status}");
        }

        // Create the default account and capture the transparent miner address.
        let miner_out = Command::new(&bin)
            .args([
                "--datadir", datadir.to_str().unwrap(),
                "regtest", "generate-account-and-miner-address",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .context("spawn zallet regtest generate-account-and-miner-address")?;
        if !miner_out.status.success() {
            bail!(
                "zallet regtest generate-account-and-miner-address failed with {}",
                miner_out.status
            );
        }
        let miner_address = String::from_utf8_lossy(&miner_out.stdout)
            .trim()
            .to_string();

        Ok(Zallet {
            child: None,
            rpc_port,
            http: reqwest::Client::new(),
            miner_address,
            _dir: dir,
        })
    }

    /// Spawn the Zallet daemon and wait for JSON-RPC to come up.
    ///
    /// Requires that [`Zallet::init`] has been called first. The Zebra node
    /// must be running and reachable at the configured `validator_address`.
    pub async fn start_daemon(&mut self) -> Result<()> {
        let bin = zallet_bin();
        let (out, err) = if std::env::var_os("ZALLET_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        self.child = Some(
            Command::new(&bin)
                .args(["--datadir", self._dir.path().to_str().unwrap(), "start"])
                .stdout(out)
                .stderr(err)
                .spawn()
                .context("spawn zallet daemon")?,
        );
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.rpc_port)
    }

    /// Issue a JSON-RPC call to the wallet, returning the `result` on success.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "1.0", "id": "harness", "method": method, "params": params });
        let resp = self
            .http
            .post(self.rpc_url())
            .basic_auth("user", Some("pass"))
            .json(&body)
            .send()
            .await
            .context("zallet rpc request")?;
        let envelope: Value = resp.json().await.context("decode zallet rpc response")?;
        if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
            bail!("zallet rpc error from {method}: {err}");
        }
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Poll until the wallet's JSON-RPC endpoint responds.
    async fn wait_until_rpc_up(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(child) = self.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    if !status.success() {
                        bail!("zallet exited during startup ({status})");
                    }
                }
            }
            if self.call("getwalletstatus", json!([])).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("zallet RPC did not come up within 60s");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Poll until the wallet has scanned to the target block height.
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
                bail!("zallet did not sync to height {target} within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

impl Drop for Zallet {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
