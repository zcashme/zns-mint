//! `zns-mint` — the ZNS minting daemon.
//!
//! Boot-and-run-forever: load config, construct the [`Registry`], then poll
//! lightwalletd for incoming notes and dispatch each through the registry
//! (CLAIM mints immediately; UPDATE/RELEASE issue + relay an OTP challenge;
//! confirm notes complete the mint). No CLI — config comes from a file +
//! `ZNS_*` env. A `tokio-graceful-shutdown` supervision tree and a `jsonrpsee`
//! control plane land on top of this loop; this is the intake→dispatch core.

use std::sync::Arc;
use std::time::Duration;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zns_mint::{
    scan_incoming_all, select_funding, FundingInput, GrpcClient, MintContext, ProcessResult,
    Registry, ScannerConfig, Signer, SpendPolicy, Treasury, FUNDING_MIN_ZAT, MINT_FEE_ZAT,
};

/// How often to poll lightwalletd for new blocks.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// How many blocks back to take the spend anchor — confirmed, well within the
/// Orchard anchor window. Override with `ZNS_ANCHOR_CONFIRMATIONS`.
const ANCHOR_CONFIRMATIONS: u32 = 3;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: load from the `config` crate (file + ZNS_* env), init tracing+metrics.
    let cfg = DaemonConfig::from_env()?;

    // `zns-mint address` prints the registry Unified Address (addr_reg) and
    // exits — operators fund this and senders address CLAIM notes to it.
    if std::env::args().nth(1).as_deref() == Some("address") {
        println!("{}", cfg.registry_ua()?);
        return Ok(());
    }

    // `zns-mint viewkey` prints addr_reg's Unified *Incoming* Viewing Key —
    // the published key (DESIGN.md §7) every resolver scans with.
    if std::env::args().nth(1).as_deref() == Some("viewkey") {
        println!("{}", cfg.registry_uivk()?);
        return Ok(());
    }

    // `zns-mint scan` does one intake scan and prints the ZNS notes found at
    // addr_reg, without minting — a read-only check that intake works.
    if std::env::args().nth(1).as_deref() == Some("scan") {
        let notes = scan_incoming_all(&cfg.scanner()).await?;
        eprintln!(
            "zns-mint: scanned from height {} → {} note(s) at addr_reg",
            cfg.birthday,
            notes.len()
        );
        for n in &notes {
            match zns_mint::parse_memo(&n.memo) {
                Ok(m) => println!("  {} zat @h{}: {:?}", n.value_zat, n.height, m),
                Err(_) => println!("  {} zat @h{}: (non-ZNS memo)", n.value_zat, n.height),
            }
        }
        return Ok(());
    }

    let registry = Registry::new(&cfg.db_path, &cfg.lwd_url)?;
    let scanner = cfg.scanner();
    let grpc = GrpcClient::new(&cfg.lwd_url);
    // The policy-gated signing authority — the only holder of key material on
    // the mint path. The daemon proposes intent; the signer authors and signs.
    let signer = Arc::new(cfg.signer()?);

    eprintln!(
        "zns-mint: polling {} every {}s (db: {})",
        cfg.lwd_url,
        POLL_INTERVAL.as_secs(),
        cfg.db_path,
    );

    let mut tick = tokio::time::interval(POLL_INTERVAL);
    loop {
        tick.tick().await;
        // One poll = one velocity window (with take-once treasury, at most one
        // spend lands per poll anyway; the cap matters once that changes).
        signer.roll_window();

        // Stamp this round's mints with the current chain tip.
        let tip = match grpc.tip_height().await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("zns-mint: tip query failed: {e:#}");
                continue;
            }
        };
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

        // There is something to mint: select a treasury note to self-fund the
        // fee and build its witness, anchored a few blocks back (well confirmed).
        let anchor_height = tip.saturating_sub(ANCHOR_CONFIRMATIONS);
        let mut ctx = cfg.mint_context(tip, signer.clone());
        match select_funding(&scanner, FUNDING_MIN_ZAT, cfg.birthday, anchor_height).await {
            Ok(selection) => {
                ctx.hot_balance_zat = selection.spendable_total_zat;
                match selection.note {
                    Some(sn) => {
                        eprintln!(
                            "zns-mint: funding note {} zat of {} spendable, anchor @h{anchor_height} = {}",
                            sn.value_zat,
                            selection.spendable_total_zat,
                            hex::encode(sn.anchor.to_bytes()),
                        );
                        ctx.treasury = Some(Arc::new(Treasury {
                            funding: FundingInput {
                                note: sn.note,
                                merkle_path: sn.merkle_path,
                                anchor: sn.anchor,
                            },
                        }));
                    }
                    None => eprintln!(
                        "zns-mint: no treasury note ≥ floor ({} zat spendable) — spends deferred",
                        selection.spendable_total_zat
                    ),
                }
            }
            Err(e) => eprintln!("zns-mint: funding selection failed: {e:#}"),
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

/// Daemon configuration. Sourced from `ZNS_*` env for now; the `config` crate
/// (file + env, hot-reload) replaces this.
struct DaemonConfig {
    db_path: String,
    lwd_url: String,
    network: zns_mint::ZcashNetwork,
    birthday: u32,
    /// 32-byte zip32 seed the registry Orchard key is derived from.
    seed: [u8; 32],
}

impl DaemonConfig {
    fn from_env() -> anyhow::Result<Self> {
        let lwd_url =
            std::env::var("ZNS_LWD_URL").unwrap_or_else(|_| "http://127.0.0.1:9067".into());
        let network = match std::env::var("ZNS_NETWORK") {
            Ok(name) => zns_mint::ZcashNetwork::from_name(&name)
                .ok_or_else(|| anyhow::anyhow!("unknown ZNS_NETWORK '{name}'"))?,
            Err(_) => zns_mint::ZcashNetwork::Main,
        };
        let birthday = std::env::var("ZNS_BIRTHDAY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // TODO: load the seed from a secret store (zeroized), never plain env in
        // production. A zero seed is deterministic — fine only for regtest.
        let seed = match std::env::var("ZNS_SPEND_SEED") {
            Ok(hex) => decode_seed(&hex)?,
            Err(_) => {
                eprintln!("zns-mint: WARNING — ZNS_SPEND_SEED unset, using a zero seed (regtest only)");
                [0u8; 32]
            }
        };

        Ok(Self {
            db_path: std::env::var("ZNS_DB_PATH").unwrap_or_else(|_| "zns-mint.sqlite".into()),
            lwd_url,
            network,
            birthday,
            seed,
        })
    }

    /// Coin type for zip32 derivation: 133 mainnet, 1 test/regtest.
    fn coin_type(&self) -> u32 {
        match self.network {
            zns_mint::ZcashNetwork::Main => 133,
            _ => 1,
        }
    }

    fn spend_key(&self) -> SpendingKey {
        SpendingKey::from_zip32_seed(&self.seed, self.coin_type(), zip32::AccountId::ZERO)
            .expect("valid zip32 seed")
    }

    fn registry_fvk(&self) -> FullViewingKey {
        FullViewingKey::from(&self.spend_key())
    }

    /// The registry's Orchard-only Unified Address (`addr_reg`) for this network.
    fn registry_ua(&self) -> anyhow::Result<String> {
        let addr = self.registry_fvk().address_at(0u32, Scope::External);
        let ua = zcash_keys::address::UnifiedAddress::from_receivers(Some(addr), None, None)
            .ok_or_else(|| anyhow::anyhow!("could not build a Unified Address"))?;
        Ok(ua.encode(&self.network))
    }

    /// addr_reg's Unified Incoming Viewing Key — the published key
    /// (`DESIGN.md §7`): resolvers scan with it; it cannot spend.
    fn registry_uivk(&self) -> anyhow::Result<String> {
        use zcash_address::unified::{Encoding, Ivk, Uivk};
        use zcash_protocol::consensus::Parameters as _;

        let ivk = self.registry_fvk().to_ivk(Scope::External).to_bytes();
        let uivk = Uivk::try_from_items(vec![Ivk::Orchard(ivk)])
            .map_err(|e| anyhow::anyhow!("building UIVK: {e:?}"))?;
        Ok(uivk.encode(&self.network.network_type()))
    }

    fn scanner(&self) -> ScannerConfig {
        ScannerConfig {
            registry_fvk: self.registry_fvk(),
            network: self.network,
            birthday: self.birthday,
            lwd_url: self.lwd_url.clone(),
        }
    }

    /// Build the per-round mint context. Value-0 Name Notes need only the
    /// registry key, an empty-tree anchor, and the current height — no treasury.
    /// `treasury` stays `None` until note-state lands, so UPDATE/RELEASE relays
    /// surface a clear "no treasury funding configured" error.
    /// The signing authority: the spend seed behind the policy gate. Default
    /// bounds are deliberately conservative; a config file refines them later.
    fn signer(&self) -> anyhow::Result<Signer> {
        let registry_addr = self.registry_fvk().address_at(0u32, Scope::External);
        let policy = SpendPolicy {
            registry_addr,
            // Sweeps are not wired in the daemon yet; cold = self keeps the
            // constant harmless until a real cold address is configured.
            cold_addr: registry_addr,
            max_fee_zat: MINT_FEE_ZAT,
            target_float_zat: 0,
            high_watermark_zat: u64::MAX, // never suggest a sweep
            low_watermark_zat: 2 * MINT_FEE_ZAT, // pause when even a relay can't fund
            max_mints_per_window: 4,
            max_swept_per_window_zat: 0, // sweeps disabled
        };
        Signer::new(self.seed, self.coin_type(), zip32::AccountId::ZERO, policy)
            .map_err(|e| anyhow::anyhow!("constructing signer: {e}"))
    }

    fn mint_context(&self, tip_height: u32, signer: Arc<Signer>) -> MintContext {
        // Branch id for the active upgrade at the tip — `ZcashNetwork` carries the
        // activation heights, so this resolves Nu6 on regtest and Nu6_2 on a
        // post-NU6.2 testnet automatically.
        let branch_id = zcash_protocol::consensus::BranchId::for_height(
            &self.network,
            zcash_protocol::consensus::BlockHeight::from_u32(tip_height),
        );
        MintContext {
            signer,
            hot_balance_zat: 0,
            anchor: orchard::tree::Anchor::empty_tree(),
            height: tip_height,
            expiry_height: 0,
            network: self.network,
            circuit_version: self.circuit_version(),
            branch_id,
            treasury: None,
        }
    }

    /// Orchard circuit version to prove against — must match the circuit the
    /// target chain validates with for its active upgrade. The NU6.2 fix swapped
    /// the circuit/VK: pre-NU6.2 chains verify with `InsecurePreNu6_2`, post-NU6.2
    /// with `FixedPostNu6_2`. Testnet and our NU6.2 regtest are both post-NU6.2,
    /// so default to fixed. Override with `ZNS_CIRCUIT=insecure|fixed`.
    fn circuit_version(&self) -> orchard::circuit::OrchardCircuitVersion {
        use orchard::circuit::OrchardCircuitVersion::*;
        match std::env::var("ZNS_CIRCUIT").as_deref() {
            Ok("insecure") => InsecurePreNu6_2,
            _ => FixedPostNu6_2,
        }
    }
}

/// Decode a 64-char hex string into a 32-byte seed.
fn decode_seed(hex: &str) -> anyhow::Result<[u8; 32]> {
    let hex = hex.trim();
    anyhow::ensure!(hex.len() == 64, "ZNS_SPEND_SEED must be 64 hex chars (32 bytes)");
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in ZNS_SPEND_SEED: {e}"))?;
    }
    Ok(seed)
}
