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

use zns_registry::{
    test_orchard_ivk, test_registry_address, scan_incoming_all, scan_mempool, FundingInput,
    GrpcClient, MintContext, NoteState, ProcessResult, Processor, Registry, ScannerConfig,
    Signer, SpendPolicy, Treasury, TreasuryConfig, FUNDING_MIN_ZAT, MINT_FEE_ZAT,
};

/// How often to poll lightwalletd for new blocks.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// How many blocks back to take the spend anchor — confirmed, well within the
/// Orchard anchor window. Override with `ZNS_ANCHOR_CONFIRMATIONS`.
const ANCHOR_CONFIRMATIONS: u32 = 3;

/// Built transactions expire this many blocks after the tip (ZIP-203). Bounded
/// expiry is what lets crash reconciliation declare an unmined intent dead
/// instead of holding it open forever.
const TX_EXPIRY_BLOCKS: u32 = 40;

/// Control-plane (health/status RPC) bind address.
const RPC_ADDR: &str = "127.0.0.1:8081";

/// Cold-vault destination for hot→cold sweeps, as a Unified Address string.
/// Baked into source — like the rest of `SpendPolicy` — so the sweep
/// destination is covered by the same reproducible-build/attestation story
/// as the code itself, not settable by whoever launches the process.
///
/// Empty until a real cold vault address exists. While empty, `signer()`
/// falls back to `cold_addr == registry_addr` and force-disables sweeps.
const COLD_ADDR_UA: &str = "";

/// Once the hot balance exceeds this, a sweep is due
/// ([`SpendPolicy::evaluate_sweep`]).
const HIGH_WATERMARK_ZAT: u64 = 10 * MINT_FEE_ZAT;

/// Sweep aims to bring the hot balance back down toward this.
const TARGET_FLOAT_ZAT: u64 = 4 * MINT_FEE_ZAT;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = DaemonConfig::load();

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
            match zns_registry::parse_memo(&n.memo) {
                Ok(m) => println!("  {} zat @h{}: {:?}", n.value_zat, n.height, m),
                Err(_) => println!("  {} zat @h{}: (non-ZNS memo)", n.value_zat, n.height),
            }
        }
        return Ok(());
    }

    let store = Registry::new(&cfg.db_path)?;
    let scanner = cfg.scanner();
    // Treasury note-state: a view-only WalletDb over the registry FVK. It owns
    // scanning, witnesses, reorg rewind, and note selection for the spend side.
    let mut notestate = NoteState::open(&cfg.wallet_db_path, &cfg.treasury_config()).await?;
    let grpc = GrpcClient::new(&cfg.lwd_url);
    // The policy-gated signing authority — the only holder of key material on
    // the mint path. The daemon proposes intent; the signer authors and signs.
    let signer = Arc::new(cfg.signer()?);

    let processor = Processor::new(store.clone());

    tracing::info!(
        lwd = cfg.lwd_url,
        every_s = POLL_INTERVAL.as_secs(),
        db = cfg.db_path,
        "polling"
    );

    // Control plane: health + status, read-only by construction.
    let status = Arc::new(tokio::sync::RwLock::new(
        zns_registry::rpc::ChainStatus::default(),
    ));
    tokio::spawn(zns_registry::rpc::serve(
        RPC_ADDR.to_string(),
        zns_registry::rpc::RpcContext {
            registry: store.clone(),
            status: status.clone(),
        },
    ));

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
                tracing::warn!("tip query failed: {e:#}");
                continue;
            }
        };
        {
            let mut s = status.write().await;
            s.tip_height = tip;
            s.last_poll_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        // Detect and recover from chain reorganizations before we process any
        // new notes. A reorg rolls back processed_notes, name_events,
        // names (live tip), and mint_intents above the common ancestor.
        match processor.handle_reorg(&grpc, &signer, tip).await {
            Ok(Some(reorg_height)) => {
                tracing::warn!(
                    reorg_height,
                    "reorg handled; resuming poll on canonical chain"
                );
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("reorg handling failed: {e:#}");
                continue;
            }
        }

        // Resolve any mints a crash left between broadcast and persistence.
        if let Err(e) = processor.reconcile_intents(&grpc, &signer, tip).await {
            tracing::error!("intent reconciliation failed: {e:#}");
            continue; // don't mint over an unresolved intent
        }
        let notes = match scan_incoming_all(&scanner).await {
            Ok(notes) => notes,
            Err(e) => {
                tracing::warn!("scan error: {e:#}");
                continue; // transient — retry on the next tick
            }
        };
        let notes = store.unsettled(notes).await;

        // Monitor the mempool for unconfirmed ZNS notes. We deliberately act
        // only on `confirm` memos from the mempool — those are the OTP auth
        // response and the UX win is meaningful. Claims/updates stay block-
        // gated because they carry fees the registry must actually receive.
        let mut mempool_confirms = Vec::new();
        match scan_mempool(&scanner, tip).await {
            Ok(mempool) => {
                status.write().await.mempool_notes = mempool.len() as u64;
                for n in mempool {
                    match zns_registry::parse_memo(&n.memo) {
                        Ok(zns_registry::ParsedMemo::Confirm { ref name, .. }) => {
                            tracing::info!(
                                txid = hex::encode(n.txid),
                                name,
                                "mempool confirm note — will act on it"
                            );
                            mempool_confirms.push(n);
                        }
                        Ok(m) => tracing::debug!(
                            txid = hex::encode(n.txid),
                            value = n.value_zat,
                            ?m,
                            "mempool ZNS note (ignored until mined)"
                        ),
                        Err(_) => {}
                    }
                }
            }
            Err(e) => tracing::warn!("mempool scan failed: {e:#}"),
        }

        // Bring the treasury wallet to the tip and pick a note to self-fund
        // fees, with its witness anchored a few blocks back (well
        // confirmed). Runs every tick — independent of mint activity —
        // because the sweep check below needs a current hot balance.
        let mut ctx = cfg.mint_context(tip, signer.clone());
        if let Err(e) = notestate.sync().await {
            tracing::warn!("treasury sync failed: {e:#}");
        } else {
            match notestate.select_funding(FUNDING_MIN_ZAT, ANCHOR_CONFIRMATIONS) {
                Ok(selection) => {
                    ctx.hot_balance_zat = selection.spendable_total_zat;
                    status.write().await.spendable_zat = selection.spendable_total_zat;
                    match selection.note {
                        Some(sn) => {
                            tracing::info!(
                                note_zat = sn.value_zat,
                                spendable_zat = selection.spendable_total_zat,
                                anchor = hex::encode(sn.anchor.to_bytes()),
                                "funding selected"
                            );
                            ctx.treasury = Some(Arc::new(Treasury {
                                funding: FundingInput {
                                    note: sn.note,
                                    merkle_path: sn.merkle_path,
                                    anchor: sn.anchor,
                                },
                            }));
                        }
                        None => tracing::warn!(
                            spendable_zat = selection.spendable_total_zat,
                            "no treasury note ≥ floor — spends deferred"
                        ),
                    }
                }
                Err(e) => tracing::warn!("funding selection failed: {e:#}"),
            }
        }

        // Sweep check: if the hot balance is over the high watermark, drain
        // this poll's selected note to cold before anything else can spend
        // it. On any failure, give the note back so a relay/mint can still
        // use it this round.
        if let Some(plan) = signer.policy().evaluate_sweep(ctx.hot_balance_zat) {
            if let Some(treasury) = ctx.treasury.take() {
                match signer.sign_sweep(
                    treasury.funding_input(),
                    MINT_FEE_ZAT,
                    ctx.branch_id,
                    ctx.expiry_height,
                    ctx.circuit_version,
                ) {
                    Ok(result) => match grpc.broadcast(result.tx_bytes).await {
                        Ok(()) => tracing::info!(
                            amount_zat = result.amount_zat,
                            target_zat = plan.amount_zat,
                            "sweep broadcast"
                        ),
                        Err(e) => {
                            tracing::warn!("sweep broadcast failed: {e:#}");
                            ctx.treasury = Some(treasury);
                        }
                    },
                    Err(e) => {
                        tracing::warn!("sweep sign failed: {e}");
                        ctx.treasury = Some(treasury);
                    }
                }
            } else {
                tracing::warn!(
                    spendable_zat = ctx.hot_balance_zat,
                    "sweep due but no treasury note selected — deferred"
                );
            }
        }

        // Combine mined, unsettled notes with unconfirmed mempool confirms.
        // Mempool confirms are processed once per txid; if they later mine,
        // the intake ledger will skip them as already settled.
        let mut to_process = notes;
        to_process.extend(mempool_confirms);

        // Quiet poll = everything already settled; nothing left to mint.
        if to_process.is_empty() {
            continue;
        }

        for result in processor.process_notes(&to_process, &ctx, &grpc).await {
            match result {
                ProcessResult::Ok(outcome) => tracing::info!("{outcome:?}"),
                ProcessResult::Skipped(why) => tracing::debug!("skipped ({why})"),
                ProcessResult::Err(name, err) => tracing::warn!(name, "{err}"),
            }
        }
    }
}

/// Daemon configuration. Every value is a build-time constant — covered by the
/// same attestation as everything else, not switchable by whoever launches the
/// process. There is no runtime config file; operational values (lwd URL, DB
/// path, poll interval, policy thresholds) are baked in so the binary's
/// behavior is fixed at build time.
struct DaemonConfig {
    db_path: String,
    /// Treasury note-state (WalletDb) sqlite — separate from the registry db.
    wallet_db_path: String,
    lwd_url: String,
    network: zcash_protocol::consensus::Network,
    birthday: u32,
}

impl DaemonConfig {
    fn load() -> Self {
        // Network is a build-time choice (the `testnet` feature), not runtime
        // config — which network a binary talks to should be fixed at build
        // and covered by the same attestation as everything else, not
        // switchable by whoever launches the process.
        #[cfg(feature = "testnet")]
        let network = zcash_protocol::consensus::Network::TestNetwork;
        #[cfg(not(feature = "testnet"))]
        let network = zcash_protocol::consensus::Network::MainNetwork;

        Self {
            db_path: "zns-mint.sqlite".into(),
            wallet_db_path: "zns-wallet.sqlite".into(),
            lwd_url: "https://zec.rocks:443".into(),
            network,
            birthday: 0,
        }
    }

    /// The registry's Orchard-only Unified Address (`addr_reg`) for this network.
    /// Delegates to the signer crate boundary so the host never sees spend seed material.
    fn registry_ua(&self) -> Result<String, zns_registry::RegistryError> {
        let addr = test_registry_address();
        let ua = zcash_keys::address::UnifiedAddress::from_receivers(Some(addr), None, None)
            .ok_or_else(|| {
                zns_registry::RegistryError::Config("could not build a Unified Address".into())
            })?;
        Ok(ua.encode(&self.network))
    }

    /// addr_reg's Unified Incoming Viewing Key — the published key
    /// (the one resolvers use to scan). We get the IVK via the signer boundary
    /// (no spend seed in the host) and do the (public) encoding here.
    fn registry_uivk(&self) -> Result<String, zns_registry::RegistryError> {
        use zcash_address::unified::{Encoding, Ivk, Uivk};
        use zcash_protocol::consensus::Parameters as _;

        let ivk_bytes = test_orchard_ivk().to_bytes();
        let uivk = Uivk::try_from_items(vec![Ivk::Orchard(ivk_bytes)])
            .map_err(|e| zns_registry::RegistryError::Config(format!("building UIVK: {e:?}")))?;
        Ok(uivk.encode(&self.network.network_type()))
    }

    fn scanner(&self) -> ScannerConfig {
        ScannerConfig {
            registry_ivk: test_orchard_ivk(),
            network: self.network,
            birthday: self.birthday,
            lwd_url: self.lwd_url.clone(),
        }
    }

    /// Config for the registry's treasury wallet (`zns_state::NoteState`).
    /// The FVK is obtained by asking a test-harness Signer (seed derivation stays inside
    /// the signer crate).
    fn treasury_config(&self) -> TreasuryConfig {
        // Temporary test-harness Signer just to extract the FVK. The real long-lived
        // signer for signing is created later via the same boundary.
        let test_signer = Signer::new_test(SpendPolicy {
            registry_addr: test_registry_address(),
            cold_addr: test_registry_address(),
            max_fee_zat: MINT_FEE_ZAT,
            target_float_zat: 0,
            high_watermark_zat: u64::MAX,
            low_watermark_zat: 0,
            max_mints_per_window: u32::MAX,
        })
        .expect("test signer for FVK");

        TreasuryConfig {
            registry_fvk: test_signer.fvk().clone(),
            network: self.network,
            birthday: self.birthday,
            lwd_url: self.lwd_url.clone(),
        }
    }

    /// Build the signing authority.
    /// The raw spend seed is derived inside the signer crate only (via new_test).
    /// The host never sees the seed bytes.
    fn signer(&self) -> Result<Signer, zns_registry::RegistryError> {
        let registry_addr = test_registry_address();

        // cold_addr == registry_addr (the COLD_ADDR_UA-unset fallback) keeps
        // sweeps a harmless no-op.
        let cold_addr = if COLD_ADDR_UA.is_empty() {
            registry_addr
        } else {
            parse_orchard_address(COLD_ADDR_UA, self.network)?
        };
        let sweeps_enabled = cold_addr != registry_addr;

        let policy = SpendPolicy {
            registry_addr,
            cold_addr,
            max_fee_zat: MINT_FEE_ZAT,
            target_float_zat: TARGET_FLOAT_ZAT,
            high_watermark_zat: if sweeps_enabled {
                HIGH_WATERMARK_ZAT
            } else {
                u64::MAX
            },
            low_watermark_zat: 2 * MINT_FEE_ZAT,
            max_mints_per_window: 4,
        };

        Signer::new_test(policy)
            .map_err(|e| zns_registry::RegistryError::Config(format!("constructing signer: {e}")))
    }

    fn mint_context(&self, tip_height: u32, signer: Arc<Signer>) -> MintContext {
        // Branch id for the active upgrade at the tip.
        let branch_id = zcash_protocol::consensus::BranchId::for_height(
            &self.network,
            zcash_protocol::consensus::BlockHeight::from_u32(tip_height),
        );
        MintContext {
            signer,
            hot_balance_zat: 0,
            anchor: orchard::tree::Anchor::empty_tree(),
            height: tip_height,
            expiry_height: tip_height + TX_EXPIRY_BLOCKS,
            network: self.network,
            circuit_version: self.circuit_version(),
            branch_id,
            treasury: None,
        }
    }

    /// Orchard circuit version to prove against — must match the circuit the
    /// target chain validates with for its active upgrade. The NU6.2 fix
    /// swapped the circuit/VK: pre-NU6.2 chains verify with
    /// `InsecurePreNu6_2`, post-NU6.2 with `FixedPostNu6_2`. Every live
    /// network (mainnet and testnet) is now post-NU6.2.
    fn circuit_version(&self) -> orchard::circuit::OrchardCircuitVersion {
        orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2
    }
}

/// Parse a Unified Address string into its Orchard receiver — used to decode
/// `COLD_ADDR_UA`.
fn parse_orchard_address(
    ua: &str,
    network: zcash_protocol::consensus::Network,
) -> Result<orchard::Address, zns_registry::RegistryError> {
    use zcash_keys::address::Address;
    match Address::decode(&network, ua) {
        Some(Address::Unified(addr)) => addr.orchard().copied().ok_or_else(|| {
            zns_registry::RegistryError::Config(format!(
                "COLD_ADDR_UA has no Orchard receiver: {ua}"
            ))
        }),
        _ => Err(zns_registry::RegistryError::Config(format!(
            "COLD_ADDR_UA is not a valid Unified Address: {ua}"
        ))),
    }
}
