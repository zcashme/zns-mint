# zns-mint orchestrator — phase plan & status

Block-linear orchestrator: scan from `birthday` → tip, single-lane spend, names
persisted **only when registry Name Notes appear on chain** (not at broadcast).
No mint intents, no persisted spend queue. **10s** poll.

Last updated: 2026-06-15

---

## Architecture (agreed)

| Topic | Decision |
|-------|----------|
| Scan | Blocks; `scan_tip` advances only after a block is fully classified |
| Spend | One outbound tx at a time; treasury synced once per tick before spend |
| Name persistence | On-chain Name Note sight → `apply_mint`; not at broadcast |
| Request settlement | Mint → Name Note on chain; OTP relay → `transaction_exists`; UPDATE/RELEASE request → relay confirms |
| Rejects | Permanent at scan (bad memo, dup claim, low fee, unknown name); transient spend errors re-queue |
| Spend queue | In-memory only (`SpendLane`); no SQLite `spend_queue` |
| Crash recovery | Startup rewind `scan_tip` to `birthday - 100` (`STARTUP_REWIND_BLOCKS`) |
| Treasury | Optional; auto-bootstrap via `get_tree_state` at `birthday - 1` if wallet uninitialized |
| In-flight | `InFlightSpend` in registry DB: `relay` / `sweep` / mint (await name note) |

### Tick order

```
reorg → purge challenges → treasury sync → scan catch-up → spend → sweep (if idle) → record status
```

### Key paths

| Path | Role |
|------|------|
| `mint/src/lib.rs` | `Mint::boot`, `run`, `tick` |
| `mint/src/scan.rs` | Block intake, enqueue, classification |
| `mint/src/spend.rs` | Single lane, dispatch, in-flight reconcile |
| `mint/src/record.rs` | On-chain name persistence |
| `mint/src/sweep.rs` | Cold sweep when lane idle + above high watermark |
| `mint/src/rpc.rs` | JSON-RPC control plane (`health`, `status`) |
| `mint/src/status.rs` | Per-tick observations for RPC |
| `mint/src/shutdown.rs` | SIGINT / SIGTERM graceful stop |
| `state/src/block_cache.rs` | Persistent compact-block cache (treasury BlockDb) |
| `state/src/treasury.rs` | WalletDb + `sync` + `select_funding` |
| `state/src/orchestrator.rs` | `scan_tip`, `in_flight_spend` |

### Config (env)

| Variable | Default | Notes |
|----------|---------|-------|
| `ZNS_LWD_URL` | `https://zec.rocks:443` | lightwalletd |
| `ZNS_REGISTRY_DB` | `zns-registry.sqlite` | |
| `ZNS_TREASURY_WALLET_DB` | `zns-treasury.sqlite` | |
| `ZNS_TREASURY_BLOCK_DB` | `zns-treasury-blocks.sqlite` | |
| `ZNS_BIRTHDAY` | `2000000` | |
| `ZNS_HIGH_WATERMARK_ZAT` | `5000000` | cold sweep threshold (0.05 ZEC) |
| `ZNS_RPC_BIND` | *(empty)* | e.g. `127.0.0.1:8332`; empty = RPC off |

---

## Phases — done

### Phase 0 — Compile
Workspace builds; stub/fix type errors (`SpendPolicy`, `ScanSyncError`, mutex spend queue, etc.).

### Phase 1 — Spec alignment
- Dropped `spend_queue` table/APIs; `QueuedSpend` / `SpendVerb` in-memory
- `Treasury: Option<Mutex<Treasury>>` → scan-only if unavailable
- Startup `scan_tip` rewind

### Phase 2 — Behavior
- Signer: `RelayResult`, `derive_psi_rcm`
- `record.rs`: Name Note → `apply_mint`, in-flight mint clear
- `spend.rs`: CLAIM / UPDATE+challenge / CONFIRM / RELEASE; reconcile relay vs mint expiry
- `scan.rs`: classification, dup claim, UPDATE defer if challenge pending

### Phase 3 — Operations
- `Mint::boot` async: treasury bootstrap via `tree_state`
- Tick: reorg → `SpendLane::reset()`, purge challenges
- Relay confirm → `mark_processed` on request
- Binary: `MintConfig::from_env()`, tracing subscriber

### Phase 4 — Treasury & sweep
- `PersistedBlockCache` (SQLite `compactblocks`); `Treasury::sync(&mut client)` only
- Treasury sync **once per tick** (removed per-spend ephemeral cache)
- `mint_intents` removed from schema/API/reorg
- Cold sweep (`sweep.rs`) + `InFlightSpend.sweep`
- Light tests: state reorg/in-flight, spend lane idle

### Phase 5 — Control plane
- JSON-RPC: `health`, `status` (read-only)
- `status` fields: tip, scan_tip, spendable, mempool count, queue depth, in_flight, registry counts
- `ZNS_RPC_BIND`; status recorded each tick

### Phase 6 — Hardening
- Graceful shutdown: SIGINT + SIGTERM (Unix), Ctrl-C elsewhere; finish current tick then exit
- RPC `stop()` on shutdown
- Scan intake unit tests (enqueue, fee floor, dup claim, unknown name, unconfirmed skip)

---

## Deferred (not scheduled)

Explicitly **out of scope for now** — do not block current orchestrator work.

| Item | Notes |
|------|-------|
| **Production signer** | Non-test seed (TEE / sealed env); replace `Signer::new_test` + `test_*` IVK/FVK helpers in boot |
| **Mocked-gRPC tick harness** | Full `tick()` integration test without lightwalletd |
| **Mempool-aware scan deferral** | Beyond current “unconfirmed → skip” (e.g. defer UPDATE until mempool confirms) |
| **Spend policy hardening** | Real `admit_sweep` / velocity limits beyond test stubs |
| **systemd / sd-notify** | Ready/ stopping notifications |
| **Metrics / Prometheus** | `metrics` crate is in workspace catalog only |
| **Auth on JSON-RPC** | Old zallet-style RPC auth not ported |
| **Treasury reorg rewind** | WalletDb rewind on chain reorg (orchestrator rewinds registry only today) |

---

## Tests (current)

```bash
cargo test -p zns-state --lib    # registry + in-flight/reorg
cargo test -p zns-mint           # rpc, scan intake, spend lane
cargo check -p zns-mint
```

---

## Stale docs

`treasury-sync-architecture.mmd` / `.html` describe the **pre–Phase 4** design (ephemeral cache, dummy NoteState, disabled sync). Prefer this file and the code paths above.