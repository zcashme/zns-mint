# main.changelog.md

Tracks when context for `src/main.rs` has been defined.

Detailed rules live in `main.rs.context.md`. This file only records the definition of context (keep it short).

## 2026-06-25
- Clean restart (`2cd9859`).
- Context defined in `main.rs.context.md`:
  - ONE SINGLE MAIN FUNCTION
  - No environment variables ever
  - TEE-injected encrypted seed blob (never human-visible)
  - Single seed → two ZIP-32 accounts (Treasury 0 for fees/sweeps, Registry 1 for Name Notes)
  - Keep extremely minimal until user explicitly directs expansion

## 2026-06-27
- First expansion past `main.rs`: added `boot.rs` module (declared as `mod boot;` in `main.rs`).
- `main()` now initializes `tracing`, logs startup, calls `boot::boot().await`, and logs the resulting `Accounts { treasury, registry }`.
- `boot::boot()` performs the first real boot step: connects to a Zebra indexer gRPC endpoint and runs a liveness check via `ChainTipChange` (streams the current chain tip; logs the tip height).
- Introduced the first non-tracing external dependency: `zebra-indexer-proto` (v2.3), exposing `ZebraClient` (a `tonic`-based gRPC client of Zebra's `Indexer` service). Generated from the vendored `indexer.proto`. See `boot.rs.context.md` for how the proto/RPC layer works and what's available.
- Hard-coded Zebra indexer URL `http://light.zcash.me:8230` is a temporary constant inside `boot::connect_zebra()`. Not env, not config — consistent with the no-env-vars rule.
- Seed/blob decryption, ZIP-32 account derivation, wallet DBs, and the run loop remain **not coded yet**; `boot()` currently returns placeholder `Accounts { treasury: 0, registry: 1 }`.

## 2026-06-27 (later)
- Added `mod key;` and wired real ZIP-32 derivation into boot.
- `boot()` now returns `Keys` directly (treasury acct 0 + registry acct 1) after the Zebra liveness check.
- Temporary dev zero seed with loud warning (will become TEE blob decrypt).
- `key.rs` tests now run as part of the crate.
- `main.rs` updated to receive the keys result.
- User noted: `boot` return type is temporary ("I will obviously change this").
- Updated `boot.rs.context.md`.

## 2026-06-27 (later still)
- Removed the incorrect `Booted` wrapper type from `boot.rs`.
- `boot()` now returns `Keys` directly, matching `main.rs` and the existing boot docs.

## 2026-06-27 (smoke test)
- Added an ignored Zebra smoke test in `boot.rs` that connects to the same hard-coded endpoint and exercises both `ChainTipChange` and `GetBlock`.
- The test requests the current tip block by height using `GetBlock` so we can validate whether the node is serving the block fetch RPC needed for sync/backfill.
- This is intended as a manual node-health check before building `sync.rs`.

## 2026-06-27 (exhaustive boot check + refactor)
- Upgraded the running Zebra node from `zfnd/zebra:latest` (5.2.0) to a `main`-based image built from source on the server (`zebra:main-local`). 5.2.0's indexer service did not implement `GetBlock` (it was added to Zebra `main` in PR #10776, merged Jun 23 2026, not yet released). State DB format is unchanged (v27 on both), so the 258G synced state was reused with no resync. Old container preserved as `zebra-old` for rollback.
- `boot.rs` now runs an exhaustive structural + integrity check of the tip block during boot, in a new `verify_tip_block` step. Added `zcash_primitives = "0.28"` as a dep to parse the block bytes via `Block::read` against `MAIN_NETWORK`. The check proves: the node serves a real mainnet block at the tip, the block parses + passes structural consensus invariants, the recomputed header hash matches both `GetBlock`'s and `ChainTipChange`'s reported hash (catches tampering/corruption and RPC disagreement), the claimed height matches the tip, and a coinbase is present. This is NOT full consensus verification (no PoW/merkle/tx-proof checks) — those remain Zebra's job.
- Refactored `boot()` from a single ~110-line function into a thin orchestrator calling named steps: `connect_zebra`, `liveness_check`, `verify_tip_block`, `derive_accounts`. Seed material is now touched only in `derive_accounts`, after every chain check has passed — making the "liveness before trust" boundary visually explicit. Removed the no-op `drop(keys)` (clippy: `drop_non_drop` — `Keys` has no `Drop` impl).
- Switched `key.rs` and `main.rs` from `TEST_NETWORK` to `MAIN_NETWORK`. `UnifiedSpendingKey::from_seed` uses the network's `coin_type` (mainnet=0, testnet=1), so deriving against `TEST_NETWORK` was producing testnet spending keys while `boot.rs` validated against mainnet and `main.rs` encoded FVKs with mainnet — a real inconsistency. Now the whole codebase is consistently mainnet.
- Smoke test restored and renamed to `zebra_smoke_liveness_and_verify_tip_block`; it now calls the split `liveness_check` + `verify_tip_block` functions instead of duplicating their logic.
- Updated `boot.rs.context.md` (Current State, How boot.rs uses it today, Roadmap).
