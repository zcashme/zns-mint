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
