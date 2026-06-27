# Context for src/boot.rs (zns-mint)

**This file exists so that any agent (or future human) can read the full design context, constraints, and intent of `boot.rs` without having to reconstruct it from code comments or chat history.**

Companion to `main.rs.context.md` — the overall-purpose, TEE/no-env-vars, single-seed/two-account constraints defined there apply here unchanged.

## Why this file exists

`main.rs` was deliberately kept as one tiny function for as long as possible. On 2026-06-27 the user authorized the **first expansion**: a separate `boot` module that owns the **boot phase** of the binary (everything between "tracing is initialized" and "enter the run loop"). This mirrors the "Boot Idea" section of `main.rs.context.md`.

Splitting boot out of `main` keeps `main.rs` readable and lets the boot sequence grow (seed blob → decrypt → derive → open DBs → connect → sync) without cluttering the single entrypoint. `main()` stays the orchestrator of phases; `boot.rs` owns *one* phase.

## Current State (as of this writing)

`boot.rs` is intentionally minimal and performs the early boot steps:

1. Connects to a Zebra indexer gRPC endpoint and runs a liveness check via `ChainTipChange`.
2. Performs ZIP-32 derivation of the two accounts using `Keys` (from `src/key.rs`):
   - Treasury (account 0)
   - Registry (account 1)
   `boot()` currently returns `Keys` directly. The user may later replace this with a richer `Accounts` type containing FVKS, addresses, etc.
3. Uses a temporary dev zero seed (`obtain_dev_seed`). This will be replaced by TEE-injected blob decryption + zeroization.
4. The hard-coded Zebra URL remains a `const` (no env vars, per project rules).

`async fn connect_zebra() -> ZebraClient` builds the gRPC client. Endpoint: `http://light.zcash.me:8230`.

No wallet DBs or full sync yet. Those come later.

## How the Zebra gRPC layer works (proto / `zebra-indexer-proto`)

`boot.rs` talks to Zebra over gRPC using the published crate [`zebra-indexer-proto`](https://crates.io/crates/zebra-indexer-proto) v2.3. Understanding the wire layer matters because it is the only chain I/O the binary currently has.

### Source of the bindings

- The proto schema is `indexer.proto`, originally vendored from Zebra's `zebra-rpc/proto/` tree. It defines `package zebra.indexer.rpc` and one gRPC service, `Indexer`.
- `zebra-indexer-proto` ships **pre-generated** Rust bindings committed under `proto/__generated__/`. A normal `cargo build` regenerates nothing and has **no `protoc` build dependency**. Maintainers regenerate with `cargo build --features regenerate`.
- The crate re-exports everything at the root for ergonomic single-import usage:
  - Messages/enums at crate root (`Empty`, `BlockHashAndHeight`, `BlockAndHash`, `BlockRequest`, `NonFinalizedStateChangeRequest`, `MempoolChangeMessage`).
  - `ZebraClient` = `IndexerClient<tonic::transport::Channel>` — a ready-to-use client with the default transport pinned, so callers don't need `tonic` in their own `Cargo.toml` to name the client type.
  - `ConnectError` = `tonic::transport::Error` (re-exported so `?` on `connect` doesn't pull `tonic` into our manifest).
- We import only `{ZebraClient, Empty}` in `boot.rs` today.

### The `Indexer` service surface (the 4 RPCs available)

From `indexer.proto`:

| RPC | Request | Returns | What it's for |
|-----|---------|---------|---------------|
| `ChainTipChange` | `Empty` | `stream BlockHashAndHeight` | Subscribe to best-chain tip changes. First message = current tip. **We use this for liveness.** |
| `NonFinalizedStateChange` | `NonFinalizedStateChangeRequest` (list of caller's known tip hashes) | `stream BlockAndHash` | Stream non-finalized (non-best-chain) blocks after the supplied tips. Used by syncers to bridge finalized→non-finalized. |
| `MempoolChange` | `Empty` | `stream MempoolChangeMessage` | Stream mempool adds/invalidations/minings. `MempoolChangeMessage.ChangeType ∈ {ADDED, INVALIDATED, MINED}` plus `tx_hash` and `auth_digest`. |
| `GetBlock` | `BlockRequest { hash_or_height: bytes }` | `BlockAndHash` | Fetch a finalized block by 32-byte hash (display order) or 4-byte big-endian height. Other lengths are rejected. |

Notes:
- `BlockHashAndHeight.hash` is **display order** (Zebra's standard), 32 bytes.
- `BlockAndHash.data` is an **encoded Zcash block** (the full serialized block, not the compact form). This is the heavier of the two block-fetch shapes; for light-wallet flows the compact-block streaming from lightwalletd is usually what we want instead, but the indexer proto is what's wired in here for now.
- This is **Zebra's indexer RPC**, distinct from the older `lightwalletd` `CompactTxStreamer` service (`service.proto` / `compact_formats.proto`). Both exist in the Zebra tree; we are using the newer direct-to-Zebra indexer interface.

### How `boot.rs` uses it today

```rust
let mut client = connect_zebra().await;            // ZebraClient::connect(URL)
let resp = client.chain_tip_change(Empty {}).await.expect("...");
let mut stream = resp.into_inner();                // Streaming<BlockHashAndHeight>
let tip = stream.message().await                  // first message = current tip
    .expect("no chain tip message")
    .expect("stream closed with no tip");
tracing::info!(height = tip.height, "zebra: liveness check passed");
```

This is a one-shot liveness probe: we connect, ask for the tip stream, pull exactly one message, and drop the stream. We are not yet subscribing to ongoing tip changes or driving a sync loop from it — both are future boot/run steps.

### Why a hard-coded public endpoint?

`http://light.zcash.me:8230` is a public Zebra indexer instance. It's a placeholder so the wiring can be exercised end-to-end before the TEE-bound config story lands. It is **not** loaded from env and **not** a CLI flag — it will be replaced by a value bound to the attested measurement / injected boot config once the seed-blob path is implemented (see Roadmap). Do not "fix" this by reaching for `std::env::var` — that would violate a critical constraint.

## Constraints (carried over + boot-specific)

- **No environment variables, ever.** The endpoint is a `const`, not env. Same rule as `main.rs.context.md`.
- **Minimalism.** Add boot steps one at a time, only when the user says so. Don't speculatively build the whole boot sequence.
- **No premature abstraction.** `Accounts` is two `u32`s for now. Don't turn it into a full key-handle struct until derivation actually lands.
- **Liveness before trust.** The first thing boot does after tracing is prove the chain connection is alive. Subsequent boot steps (decrypt, derive, open DBs, sync) should similarly fail loudly and early via `.expect(...)`/panics rather than soldiering on with partial state.
- **Fail loud.** `boot()` uses `.expect("...")` on the gRPC calls. Boot failures are fatal — the binary should not enter the run loop on a broken chain connection or missing seed.

## Roadmap (only when the user says so)

In roughly the order implied by the "Boot Idea" in `main.rs.context.md`:

1. Encrypted seed blob intake (injected by the TEE launcher; bound to measurement).
2. Decrypt the blob **inside** the TEE; zeroize plaintext ASAP after derivation.
3. ZIP-32 multi-account derivation → real `Accounts` (Treasury 0, Registry 1), plus Full Viewing Keys, the registry self-address, UIVK.
4. Open wallet DBs for both accounts.
5. Real sync of both accounts to the current tip (replacing/augmenting the single-message liveness probe; likely via ongoing `ChainTipChange` subscription + `GetBlock` backfill).
6. ZNS memo scanning setup (registry account), using the `Indexer` RPCs (and/or lightwalletd compact blocks) to feed the run loop.
7. Hand off to the run loop (see "Run Idea" in `main.rs.context.md`).

Each step should land as its own small change, with this file and `main.changelog.md` updated in the same change.

## For Future Agents / Maintainers

- Re-read this file **and** `main.rs.context.md` before changing `boot.rs`.
- `boot.rs` is the **only** place that owns the boot phase. Don't add boot logic to `main.rs` and don't add run-loop logic here.
- When you add a boot step, update this file (Current State + Roadmap) and append a dated entry to `main.changelog.md`.
- Don't reach for env vars, CLI args, or a config struct to parameterize `boot.rs`. The TEE/injected-blob model is the configuration story.
- If the proto surface changes (new RPCs, renamed messages, version bump of `zebra-indexer-proto`), update the table above and verify `boot.rs` still compiles — the crate pins generated bindings, so a major-version bump may require import/type changes.

## Related Files

- `src/main.rs` — entrypoint; declares `mod boot;` and calls `boot::boot().await`.
- `src/main.rs.context.md` — overall purpose, TEE model, single-seed/two-account design, Boot/Run ideas.
- `src/main.changelog.md` — chronological log of when context changed.
- `Cargo.toml` — `zebra-indexer-proto = "2.3"` plus key-derivation crates (`zcash_keys`, `zcash_protocol`, `orchard`, `zip32`) already declared for the upcoming derivation step.
- `zebra-indexer-proto` crate `src/lib.rs` and `proto/indexer.proto` (in the crate's registry src dir) — the authoritative proto/service definitions.
- `docs/ARCHITECTURE.md` — older, larger-architecture document from the pre-restart workspace; useful background on crate boundaries and the producer/consumer split but **not** the current code shape.

This context document should be kept up to date whenever `boot.rs` changes.
