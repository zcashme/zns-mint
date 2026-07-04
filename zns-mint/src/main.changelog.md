# main.changelog.md

Tracks when context for `src/main.rs` has been defined.

Detailed rules live in `main.rs.context.md`. This file only records the definition of context (keep it short).

## 2026-07-01
- Separated `main.rs` into a binary/library split by creating `lib.rs` to anchor the module tree. `main.rs` continues to be a strictly thin orchestrator that imports the core logic from the library crate. No CLI/env-var parsing added.

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

## 2026-06-28 (sync module context)
- Added `src/sync.rs.context.md` and `src/sync.rs.changelog.md`.
- Documented the current birthday scan from height `3_000_000`, full-block `GetBlock` parsing path, one-UFVK scanner boundary, and known lack of DB/persistence/reorg handling.
- Updated `AGENTS.md` with the rule that source modules should always have an adjacent `*.context.md`.

## 2026-06-28 (sync start-height correction)
- Runtime scan from height `3_000_000` failed with `TreeSizeUnknown { protocol: Sapling }` because full-block scanning after Sapling activation requires prior tree sizes.
- Changed the temporary full-block scan start to Sapling activation height `419_200` and seeded the scanner with explicit block `419_199` metadata plus zero Sapling/Orchard tree sizes.
- Updated `src/sync.rs.context.md` and `src/sync.rs.changelog.md` to record that arbitrary post-Sapling birthday heights require a trusted checkpoint/tree-state source.

## 2026-06-28 (stored birthday checkpoint)
- Restored the intended scan birthday to height `3_000_000`.
- Added a stored mainnet checkpoint at `src/checkpoints/mainnet-2999999.json`, fetched from Zebra JSON-RPC `z_gettreestate("2999999")`.
- `sync.rs` now parses the stored checkpoint into `TreeState`/`AccountBirthday`, derives prior block metadata, verifies the checkpoint hash against Zebra `GetBlock(2_999_999)`, and then scans full blocks from `3_000_000`.
- Removed the live lightwalletd gRPC checkpoint fetch path from `sync.rs`.

## 2026-06-28 (key-material logging cleanup)
- Removed ready-time UFVK logging from `main.rs`; derived viewing keys are key material and must not be printed.
- Removed `Debug` from `Keys`, because it contains spending keys.
- Updated `main.rs.context.md` and `key.rs.context.md` to make the no-key-material logging boundary explicit.

## 2026-06-28 (orchard ZNS fork wired in as a git dep)
- Added the ZNS fork of `orchard` (`https://github.com/zcashme/orchard`, rev `e2ff14a3`, branch `main`) as a first-class git dependency in `Cargo.toml` with `features = ["unsafe-zns", "circuit"]`. This is the foundation for minting Orchard Name Notes: the fork's `unsafe-zns` feature exposes `Builder::add_zns_spend`, `Builder::add_zns_output`, `OutputInfo::new_zns`, and `Address::zns_commitment_keys`, which override the standard note commitment so a note commits to a ZNS payload instead of the spec-faithful `(recipient, value, rcm)`.
- Added a `[patch.crates-io]` entry so the transitive `orchard = "0.14"` consumed by `zcash_keys` / `zcash_primitives` / `zcash_client_backend` (from librustzcash rev `03cedf93`) is unified onto the same fork source. Verified via a throwaway probe that all four `unsafe-zns` symbols are reachable from the unified graph; `cargo build`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` all pass.
- The fork was force-pushed to `origin/main` on `github.com/zcashme/orchard` (overwriting two stale pre-rebase commits `f1b28c62` / `c0b174c5` whose work is fully represented — and evolved past — in the new tip `e2ff14a3`). No work was lost.
- This is wiring only: no `zns-mint` source file yet calls the ZNS builder API. The next step is the ZNS memo payload format and a signer path that reaches the Registry spending key.
- `Cargo.lock` now records `orchard` source as `git+https://github.com/zcashme/orchard?rev=e2ff14a3...`.

## 2026-06-28 (drop BootState)
- Removed the `BootState` wrapper struct from `boot.rs`; `boot()` now returns `Accounts` directly. `main.rs` destructures it inline. The struct had no behavior of its own, just accessors — it was premature abstraction.
- `boot()` no longer returns the verified tip height. The boot-time tip is stale by the time sync runs, and sync already connects to Zebra independently and re-fetches every block, so trusting boot's tip bought sync nothing. `sync::scan_to_tip` now fetches its own current tip via a one-shot `ChainTipChange` read.
- Updated `boot.rs.context.md` and `sync.rs.context.md`.

## 2026-06-28 (birthday treestate as binary protobuf)
- Replaced `src/checkpoints/mainnet-2999999.json` with `src/checkpoints/birthday.bin` — a binary protobuf-encoded `TreeState` (the wire-native form of `zcash_client_backend::proto::service::TreeState`). Same six fields, same values, native encoding instead of JSON.
- `sync.rs` now reads `birthday.bin` with `std::fs::read` + `TreeState::decode` (`prost::Message`). Removed `StoredCheckpoint` (the camelCase→snake_case mirror struct), `SCAN_START_CHECKPOINT_JSON`, `include_str!`, `serde::Deserialize`, and the field-by-field copy into `TreeState`. One read, one decode, no mirror.
- Removed `serde` (with `derive` feature) from `Cargo.toml`; added `prost = "0.14"` as a direct dep (already transitively present via `zcash_client_backend`).
- The birthday file is now data, not compile-time input: swapping it no longer requires a recompile (the old `include_str!` baked the JSON into the binary). Read once at boot, fail-loud if missing or malformed — same trust posture as the previous `expect("...malformed")` on the JSON path.
- `AccountBirthday::from_treestate` still does the real validation (parsing Sapling/Orchard hex frontiers into `Frontier`s); only the *transport* into `TreeState` changed, not the trust gate.
- Generated `birthday.bin` from the existing JSON via a one-shot Python script using `protoc`-compiled `service_pb2.TreeState`. The script is not part of the mint; the JSON file is deleted from the tree.
- Updated `src/sync.rs.context.md` and `src/sync.rs.changelog.md`.

## 2026-06-28 (Step 1: ZNS kernel — payload module)
- Added `mod payload;` (declared in `main.rs`): the mint's independent re-implementation of the shared ZNS kernel. Reference is the `zns-verify` crate (`/Users/jules/ZcashNames/zns-verify`), which is NOT pulled in as a dependency — producer and verifier keep separate copies of the spec so a derivation bug surfaces instead of cancelling out.
- `payload.rs` provides: `Action` (claim/update/release) + canonical bytes; name validation (DNS-label rule) + `canonicalize_name`; the per-name chain rule (`Tip`, `ZERO_PREV_RCM`, `prev_rcm_for`); the Name-Note memo grammar (`encode_name_note` / `parse_name_note`, strict `ZNS:<verb>:<name>:<ua>:<prev_rcm>`, ZIP-302 512-byte zero-padded); and `zns_psi_rcm(action, name, ua, prev_rcm) -> (psi, rcm)` via length-prefixed BLAKE2b-512 wide reduction. It does NOT re-implement Sinsemilla (the orchard `unsafe-zns` fork computes `cmx` from the `(rcm, psi)` here) and does NOT define the request-memo grammar yet.
- Pinned the four sacred cross-language vectors from `zns-verify::tests::vectors`; `zns_psi_rcm_matches_sacred_vectors` passes, confirming byte-for-byte agreement with the deployed verifier.
- Reconciled earlier design answers against the deployed spec: on-chain binding is `name -> ua` (Unified Address string), NOT Orchard FVK bytes (FVK concept dropped); actions are claim/update/release, not "register"; OTP authorization will live in request/challenge memos (deferred to the auth step), never in the Name Note, so Name Notes stay verifiable by unmodified `zns-verify`.
- New deps: `blake2b_simd = "1"`, `pasta_curves = "0.5"` (both already transitive via `zcash_spec` / orchard — no new compiled code).
- Added `src/payload.rs.context.md` and `src/payload.rs.changelog.md`. `payload.rs` carries `#![allow(dead_code)]` until the signer (Step 2) wires `zns_psi_rcm` / `encode_name_note`.
- `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo test` all pass (13 tests, 1 ignored smoke).

## 2026-06-28 (Step 2: Orchard Name-Note signer)
- Added `mod signer;` (declared in `main.rs`): the attested-boundary signer for the Registry account, the only consumer of the Registry spending key.
- `build_register` / `build_update` / `build_release` build, prove, and sign Orchard bundles that mint / update / release ZNS Name Notes, using `payload::zns_psi_rcm` for `(rcm, psi)` and `payload::encode_name_note` for the memo, fed to the fork's `Builder::add_zns_output` / `add_zns_spend`. Value-0 self-send to the Registry external address; spend-auth + binding nonces from `OsRng`; chain rule encoded (the new note's `prev_rcm` = the old note's `rcm`).
- Scope is bundle-level build/prove/sign verified with `verify_proof`. Sighash is a `[0;32]` stand-in (real v5 sighash, fee funding, broadcast, and real Merkle witnesses are Step 6). `build_register` is unit-tested end-to-end against the real ZIP-32-derived Registry spending key and `verify_proof` passes; `build_update` / `build_release` are compile-verified only (cannot construct a spendable `Note` outside orchard; exercised in Step 5/6). orchard `test-dependencies` deliberately NOT enabled (would pull `proptest` + `rand/std` into prod).
- `key.rs`: added `Keys::registry_orchard_spending_key` (`pub(crate)`, attested-boundary).
- New dep: `rand = "0.8"` (for `OsRng`; already transitive via orchard).
- Added `src/signer.rs.context.md` and `src/signer.rs.changelog.md`; updated `src/key.rs.context.md`. `signer.rs` carries `#![allow(dead_code)]` until Step 5.
- `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo test` all pass (15 tests, 1 ignored). Signer tests are slow (~2 min) from `ProvingKey::build()`; Step 5/6 must cache the proving/verifying keys.

## 2026-06-28 (Step 3: incoming memo detection in sync)
- `sync::scan_to_tip` now surfaces `detected_memos: Vec<DetectedMemo>` -- incoming Orchard memos (`TransferType::Incoming`) recovered via `zcash_client_backend::decrypt_transaction` (the only public memo path; `decrypt_block`/`scan_block` drop the memo). Only Orchard-bearing txs are trial-decrypted; capture happens before `decrypt_block` consumes the block.
- `payload::classify_memo` (new) classifies a 512-byte memo as `NameNote` / `ZnsRequest` / `NotZns` for the run loop. Full request parsing (incl. OTP) is the auth step; `ZnsRequest` is presence-only for now.
- `main.rs` logs the registry scan's detected memos via `classify_memo`, redacted (txid + action type only; name/ua are shielded user data and stay inside the attested boundary).
- `SyncState` gains `ufvk_map` for `decrypt_transaction`; `SyncReport`/`ScanSummary` gain `detected_memos` (`ScanSummary` no longer `Copy`).
- Known limitation: double trial-decryption of Orchard txs (extract pass + decrypt_block). Deferred to the run-loop step.
- Updated `src/sync.rs.context.md`, `src/sync.rs.changelog.md`. `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass (17 tests, 1 ignored).

## 2026-06-28 (Step 4/5: OTP auth + registry application pass)
- Added `mod auth;` and `mod registry;`.
- `payload.rs` now parses the confirmed request grammar and encodes OTP relay memos:
  user requests are `ZNS:claim:<name>:<ua>`,
  `ZNS:update:<name>:<ua>[:<otp>]`,
  `ZNS:release:<name>:<ua>[:<otp>]`; Registry relay is
  `ZNS:otp:<name>:<verb>:<ua>:<otp>`.
- `auth.rs` implements in-memory OTP issue/verify/consume scoped to `(name, action, ua)`.
  OTPs are 16-byte lowercase hex so they cannot be confused with 64-char Name Note
  `prev_rcm` fields.
- `registry.rs` applies observed Name Notes to in-memory state, validates requests,
  builds/proves/signs claim bundles, issues in-band OTP relay memos for update/release,
  and accepts authorized update/release into explicit `NeedsWitness` outcomes.
- `main.rs` now processes Registry memos through `Registry` with redacted logs rather
  than only classifying presence.
- `boot::Accounts` now retains the `Keys` handle internally and exposes a narrow
  `registry_orchard_spending_key` accessor for the registry/signer path.
- Remaining mainnet gaps are explicit: OTP relay broadcast, Treasury fee funding,
  full transaction assembly, real Orchard witnesses, persistence, reorg handling.

## 2026-06-28 (protocol docs spine)
- Added `docs/protocol/` as the protocol design source for the mint.
- Split the protocol into focused documents covering overview, trust model,
  accounts/keys, Name Notes, memo grammar, lifecycle, authorization, run loop,
  chain sync, transaction assembly, resolver verification, and open questions.
- `docs/protocol/07-mint-run-loop.md` records the target long-running loop shape
  that `main.rs` should eventually orchestrate while staying thin.
- Updated `src/main.rs.context.md` to point future `main.rs` work at the protocol
  docs before adding runtime machinery.

## 2026-06-28 (protocol decisions: payment, OTP, finality)
- Recorded that claim requires payment for the name, but the minted Name Note is
  still a value-0 Registry Name Note.
- Recorded that pending OTPs are in-memory operational state and expire 30
  minutes after issuance.
- Recorded that ZNS uses the immediate Zcash best chain as truth; reorgs are
  handled by rewind/replay rather than protocol-level confirmation depth.
- Removed payment binding from the protocol open questions: claim payment exists,
  but the mint authorization path does not need to bind payment to request
  parsing in the protocol docs.

## 2026-06-28 (programming model docs)
- Added `docs/protocol/12-programming-model.md` to describe the concrete
  software shape with Mermaid diagrams: Zebra interaction, mint database state,
  wallet maintenance, block processing, request handling, and coding order.
- Standardized the high-level term to "attested issuer" for ZNS Name Notes.
  The binary is the runtime for that issuer; the Zcash best chain remains the
  source of truth.
- Recorded that anyone can run a resolver with the Registry UFVK and chain data.

## 2026-06-28 (main run-loop skeleton)
- `main.rs` now has the target loop as live source showing the intended
  automatic orchestration shape: boot returns `boot::Sequence`, `main` drives
  chain events, mempool events, and shutdown, while scanner/wallet/registry/tx
  modules own the actual work.
- Extracted `init_tracing()` and removed today's one-shot dry-run body from
  `main.rs`; the file is intentionally ahead of the supporting module
  implementations.
- Updated `src/main.rs.context.md` with the target loop boundaries.

## 2026-06-28 (Zcash node I/O)
- Added `src/zcash.rs` as the top-level Zcash node I/O module file, with child
  modules under `src/zcash/`. There is intentionally no `src/zcash/mod.rs`.
- Added `src/zcash/chain.rs` for Zebra best-chain events:
  `ChainTipChange` for tip notifications and `GetBlock` for full block bytes.
- Added `zcash::chain::Event::{Block, Reorg}`, `VerifiedBlock`, `ChainPoint`,
  and `Chain::next_event()` so `main.rs` has a real chain module to target.
- Added `src/zcash/mempool.rs` with local mempool event primitives for Zebra
  `MempoolChangeMessage`.
- Current limitations are explicit: no multi-block backfill, no durable
  checkpoint input, and no true common-ancestor search yet.

## 2026-06-28 (implementation slices)
- Added `docs/protocol/13-implementation-slices.md` to break the mint into
  smaller coding problems: green baseline, terminology, wallet persistence,
  sync observations, Name Note witnesses, transaction assembly, Zebra
  submission, live best-chain loop, metrics, and TEE seed blob intake.
- Updated `12-programming-model.md` to point at the slice breakdown for the
  detailed coding order.

## 2026-06-28 (Zebra client construction module)
- Added `src/zcash/zebra.rs` as a deliberately tiny `pub(crate)` Zebra indexer
  client newtype.
- `zcash::chain::Chain` now stores `zcash::zebra::Client` instead of owning a
  raw `ZebraClient` and duplicate endpoint constant.
- Kept block verification, chain-event semantics, and mempool interpretation
  outside `zcash::zebra`; it is nominal construction glue only, not a broad
  client abstraction.

## 2026-06-28 (chain module stateless reads)
- Refactored `src/zcash/chain.rs` away from the incorrect `Chain` event-source
  struct.
- `chain.rs` now exposes stateless helpers over a caller-owned
  `zcash::zebra::Client`: `tip()` for the current best-chain tip and `block()`
  for full-block fetch/parse/verification.
- Replaced `ChainPoint`/`VerifiedBlock` with a single opaque `Block` wrapper for
  fetched blocks. `tip()` returns the bare `(BlockHeight, BlockHash)` pair
  because the Zebra tip RPC does not return block bytes.
- Removed the misleading `Event::{Block, Reorg}` shape from `chain.rs`; reorg
  detection requires caller-owned checkpoints and common-ancestor logic.

## 2026-06-28 (Zebra JSON-RPC transaction client)
- Added `src/zcash/transaction.rs` as the narrow Zebra JSON-RPC transaction
  boundary, matching the small-client pattern in `src/zcash/zebra.rs`.
- The allowlisted JSON-RPC surface is only `ping`, `getrawtransaction`, and
  `sendrawtransaction`; chain data remains on indexer gRPC.

## 2026-06-29 (Zebra JSON-RPC transaction skeleton)
- Fully implemented `src/zcash/transaction.rs` as the narrow JSON-RPC transaction boundary.
- Built `ZebraJsonRpcClient` wrapping `reqwest::Client` with a hard-coded Zebra URL, avoiding the heavy `jsonrpsee` dependency to keep the TEE footprint minimal.
- Implemented strictly typed JSON-RPC 2.0 envelopes (`RpcRequest`, `RpcResponse`, `RpcError`, `TransportError`) leveraging `serde`.
- Wired up `ping` (liveness), `raw` (`getrawtransaction`), and `send` (`sendrawtransaction`) methods.
- Refactored `main.rs` to temporarily comment out the unfinished `boot::boot()` and `loop` so the test binary compiles independently.
- Added comprehensive `wiremock` transport tests to independently verify JSON-RPC serialization, response parsing, and HTTP error mapping.
- **Unified Client**: Deleted `src/zcash/transaction.rs` and moved all JSON-RPC logic into `src/zcash/zebra.rs` so that there is only one `zcash::zebra::Client` struct holding both the `tonic` gRPC channel and the `reqwest` JSON-RPC connection. Tests were updated and pass successfully.
- **Decoupled Structs**: Realized that unifying gRPC and JSON-RPC into one struct conflates the "streaming state observer" (gRPC) with the "point-in-time submitter" (JSON-RPC). Split them inside `src/zcash/zebra.rs` into two distinct structs: `ChainClient` and `RpcClient`.
- **Actor Pattern Refinements**: Refactored `src/zcash/chain.rs` to wrap the raw gRPC client in a domain-specific `Client` and shifted architecture toward domain-specific background loops (e.g., `chain` block polling, `mempool` streaming) that yield channel receivers to the orchestrator, avoiding a single `Network` god-object.

## 2026-06-29 (main wires real boot + shutdown wait)
- `main()` is no longer a stub: it calls `boot::boot().await`, destructures
  `(chain, accounts, tip_height)`, sets `metrics::set_boot_success(true)`,
  logs the boot-complete + ready lines with the tip height, and then awaits
  SIGINT/SIGTERM (Ctrl-C off-unix) before exiting. `init_tracing()` is kept.
- No speculative run-loop machinery (chain poller, mempool, scanner, wallet,
  registry, tx) was added; the `boot::Sequence` / `loop { ... }` skeleton
  comments were removed because they gestured at modules that do not exist
  yet (see commits `23f6d23` / `b2128b5`). Per the AGENTS.md "only expand when
  I explicitly say so" rule, those modules come back when the user asks.
- `#![allow(dead_code)]` kept at the crate root: boot is the only caller of
  the wired modules today, so `sync`/`chain`/`zebra` helpers remain ahead of
  their callers by design (already the project's pattern, per
  `main.rs.context.md`).
- `shutdown()` is a small `tokio::select!` over Unix signal handlers; off-unix
  falls back to `tokio::signal::ctrl_c()`. No env vars, no config.
- `mod auth` stays commented out: `payload`/`signer`/`registry` were removed
  in `23f6d23` and have not been re-added.
- `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
  pass (6 passed, 1 ignored).

## 2026-06-29 (ZNS-owned birthday checkpoint)
- Moved birthday tree-state handling away from lightwalletd protobuf
  `TreeState` and into a ZNS-owned JSON checkpoint schema.
- `zcash::zebra::JsonRpc` now owns Zebra `z_gettreestate`, creates
  `src/checkpoints/birthday.json` if it is missing, and validates existing
  checkpoints without silently overwriting bad data.
- `sync.rs` now consumes checkpoint-derived `BlockMetadata` through the Zebra
  boundary and no longer imports `prost::Message` or lightwalletd proto types.
- The design remains one static birthday checkpoint plus in-memory runtime
  wallet state; no rolling persistent wallet checkpoint was added.

## 2026-06-29 (wallet design + treasury stub + account-role flip)
- Added `docs/protocol/14-wallet-design.md`: in-memory wallet design (per-account
  note maps, shared nullifiers + tree + undo buffer, Registry Name Note
  witnesses, reorg rewind, ZNS-specific Registry view, Treasury request
  surface, sync flow, integration boundaries). Indexed in protocol README.
- Added `src/treasury.rs` + `src/treasury.rs.context.md` as a registered stub
  module (declared as `mod treasury;` in `main.rs`). Compiles empty, per the
  "only expand when I say so" rule.
- Account-role flip driven by user direction: Treasury no longer pays Name
  Note fees; Registry self-funds its Name Note transactions, and Treasury is
  the user-facing account (name payments, request memos, OTP relay memos).
  This contradicted prior protocol text in 01/02/04/06/09/12/13. All of those
  docs were rewritten in the same change to reflect:
  - Treasury (acct 0): receives name payments + request memos, sends OTP relay
    memos, funds OTP relay fees; never authorizes Name Notes.
  - Registry (acct 1): name-notes-only, sole signer for Name Note lifecycle,
    self-funds Name Note fees; never receives user request memos, never relays
    OTPs.
- `main.rs.context.md` account-assignment section updated to reflect the new
  Treasury / Registry roles (was "pays fees / can sweep excess" + "creates/spends
  the special Name Notes"; now user-facing payments/OTP relay vs name-notes-only
  with self-funded fees).

## 2026-06-30 (context docs synced to current code)
- Updated stale `*.context.md` files so the protocol docs remain the source of
  design truth and the code is the source of current state.
- `src/main.rs.context.md`: Current State now lists the modules actually
  declared in `main.rs` (`boot`, `key`, `metrics`, `sync`, `treasury`, `zcash`),
  notes there is no run loop yet (`main()` boots then `std::future::pending`
  forever, no shutdown handler), and the Boot/Run State sections match what the
  code does. Dependency surface records that the `unsafe-zns` orchard surface is
  unreached by current source.
- `src/auth.rs.context.md`: documents that `mod auth;` is commented out in
  `main.rs` so the module is not in the build graph and nothing runs it; the file
  is preserved as a design reference.
- `src/key.rs.context.md`: `registry_orchard_spending_key` accessor description
  updated — it currently has no caller in-tree.
- `src/treasury.rs.context.md`: dropped the stale `src/registry.rs` related-file
  reference.
- `src/sync.rs.context.md`: Related Files now state no checkpoint file is
  checked in; `src/checkpoints/` is empty until first boot.
- `src/zcash/zebra.rs.context.md`: birthday checkpoint section now states the
  on-disk file is created at runtime (no file checked in), and notes
  `load_or_create_birthday_checkpoint` is currently unused in-tree.
- `src/zcash/chain.rs.context.md`: Related Files corrected — `boot.rs` runs its
  own liveness cross-check (not "duplicates" this module), and `sync.rs` no
  longer fetches blocks itself (the orchestrator hands verified blocks into
  `Wallet::scan_verified_block`).
- `src/zcash/mempool.rs.context.md`: Current State now reflects that
  `spawn_observer` exists as a stub loop with no caller, rather than "no live
  stream client yet".
- Deleted `src/checkpoints/birthday.bin`: stale binary protobuf `TreeState` from
  an earlier format that the current `zcash::zebra` JSON-schema code cannot read
  or write. The on-disk checkpoint is created fresh as `birthday.json` on first
  boot via `load_or_create_birthday_checkpoint`.

## 2026-06-30 (signer refs nuked + Treasury module / auth / OTP-relay split)
- Removed stale `signer` / `src/signer.rs` references from protocol docs and
  context files. `signer.rs` was removed in commit `23f6d23` but ~31 doc
  references still talked about it as live. Replaced with role language
  ("Registry transaction signing path", "transaction-assembly path") or
  removed. Historical changelog entries left intact (a log is a log).
- Clarified the Treasury account vs Treasury module vs auth vs
  transaction-assembly boundary for OTP relay:
  - Treasury **account** (ZIP-32 acct 0) is the shielded origin of OTP relay
    memos.
  - `auth.rs` is the **sole OTP credential authority**: issuance, verification,
    expiry, one-time consumption, OTP relay memo byte construction. Does not
    sign or broadcast.
  - `treasury.rs` owns Treasury **wallet state and Treasury policy**
    (auto-sweep to a transparent address, funding the Registry account,
    `select_funds`). Does NOT sign OTP relay transactions. Does NOT own OTP
    credentials.
  - transaction-assembly (future, no module yet) is the only consumer of both
    spending keys; it signs and broadcasts OTP relay, auto-sweep, Registry
    funding, and Name Note transactions.
- `src/auth.rs` module doc + `IssuedOtp.memo` comment + `src/auth.rs.context.md`
  rewritten to reflect Treasury account as OTP origin, auth as credential
  policy only, and the three-way split. `mod auth;` remains commented out in
  `main.rs` (module still aspirational; depends on not-yet-restored
  `crate::payload`).
- `docs/protocol/14-wallet-design.md`: added F10 (Treasury Policy vs OTP Relay
  vs Auth — Separation); Scope and Module Boundaries sections rewritten; F3
  spend-authority section rewritten to cover both spending keys and explicitly
  state the wallet/treasury/registry modules never see them.
- `docs/protocol/02-accounts-and-keys.md`: added "Treasury Spending Key"
  section; "consumed only by the signer path" -> "consumed only by the
  Registry transaction signing path".
- `docs/protocol/09-transaction-assembly.md`: "Current Gap" rewritten — there
  is no signer today; the gap is build/prove/sign + assembly + funding +
  broadcast. Sighash section generalized.
- `docs/protocol/12-programming-model.md`: component diagram replaced
  `Signer[signer.rs]` with `Treasury[treasury.rs]` + `Auth[auth.rs\nOTP
  credential policy]`; wiring redrawn (Treasury -> Wallet, Treasury -> Tx,
  Registry -> Auth, Registry -> Tx, Tx -> Zebra).
- `docs/protocol/00-overview.md`, `13-implementation-slices.md`, `README.md`:
  signer references removed; auth role and Treasury module boundary reflected.
- `AGENTS.md`: Treasury=0 description updated from "pays fees/sweeps" to
  user-facing account (name payments, request memos, shielded origin of OTP
  relay memos); Registry=1 now notes self-funds its Name Note fees.
- `src/key.rs.context.md`: noted `treasury_orchard_spending_key` accessor is
  not yet present and must follow the Registry accessor's handling rules when
  added.
- `cargo build`, `cargo clippy --all-targets -- -D warnings` pass.

## 2026-06-30 (registry module context)
- Added `src/registry.rs.context.md`. No `src/registry.rs` file, no
  `mod registry;` in `main.rs` — design doc only, per "design doc only"
  instruction.
- Defines the Registry module as the ZNS state machine over the wallet
  layer's `NameChain` view: enforces the `05-lifecycle.md` chain rule
  (claim free/released, update/release live+`prev_rcm`), resolves
  `prev_rcm` (`ZERO_PREV_RCM` for claim, tip `rcm` otherwise), and produces
  typed `NameNoteRequest`s for the transaction-assembly path.
- Boundary per `14-wallet-design.md` F7/F9/F10: reads wallet state, calls
  `auth::OtpStore::verify_consume` for update/release, asks `payload.rs`
  to parse memos. Does not sign, prove, fee-select, broadcast, or hold
  spending keys; those stay in `key.rs` + the future transaction-assembly
  path.
- Cross-account claim-handoff interface (Treasury payment-accepted signal
  -> Registry mint) left as an open question, matching
  `14-wallet-design.md`; not invented silently.
- Depends on not-yet-in-tree `wallet.rs` and `payload.rs`, and on the
  currently-unwired `auth.rs`. First implementation should wait for Slice 2
  (wallet boundary) and `payload.rs` restoration.

## 2026-06-30 (treasury module design)
- Added `docs/protocol/15-treasury-module.md`: full design for the
  `treasury.rs` module. Indexed in protocol README.
- Three design decisions locked with the user:
  - T1 state ownership: Treasury module borrows the Treasury slice from the
    shared `Wallet` (`wallet.treasury()`). Owns no note map of its own;
    stateless policy layer over borrowed wallet state.
  - T4/T5 policy inputs: hardcoded constants in `treasury.rs`
    (`SWEEP_ADDRESS`, `SWEEP_THRESHOLD`, `SWEEP_RESERVE`,
    `REGISTRY_FUNDING_FLOOR`, `REGISTRY_FUNDING_TOPUP`). No env vars, no
    config files — consistent with AGENTS.md.
  - T6 payment detection: Treasury owns detection
    (`match_payment(request, price) -> Option<&SpendableNote>`), caller owns
    pricing. The user pushed back on conflating detection with pricing
    strategy; pricing is protocol policy supplied by the caller.
- Six features: T1 wallet view, T2 `select_funds`, T3 request memo
  classification, T4 auto-sweep policy, T5 Registry funding policy, T6 claim
  payment detection. Per-block evaluation order: T3 -> T6 -> T5 -> T4.
- Load-bearing exclusions documented: does NOT sign (transaction-assembly
  does), does NOT own OTP credentials (`auth.rs` does), does NOT decide name
  pricing (caller does), does NOT mint Name Notes (Registry does).
- Open questions recorded: payment memo grammar (not in
  `04-memo-grammar.md` yet), auto-sweep + Registry funding same-block
  accounting, shared `select_funds` policy fit, reorg handling for matched
  payments.
- `src/treasury.rs` module doc comment rewritten (was stale: claimed
  ownership of "OTP issuance policy" and "OTP relay transaction requests",
  both ruled out by F10).
- `src/treasury.rs.context.md` rewritten to match the new design (was stale:
  same OTP-issuance claim).
- `docs/protocol/14-wallet-design.md` F8 and F10 and Module Boundaries
  updated to reference `15-treasury-module.md`.
- `cargo build`, `cargo clippy --all-targets -- -D warnings` pass.

## 2026-06-30 (wallet module - Slice 2)
- Added `src/wallet.rs` + `src/wallet.rs.context.md`: the in-memory wallet
  state, split out of `sync.rs`. Registered in `main.rs` as `mod wallet;`.
- `Wallet` is **account-agnostic**: it holds notes indexed by `AccountId` in
  `HashMap<AccountId, HashMap<[u8; 32], SpendableNote>>` and does not know
  that account `0` is the Treasury or account `1` is the Registry. The user
  directed this: "wallet shouldn't concern itself with the registry or
  treasury it's just a wallet." Account roles are imposed by the treasury
  and registry modules on top of this generic wallet.
- Public surface: `Wallet::new(accounts, prior_block_metadata)` taking any
  `IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>`; `notes_for(id)`,
  `balance(id)`, `note(nf)`, `undo_len()`. Crate-private `insert_note` /
  `remove_note` / `scanning_keys` / `ufvk_map` / `nullifiers` / `nullifiers_mut`
  for the scanner.
- `SpendableNote` and `UndoState` currently live in `sync.rs` and are
  imported by `wallet.rs` via `use crate::sync::SpendableNote`. Temporary
  arrangement pending full trim of `sync.rs`.
- `src/sync.rs` rewritten: no longer defines `Wallet`; `scan_verified_block`
  is now a free function `fn scan_verified_block(&mut Wallet, Block) -> Result<...>`.
  `scan_to_tip` is now `fn scan_to_tip(&mut Wallet)`. The scanner is
  account-agnostic and routes notes to the wallet by `account_id`.
- `src/sync.rs.context.md` rewritten to reflect the split (scanner owns no
  wallet state; wallet state is in `wallet.rs`; scanner is account-agnostic).
- `14-wallet-design.md` still describes typed `treasury()` / `registry()`
  accessors; the implementation exposes generic `notes_for(account_id)` /
  `balance(account_id)` instead, with the treasury/registry modules imposing
  the role. Design doc will be updated to match in a follow-up.
- User explicitly rejected reintroducing `payload.rs` ("what the f--- is
  payload.rs? i don't want a payload.rs"). Memo parsing will live inline in
  whichever module needs it (treasury parses request memos, auth encodes OTP
  memos, registry parses Name Note memos). Stale `payload.rs` references
  remain in some docs and will be cleaned up as each module is implemented.
- `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
  pass (6 passed, 1 ignored).

## 2026-06-30 (wallet design reset — scanner state out of the wallet)
- Rewrote `src/wallet.rs.context.md` from scratch. The previous version
  described a `Wallet` carrying `tree`, `nullifiers`, `undo_buffer`, and
  `prior_block_metadata` in one struct — a leak from the deleted
  `sync.rs::Wallet` that mixed scanner state and note state. The new design
  narrows the wallet to **two tables only**: a notes table (per-note facts
  keyed by note identity, with a separate nullifier index for the one hot
  point-query) and a commitment tree (scanner appends, signer reads at sign
  time to build witnesses from `(position, tree)`). Scanner state — block
  cursor, undo log, reorg logic — is explicitly out of scope and belongs in
  the future scanner module.
- Three design decisions recorded in the context doc, all driven by user
  direction in this session:
  - **Wallet is chain-stupid.** No `prior_block_metadata`, no `undo_buffer`,
    no `UndoState`, no reorg awareness. The wallet holds notes + a tree;
    the scanner drives both via reversible primitives (insert/remove/
    append). The scanner owns the undo log and calls back to reverse its
    own mutations; the wallet just provides symmetric ops.
  - **Notes keyed by note identity (rho), not nullifier.** Keying by
    nullifier was the old layout and is semantically inverted — the
    nullifier is the note's death certificate, not its identity. The hot
    query (scanner spend-detection) is by nullifier, but that is served by
    a separate `HashMap<Nf, (AccountId, Rho)>` index mirroring the SQLite
    `nf BLOB UNIQUE` column, not by the row identity. `rho` is the natural
    row identity: intrinsic to the note, already in `Note`, no extra
    threading, survives reorg without churn, and is the preimage the
    nullifier is derived from. Matches librustzcash's model (notes keyed by
    `id`/`(txid, action_index)`, nullifier as a separate `UNIQUE` column).
  - **No per-note living `IncrementalWitness`.** Witnesses are derived
    from `(position, tree)` at sign time, matching librustzcash's
    `witness_at_checkpoint_depth(position, 0)` path. Per-note living
    witnesses were considered (more memory, more per-block churn) and
    rejected. The wallet owns the tree; the scanner appends to it; the
    signer reads it at sign time.
- `SpendStatus` enum recorded in the context doc as the honest version of
  "non-spendability is like an ERROR": `Spendable` / `AwaitingConfirmations`
  / `WitnessUnavailable` / `ReorgedOut` / `Uneconomic`, checked by the
  selection path rather than panicking. Confirmation policy (1 confirmation
  vs N) left open to confirm with the user.
- `src/wallet.rs` left as `pub struct Wallet;` (empty) with a doc-comment
  sketch of what the code MIGHT look like, per user direction ("leave ONLY
  comments on what the code MIGHT look like in wallet.rs"). The
  `pub struct Wallet {}` body was removed; the empty unit-like struct
  compiles cleanly.
- `cargo build`, `cargo clippy --all-targets -- -D warnings` pass.

## 2026-06-30 (sync module deleted)
- Deleted `src/sync.rs`, `src/sync.rs.context.md`, `src/sync.rs.changelog.md`.
  Removed `mod sync;` from `main.rs`.
- `SpendableNote` and `UndoState` moved from `sync.rs` into `wallet.rs` so
  `wallet.rs` is self-contained.
- The user directed deletion: "i don't think it's time for the sync module
  yet let's delete the sync module i will review the wallet module." The
  scanner pipeline (`scan_verified_block`, `scan_to_tip`, birthday
  checkpoint seeding) will be reintroduced in a future scanner module when
  the user asks.
- Updated live context docs to remove stale `src/sync.rs` references:
  `wallet.rs.context.md`, `main.rs.context.md`, `zcash/zebra.rs.context.md`,
  `zcash/chain.rs.context.md`, `registry.rs.context.md`,
  `docs/protocol/13-implementation-slices.md`,
  `docs/protocol/14-wallet-design.md` (Scope, Syncing, Module Boundaries,
  "What Moves Out Of sync.rs" -> "What Moved Out Of sync.rs (Now Deleted)",
  Related Files).
- Historical `main.changelog.md` entries that mention `sync.rs` left intact
  (a log is a log).
- `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
  pass (6 passed, 1 ignored).
