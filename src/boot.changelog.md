# Boot module changelog

Tracks design-relevant changes to `src/boot.rs`.

## 2026-09-08 — The proving parameters stop crossing the seam

- `Boot` no longer carries `sapling_spend`/`sapling_output`; `into_parts`
  returns ten parts, not twelve. The loaders stay in this module — now
  `pub(crate)` — and the orchestrator's prologue acquires them itself.
- The seam criterion, now written down: **a value crosses only if the loop
  cannot acquire it for itself, or must not.** Keys, origin, wallet, clock,
  oracle, and the chain connection pass it. The proving parameters fail it —
  the loop can load them with the same fail-loud checks — so boot stops
  couriering them.
- The load pattern is upstream-documented: `SpendParameters::read`'s
  `verify_point_encodings: false` is prescribed "if you are verifying the
  parameters in another way (such as checking the hash of the parameters
  file on disk)" (sapling-crypto 0.7.0, `circuit.rs`). Hash-then-read is
  that documented way, not custom paranoia.

## 2026-08-22 — Direct fixed-UFVK WalletDb construction

- Boot now passes the two fixed Treasury/Registry UFVKs directly to `Wallet`.
  The wallet does not own a mutable account registry, ZIP-32 derivation record,
  or account birthday. No seed or spending key enters the database.
- Boot extracts the three verified Zebra frontiers before calling
  `Wallet::seed_trees`; the wallet layer does not depend on `CheckpointData`.

## 2026-07-30 — Boot-proven consensus parameters

- Production `Boot::run()` remains parameterless and hardcodes upstream
  `MAIN_NETWORK`; its mainnet identity, activation, seed, and attestation
  requirements remain intact.
- The debug-only `Boot::run_regtest()` pins Zebra's harness schedule and
  immutable regtest genesis, then uses the same boot core. It is unavailable
  without `regtest`, which is rejected in release builds.
- `Boot<P>` carries the exact concrete `P: Parameters` that validated boot into
  the run loop. No global mutable network and no runtime parameter discovery
  are permitted.

## 2026-07-30 — Removed wall-clock freshness gate

- Removed the two-hour wall-clock freshness assertion from boot. It conflated
  block timestamps with consensus/network identity and rejects deterministic
  regtest chains for a non-consensus reason. Boot still proves local Zebra
  reachability, gRPC/JSON-RPC tip agreement, pinned genesis identity, and the
  required consensus-upgrade baseline before key derivation.

## 2026-07-30 — Hash-only genesis identity

- Changed the genesis identity check from full-block parsing to Zebra's
  `getblockhash(0)`. Upstream `Block::read` deliberately rejects the genesis
  block, so parsing it would make every correct boot fail before identity could
  be established.

## 2026-07-25 — Mainnet genesis network-identity check

- `verify_chain_integrity` now obtains the genesis hash via JSON-RPC and
  asserts it equals `zcash::MAINNET_GENESIS_HASH` before deriving keys or
  fetching the Ironwood origin checkpoint.
- The genesis check is a secondary guarantee: the primary guarantee that
  only mainnet Zebra runs inside the TEE remains the SEV-SNP image measurement.
- Removed the placeholder `PINNED_ORIGIN_HASH` assertion from
  `origin_checkpoint`; the origin checkpoint hash is now accepted from the
  verified mainnet Zebra node and stored in metadata for reference.

## 2026-07-25 — TEE seed-injection hardening

- The expected ZIP-32 seed fingerprint is now compiled into the binary from
  `deployment/seed_fingerprint.txt` (a deployment artifact, not a runtime config
  file). The placeholder value causes boot to fail closed if it is not replaced.
- `verify_fingerprint` now takes the expected fingerprint as an argument and
  redacts the panic message on mismatch: neither the actual nor the expected
  fingerprint is printed, so seed-derived material cannot leak via panic text
  or logs.
- `decrypt_sealed_blob` was split into `decrypt_capsule(blob, key)` so key
  derivation and AEAD decryption are separately testable without touching real
  SEV-SNP firmware.
- `SeedCapsule` derives `Serialize` for synthetic test fixtures.
- A single minimal unit test asserts that a fingerprint mismatch panics with
  the redacted message.

## 2026-07-23 — Typed account capabilities at boot

- Boot derives `TreasuryKeys` and `RegistryKeys` through fixed account-specific
  functions and retains those types through `Boot::into_parts` and attestation
  report-data construction.
- The runtime can no longer exchange account-0 and account-1 authority through
  a shared role-neutral key type.

## 2026-07-22 — BlockHeight type fix for origin checkpoint

- Replaced `ironwood_activation_height() - BlockHeight::from_u32(1)` with
  `ironwood_activation_height().saturating_sub(1)` so the result stays a
  `BlockHeight` rather than the `u32` difference between two heights.
- This fixes the `get_checkpoint` argument mismatch surfaced by `cargo check`
  after the Orchard fork compile error was resolved.

## 2026-09-07 (birthday origin)
- `MINT_BIRTHDAY` (3_400_000) hoisted to `mint.rs`; `origin_checkpoint` now
  fetches `z_gettreestate(MINT_BIRTHDAY - 1)`. The NU6.3 activation anchor
  and its rationale are deleted — the birthday is identity, not a derived
  consensus height.
- `Boot::checkpoint_metadata` deleted (no callers); `boot::block_metadata`
  moved to `wallet.rs` and re-exported, so `Wallet::new` and the run loop
  derive the cursor from the same helper.
- `MINT_BIRTHDAY` is cfg-gated: regtest uses 4 (first block after the
  harness's NU6.3 activation), restoring the previous regtest origin at 3;
  the schedule test asserts the constant against the pinned harness config.
- Dropped the unused `BlockMetadata` import; the `NetworkUpgrade` import
  moved into the regtest test that uses it.
