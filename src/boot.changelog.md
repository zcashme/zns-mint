# Boot module changelog

Tracks design-relevant changes to `src/boot.rs`.

## 2026-09-21 — Access-code purpose key on Boot (#83)

- Boot derives an access-code root via
  `Tee::derive_sealing_key(ZNS/access-code/root/v1)`, then wraps
  `presale::AccessCodeKey::from_private_key` (HMAC `"access-code-v1"`).
  The key rides `Boot` into the claim lane; it never enters the wallet
  or the database.

## 2026-09-21 — `Registry::new()` no longer takes the checkpoint height (issue #108)

- Boot constructs the empty Registry with no floor; the origin
  checkpoint height still fetches the treestate and seeds the wallet —
  it is just no longer copied into Registry state.

## 2026-09-16 — Seed pre-birthday subtree roots at boot (issue #44)

- New step 3b: `fetch_prebirthday_subtree_roots` pulls Sapling and Ironwood
  completed-shard roots via `z_getsubtreesbyindex` and feeds them to
  `Wallet::new`. Without them, post-birthday witnesses that cross a
  pre-birthday sibling shard fail — no anchors, no spends.
- Orchard is not fetched: the mint has no Orchard spend path. An Orchard
  payment to Treasury is scanned and left unspendable.
- Fatal on transport error (fail closed). Zebra returns only completed
  shards; the rightmost partial shard still comes from the origin
  `ChainState` frontier. Later shards fill in during scan.

## 2026-09-15 — TEE boundary is a trait; regtest no longer skips attestation

- Boot delegates the two TEE capabilities it needs — sealing-key derivation
  and signed attestation — to `crate::tee::Tee`. Capsule unsealing moves to
  `crate::capsule::{parse_capsule, unseal_seed}`; boot owns only the
  `SEED_FINGERPRINT_RAW` cross-check and the ZIP-32 derivation.
- Production still uses `RealSnpTee` (VCEK-derived sealing key via
  `/dev/sev-guest`, `firmware.get_report` for the signed report). The
  `fake-tee` feature substitutes `FakeTee` so integration tests can boot
  outside SEV-SNP; `fake-tee` is blocked from release builds by a
  `compile_error!` in `crate::lib`.
- Attestation is no longer gated on `#[cfg(not(feature = "regtest"))]`.
  Regtest is a local-consensus toggle, not a TEE toggle: a
  `--features regtest,fake-tee` mint still writes
  `zns_mint_attestation.bin` (with a synthetic report), and a
  `--features regtest` mint on a real SEV-SNP host still writes a real
  report.
- Removed the inlined `SeedCapsule`, `decrypt_sealed_blob`,
  `derive_sealing_key` (SNP-only), and `generate_mint_attestation`. All
  four are covered by the two new modules.

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

## 2026-09-17 — Boot sync rides `apply_block` (issue #55)

- Boot's own scan/apply copy is deleted. The loop fetches with
  `.expect` and calls `mint::apply_block` with per-block scratch
  queues — arrivals from history land in a queue that falls out of
  scope with the iteration, so history is balance by construction and
  `live_from` stays dead.
- Boot runs main's intake as dead work — each block's Treasury memos
  are decrypted and parsed, then discarded — so the body is one path,
  not a path plus a skip flag.
- The three continuity asserts moved inside `apply_block`; boot gets
  them and now fails fast on a forked checkpoint or a Zebra reorg
  mid-sync.

## 2026-09-22 — The node's tip is never pushed into the wallet

- Boot no longer supplies Zebra's `best_height` through
  `update_chain_tip`; the boot balance check reads the wallet's own
  chain knowledge, which exists from seeding and boot sync.
