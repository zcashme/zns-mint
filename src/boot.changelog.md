# Boot module changelog

Tracks design-relevant changes to `src/boot.rs`.

## 2026-07-25 — Mainnet genesis network-identity check

- `verify_chain_integrity` now fetches the genesis block via JSON-RPC and
  asserts its hash equals `zcash::MAINNET_GENESIS_HASH` before deriving keys
  or fetching the Ironwood origin checkpoint.
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
