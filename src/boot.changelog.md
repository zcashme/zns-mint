# Boot module changelog

Tracks design-relevant changes to `src/boot.rs`.

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
