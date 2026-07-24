# Treasury claim assembly changelog

## 2026-07-24 — Atomic claim transaction assembly

- Added `src/treasury/claim.rs` with `assemble_atomic_claim` — builds both
  Orchard (Treasury payment spend) and Ironwood (Name Note + refund + fee +
  change) bundles and combines them in one V6 transaction via
  `assemble_v6_transaction`.
- The Orchard bundle spends the Treasury payment note with no output — the
  full payment value contributes to the transaction fee.
- The Ironwood bundle includes an always-present refund output (value =
  `payment - price`, including value-zero) to the Treasury's internal address.
- The total fee is `price + ironwood_fee`: the Treasury retains `price`, the
  network gets `ironwood_fee`, and the user receives `payment - price` back.
- Registry fee notes fund the complete transaction's aggregate ZIP-317 fee.
- Both bundles are signed under one shared V6 sighash: Orchard by the Treasury
  spending key, Ironwood by the Registry spending key.