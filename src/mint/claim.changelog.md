# Treasury claim assembly changelog

## 2026-08-15 — Single-bundle atomic claim

- The two-bundle structure (Orchard Treasury payment + Ironwood Registry
  lifecycle) collapses into one Ironwood bundle: the payment spend (Treasury
  authority), the retained price as a Treasury change note, the Name Note,
  the refund to the claimed UA, the Registry fee spends, and Registry change
  all settle in the single `ironwood_bundle` a V6 transaction carries.
- The bundle is signed by both the Treasury and Registry keys under one
  shared V6 sighash; per-action authority resolves by spending key at signing
  time. The payment, price, and refund cancel in-bundle, so the bundle's net
  balance is exactly the aggregate ZIP-317 fee funded by the Registry fee
  notes (the 2026-07-28 joint-funding economics are unchanged).
- Claim payments are Ironwood notes (NU6.3 disables Orchard cross-address
  transfers; no user Orchard intake exists).
- The claimed UA must carry an Orchard receiver: it is the refund destination
  and the only address an OTP could ever be delivered to. Rejected at
  validation time in `process_claim` (`no_orchard_receiver`); the
  assembly-time `extract_orchard_address` check remains as defense in depth.

## 2026-07-30 — Boot-proven claim settlement parameters

- Claim fee selection, claimed-UA receiver decoding, and paired V6 signing use
  the immutable consensus parameters established by boot. The production claim
  policy is unchanged; only ownership of network parameters moved out of the
  Zcash transport module.

## 2026-07-28 — Claim excess returns to the claimed UA

- A claim's `name_ua` is now the refund destination; it must contain a
  mainnet Orchard receiver. No separate payer/refund address is added to the
  request grammar.
- The Treasury Orchard bundle retains exactly the one-ZEC price as a
  Treasury-controlled change output. The remaining payment value crosses to
  Ironwood and is returned to `name_ua` as the excess refund.
- Registry fee notes fund only the aggregate ZIP-317 fee. The paired Orchard
  and Ironwood bundle balances sum to that fee; the claim price and refund are
  never treated as miner fee.

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
