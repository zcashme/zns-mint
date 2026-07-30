# Treasury claim assembly changelog

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
