# Treasury replenishment changelog

## 2026-07-24 — Registry fee-note replenishment

- Added `src/treasury/replenish.rs` with `assemble_replenishment()` — builds
  a mixed V6 transaction that transfers value from the Treasury Orchard pool
  to the Registry Ironwood pool.
- Orchard bundle (Treasury authority): spends Treasury notes, creates change.
- Ironwood bundle (output-only, no spend authority): creates
  `RegistryFundingPlan.output_count` notes of `output_value` each to the
  Registry's external Ironwood address.
- The Treasury pays the transaction fee. The funding amount is transferred
  cross-pool.
- Uses `RegistryFeeLiquidity::from_wallet()` and `treasury_funding_plan()`
  from `liquidity.rs` to detect when replenishment is needed.
- Wired into `live::reconcile` as a `PendingWork::ReplenishRegistry` item.