# Treasury sweep changelog

Tracks design-relevant changes to `src/treasury/sweep.rs`.

Claim-refund assembly is tracked separately in
`src/treasury/assemble.changelog.md`.

## 2026-07-22 — ZIP-317 fee cross-check

- Replaced hand-rolled `max(2, inputs_count + 2) * 5_000` ZIP-317 fee calculations
  with `zcash_primitives::transaction::fees::zip317::FeeRule::standard().fee_required(...)`.
- Counted the transparent cold-storage sweep destination as one P2PKH output
  (34 bytes) via the upstream transparent output-size view.
- Sapling sweep: computed the Sapling logical output count with
  `sapling::builder::BundleType::DEFAULT.num_outputs(...)` instead of hardcoding `2`.
- Orchard sweep: computed Orchard action count with `orchard::builder::BundleType::num_actions`
  under `BundleVersion::orchard_v3().default_flags()`. Orchard v3 disables cross-address
  transfers, so the action count is `max(N + 1, 2)` for `N` inputs plus one change output,
  not the cross-address-enabled `max(N, 2)`.
