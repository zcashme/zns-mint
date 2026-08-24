# Treasury replenishment changelog

## 2026-09-02 — One-call refill on the wallet trait surface

- `assemble_replenishment` and `ReplenishAssembly` are replaced by one entry
  point: `replenish_registry_fees(network, wallet, treasury_keys) ->
  Option<TxId>`. It decides via `RegistryFeeLiquidity::from_wallet` (upstream
  account metadata) and `treasury_funding_plan()`, derives heights from the
  wallet, selects funding, builds, proves, signs, and records the refill in
  the wallet — returning only the `TxId`. Caller-owned exclusions, the
  height parameters, and the hand-back result struct are gone, exactly as in
  `vault`.
- Selection is upstream-faithful: `InputSource::select_spendable_notes`
  with `TargetValue::AtLeast`, oldest-first, crossing note included. The
  fee/spend-count circularity resolves by iteration through the public
  trait — select for the current requirement, recompute the ZIP-317 fee for
  the resulting action count, re-select with the prior selection as
  `exclude` until it holds — the same convergence `GreedyInputSelector`
  performs internally. Supersedes the undocumented smallest-value-first
  picking (`min_by_key`): whatever motivated it was never recorded, and it
  contradicted the oldest-first ordering our own selector implements and
  documents.
- The refill transaction is stored via `store_transactions_to_be_sent` with
  an empty sent-output list: every output is shielded to a wallet account
  (fee notes to the Registry, change to the Treasury), so all are
  rediscovered by scanning; the record's spends are what block re-selection
  until confirm-or-expiry — the wallet's spend record is the reservation
  view.
- Known incompleteness, matching `vault`: the signer's planned return of the
  built `Transaction` and the placeholder `AssemblyError` variants for
  wallet failures land with the signing and mint slices; run-loop wiring
  lands with the sync slice.

## 2026-08-15 — Ironwood-to-Ironwood single bundle

- Replenishment no longer crosses pools: the Treasury spends Treasury
  Ironwood notes and creates the Registry fee notes as Ironwood outputs in
  the same bundle (Ironwood permits the cross-address transfer).
- The bundle binds to the exact-height Ironwood checkpoint root (it spends)
  and is signed by the Treasury only.
- Fee-note outputs use the Treasury's OVK: the Treasury is the sender and can
  recover its own outgoing plaintext; the Registry detects the notes by trial
  decryption as recipient regardless.

## 2026-07-30 — Boot-proven fee network

- Replenishment fee calculation and mixed-bundle signing receive the
  boot-proven consensus parameters rather than a global default.

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
