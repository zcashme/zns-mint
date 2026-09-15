# Registry module changelog

Tracks design-relevant changes to `src/registry.rs`.

## 2026-09-15 — release_due reports which §4.5 clock fired (issue #14)

- `Registry::release_due` now returns `Option<(NameNote, ReleaseReason)>`.
  `ReleaseReason::Expiry` marks the purchased-term clock (§4.5.2);
  `ReleaseReason::Liveness` marks the τ+L clock (§4.5.4). When both
  fire at the same MTP, expiry wins — the purchased term is the more
  specific rule.
- `release_deadline` is set inside `NameRecord::from_received` from the
  block's MTP plus `LIVENESS_INTERVAL` — the same on any accepted
  transition (claim or update), so a fresh update rebinds the deadline
  by construction.

## 2026-07-23 — Operational state removed from canonical owners

- The exported fee-input selector now requires caller-owned exclusions.
- Registry state no longer exposes name-lock operations; future Live
  orchestration must own locks and reservations outside Wallet and Registry.

## 2026-07-23 — Validated tip API surface

- Removed the standalone `Rcm` and `Psi` exports. Registry state no longer
  exposes free scalar components that callers could combine into an
  unvalidated Name Note tip.
- Registry tips and transition errors are re-exported from the state module;
  exact validated note storage remains private behind `Tip::received`.

## 2026-07-23 — Opaque fee-input reservation surface

- Registry assembly exports an opaque exact fee-input plan plus a reservation-
  aware selector. Callers can reserve its locators but cannot substitute them.
