# Wallet design changelog

## 2026-07-23 — Canonical and operational state separation

- Replaced the stale Orchard-only `SpendableNote`/`UndoState` target model with
  the current three-pool `WalletBalance`/`ShardTrees` design.
- Corrected pre-refactor scanner, update-order, rewind, and module ownership
  descriptions.
- Recorded that Wallet contains only replayable chain-derived state and that
  Live locks/reservations must be externally owned and cursor-bound.
