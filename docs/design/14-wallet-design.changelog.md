# Wallet design changelog

## 2026-07-24 — One preflighted Wallet rewind

- Removed separate mutable balance/tree access from the orchestrator.
- `Wallet::rewind_to_height` preflights all three exact checkpoints, truncates
  trees first, and only then truncates balance/nullifier history.
- Trees and accepted metadata retain 101 checkpoints: the current height plus
  the complete 100-block rewind depth.
- Every accepted checkpoint verifies that all three exact pool checkpoints
  exist; failure tests preserve every pool before mutation.

## 2026-07-23 — Canonical and operational state separation

- Replaced the stale Orchard-only `SpendableNote`/`UndoState` target model with
  the current three-pool `WalletBalance`/`ShardTrees` design.
- Corrected pre-refactor scanner, update-order, rewind, and module ownership
  descriptions.
- Recorded that Wallet contains only replayable chain-derived state and that
  Live locks/reservations must be externally owned and cursor-bound.
