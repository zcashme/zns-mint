# Wallet balance changelog

## 2026-07-23 — Prepared balance application

- `WalletBalance` is cloneable so a complete block's received/spent note delta
  can be prepared in transaction order without mutating accepted state.
- Same-block spends resolve against the prepared balance, preserving the
  previous sequential semantics.
- The prepared balance is installed only after every commitment-tree append
  succeeds.

