# Treasury auto-sweep changelog

## 2026-07-24 — Treasury auto-sweep

- Added `src/treasury/sweep.rs` with `sweep_policy()` and `assemble_sweep()` —
  detects when Treasury balance exceeds `SWEEP_THRESHOLD` and builds a V6
  transaction to sweep excess to a cold storage transparent address.
- Orchard bundle (Treasury authority): spends Treasury notes, creates change.
- Transparent output: sends `treasury_balance - SWEEP_RESERVE` to
  `SWEEP_ADDRESS`.
- Constants are hardcoded (no env vars, no config): `SWEEP_THRESHOLD` =
  10,000,000 zatoshis (0.1 ZEC), `SWEEP_RESERVE` = 1,000,000 zatoshis
  (0.01 ZEC), `SWEEP_ADDRESS` = placeholder P2PKH (`[0x42; 20]`).
- TODO: set `SWEEP_ADDRESS` to the real deployment cold storage address
  before production.
- Wired into `live::reconcile` as a `PendingWork::AutoSweep` item.