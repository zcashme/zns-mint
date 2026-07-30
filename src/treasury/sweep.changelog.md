# Treasury auto-sweep changelog

## 2026-07-30 — Boot-proven fee network

- Sweep fee calculation and V6 assembly receive the boot-proven consensus
  parameters rather than a global default.

## 2026-07-28 — Two-ZEC sweep trigger

- Raised `SWEEP_THRESHOLD` from 0.1 ZEC to 2 ZEC. The independent 0.01 ZEC
  post-sweep reserve and the compiled approved P2PKH destination are unchanged.

## 2026-07-24 — Treasury auto-sweep

- Added `src/treasury/sweep.rs` with `sweep_policy()` and `assemble_sweep()` —
  detects when Treasury balance exceeds `SWEEP_THRESHOLD` and builds a V6
  transaction to sweep excess to a cold storage transparent address.
- Orchard bundle (Treasury authority): spends Treasury notes, creates change.
- Transparent output: sends `treasury_balance - SWEEP_RESERVE` to
  `SWEEP_ADDRESS`.
- Constants are hardcoded (no env vars, no config): `SWEEP_THRESHOLD` =
  10,000,000 zatoshis (0.1 ZEC), `SWEEP_RESERVE` = 1,000,000 zatoshis
  (0.01 ZEC), `SWEEP_ADDRESS` = approved P2PKH (`[0x42; 20]`).
- Wired into `live::reconcile` as a `PendingWork::AutoSweep` item.

## 2026-07-28 — Exact fee and reserve retained by assembly

- Sweep policy now determines only eligibility. Assembly selects the exact
  unreserved Treasury notes, computes its actual Orchard V3 action count and
  ZIP-317 fee, then sends `selected - reserve - fee` to cold storage.
- The fixed one-million-zatoshi Treasury reserve remains an Orchard change
  output. A sweep can no longer request the full pre-fee excess and fail for
  lack of fee funds.
