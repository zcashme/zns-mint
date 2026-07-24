# Live phase changelog

## 2026-07-24 — Initial Live phase implementation

- Added `src/live.rs` with `LiveState`, `reconcile`, `execute`, and
  `check_confirmations` — the Live phase runtime.
- Added `src/live/submissions.rs` with `Submissions` and `Submission` types
  for tracking pending transactions and their reserved notes.
- Reconciliation derives pending work from canonical Wallet + Registry state:
  - Claims: Treasury notes with claim request memos where the name is
    available and payment ≥ price.
  - Update/Release without OTP: issue OTP and build relay transaction.
  - Update/Release with OTP: verify, authorize, and submit Name Note
    transition.
- Execution builds, signs, and submits transactions via `JsonRpc::send`.
- Confirmation checking scans each block's txids against pending submissions.
- Reorg invalidation clears all cursor-bound operational state (submissions,
  pending OTPs, relay reservations).
- No durable state: restart loses all operational state; reconciliation
  re-derives pending work from canonical chain state.
- `LiveState` owns `PendingOtps`, `Submissions`, and `pending_relays`.
- Reserved notes are tracked through `Submissions::reserved_locators()` to
  prevent double-spending within one run.
- The claim price is hardcoded at 10,000 zatoshis (protocol policy, TODO:
  move to a policy module).