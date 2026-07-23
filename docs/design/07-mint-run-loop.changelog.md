# Mint run-loop design changelog

## 2026-07-24 — State reconciliation, not committed-block events

- Removed the proposed `CommittedBlock`/`project_live_effects` handoff.
- Canonical folding now returns only success or failure; the promoted cursor
  remains the accepted-prefix authority.
- Future Live work is derived by reconciling installed Wallet and Registry
  state after exact-tip verification, so rebuild never replays operational
  events.

## 2026-07-23 — Passive rebuild boundary

- Replaced the stale catch-up path that interpreted requests and submitted
  transactions with an explicit passive Rebuild and capability-separated Live
  target.
- Recorded exact Zebra target verification, cursor-last canonical folding,
  passive replacement-branch replay, gauge semantics, and the present
  same-height/shorter-reorg blocker.
- Kept atomic claim recovery and OTP burn/reissue policy as explicit follow-up
  work.
