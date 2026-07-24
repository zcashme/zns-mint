# Mint run-loop design changelog

## 2026-07-24 — Exact-target Rebuild boundary

- Implemented one immutable Zebra height/hash target per Rebuild attempt.
- Same-height, shorter, and taller divergence now share a lower-height
  comparison and exact common-ancestor rewind.
- Rebuild returns success only after cursor identity, target block bytes, and
  a second exact Zebra tip read all agree.
- Every successful block read and common-ancestor result is discarded if a
  following exact-tip read no longer equals the captured target.
- Accepted metadata retention is aligned with the current checkpoint plus the
  complete 100-block three-tree rewind depth, and cursor promotion follows
  accepted-history installation.
- Deterministic fixtures enumerate replacement branches, restart schedules,
  target races, and crashes before/after every canonical commit stage.
- Rewind/replay no longer publishes intermediate gauges; publication waits
  for final exact-target verification.

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
