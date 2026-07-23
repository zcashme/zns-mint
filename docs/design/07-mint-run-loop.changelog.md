# Mint run-loop design changelog

## 2026-07-23 — Passive rebuild boundary

- Replaced the stale catch-up path that interpreted requests and submitted
  transactions with an explicit passive Rebuild and capability-separated Live
  target.
- Recorded exact Zebra target verification, cursor-last canonical folding,
  passive replacement-branch replay, gauge semantics, and the present
  same-height/shorter-reorg blocker.
- Kept atomic claim recovery and OTP burn/reissue policy as explicit follow-up
  work.
