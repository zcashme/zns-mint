# Chain sync design changelog

## 2026-07-23 — Passive replay and reorg ownership

- Corrected `BlockOutput` transaction coverage: all Ironwood transactions are
  retained, while standard-pool transaction evidence is wallet-relevance
  driven; full per-pool commitment streams remain unconditional.
- Removed submission state from canonical rewind ownership. Future Live state
  must be invalidated before passive replacement-branch replay.
- Recorded the current same-height/shorter-reorg detection gap and the need for
  an exact fresh Zebra height/hash target.
- Corrected the chain-source description to gRPC tip wake-ups plus read-only
  JSON-RPC block reads, and recorded that beyond-history failure currently
  aborts for restart rather than rebuilding in-process.

## 2026-07-23 — Validated Name Note supplement and replayable nullifiers

- Replaced the obsolete role-agnostic raw-memo scanner description with the
  actual supplemental Registry scan boundary.
- Documented opaque validated Name Note evidence, exact action positions,
  marked retention, raw per-pool nullifiers, and immutable scanner outputs.
- Recorded exact accepted-block metadata as the reorg/restart boundary.
