# Chain sync design changelog

## 2026-07-24 — Complete passive reorg detection

- Added checked exact-tip capture from one `getblockchaininfo` response.
- Reorg discovery starts at `min(local height, target height)`, covering
  same-height and shorter chains without requesting above Zebra's tip.
- Height-indexed block reads reject a mismatched claimed height.
- Successful block reads and all common-ancestor outcomes are revalidated
  against the captured exact tip before they can mutate canonical state or
  become a retained-history failure.
- All three tree checkpoints are preflighted before rewind mutation, and
  metadata history retains the current checkpoint plus 100 predecessors.
- History gaps fail closed rather than skipping to an older retained key.

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
