# Registry state changelog

Tracks design-relevant changes to `src/registry/state.rs`.

## 2026-07-24 — Accepted height comes from scanner metadata

- Registry history records now take their block height from the immutable
  `BlockOutput` metadata rather than a duplicate output field.

## 2026-07-23 — Canonical Registry excludes operational locks

- Removed in-flight name locks and their mutation API from `Registry`.
- Registry cloning, block simulation, and reorg truncation now contain only
  canonical tips and their undo history. A future Live layer must own
  cursor-bound transition locks separately.

## 2026-07-23 — Chain-authenticated Name Note tips

- Registry tips now retain the exact cryptographically validated Name Note and
  its best-chain locator. Production tips can only be constructed from the
  scanner's opaque `ValidatedZnsNote<NameNotePayload>` handoff.
- Added a fallible, transaction-scoped transition boundary. Every accepted
  claim, update, or release requires a recognized positive-value Registry fee
  spend in the same transaction.
- Updates and releases additionally require the exact current tip nullifier and
  the payload's predecessor commitment to match the current tip.
- Transactions containing more than one validated Name Note candidate are
  rejected as ambiguous only after a Registry input proves authorship. Purely
  public attacker-created candidates are ignored and cannot stall canonical
  block following.
- The public tip view still exposes action and predecessor commitment for
  authorization, but production construction derives both from the retained
  validated payload so they cannot diverge.
- Registry block validation now derives authorship directly from `BlockOutput`
  plus the wallet's ordinary-note set; no caller-fabricable boolean evidence
  crosses the API.
- Spending any current tip without exactly one legal successor is a typed
  failure, preventing Registry from retaining an already-nullified tip.
