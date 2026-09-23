# Registry module changelog

Tracks design-relevant changes to `src/registry.rs`.

## 2026-09-22 — One pool transition law: `retire_spent`
- `AnchorPool::retire_spent` is the pool following the chain: every
  spent anchor retires, an optional created successor joins (past
  standing size — chain facts do not queue), and the pool checkpoints
  on change. `apply_claim` becomes its well-formed wrapper; the
  late-update fix (#152) builds its malformed-spend path on this op.
## 2026-09-21 — The anchor pool goes mint-private; the canon vectors carry the law (#127)

- The anchor lineage pool's live set and its height-checkpointed rewind
  history move from `Registry`'s fields into the private
  `registry/anchor_pool` module — no behavioural change; the three pool
  operations are verbatim moves. The cross-repo contract is the canon
  fixture, not the type: `AnchorPool` is crate-private, its API narrows
  to what production uses, and `ANCHOR_POOL_SIZE` stays exported.
- `tests/canon_vectors.rs` + `tests/fixtures/canon-vectors-v1.json`:
  the admission law as a byte-fixed event→snapshot artifact — seven
  scenarios (ceremony fill, backed claim, unbacked claim, duplicate
  claim, claim-after-release, update-then-release, reorg) pin per-event
  Registry state, including real `zns_rcm` commitments. Claim events
  carry an explicit `expect: accepted|rejected`, so the DSL itself
  expresses the duplicate-claim rule: rejected for the record, advanced
  for the pool. `cargo test` drift-checks the fixture against the
  emitter; regenerate with `CANON_VECTORS_REGEN=1 cargo test --test
  canon_vectors`.

## 2026-09-21 — Duplicate confirmed claims are ignored: first confirmed wins (#116)

- `accept_claim` no longer asserts the name is free-or-released. A
  backed claim that finds the name already live still advances the
  anchor pool (a duplicate spent a standing anchor and created a
  successor; the pool follows the chain) and returns `false` — the
  live registration stands. The mint's restart window (queue and
  sent-transaction ledger are memory) can produce a duplicate; the
  Registry must survive what the chain carries.

## 2026-09-21 — `claim_anchor_height` deleted: the floor was the seed checkpoint all along (issue #108)

- The `claim_anchor_height` field, the `Registry::new` parameter, and
  the "reorg boundary" doc are gone; `new()` is zero-arg over a derived
  `Default`. The Registry carries no reorg floor.
- `truncate_to_height`'s assert (`height >= claim_anchor_height`,
  "rewind crossed the boot-created Registry anchor") is deleted; the
  precondition — callers pass walk-found heights at or above the boot
  origin — moves into the method doc. Truncation is a pure history
  rewind.
- Supersedes #55's rationale ("claim_anchor_height stays as the reorg
  floor: it is the boot checkpoint, a joint constraint the wallet seed
  shares"): the floor was the wallet seed checkpoint all along, and
  main's walk now terminates on that seed directly.

## 2026-09-15 — release_due reports which §4.5 clock fired (issue #14)

- `Registry::release_due` now returns `Option<(NameNote, ReleaseReason)>`.
  `ReleaseReason::Expiry` marks the purchased-term clock (§4.5.2);
  `ReleaseReason::Liveness` marks the τ+L clock (§4.5.4). When both
  fire at the same MTP, expiry wins — the purchased term is the more
  specific rule.
- `release_deadline` is set inside `NameRecord::from_received` from the
  block's MTP plus `LIVENESS_INTERVAL` — the same on any accepted
  transition (claim or update), so a fresh update rebinds the deadline
  by construction.

## 2026-07-23 — Operational state removed from canonical owners

- The exported fee-input selector now requires caller-owned exclusions.
- Registry state no longer exposes name-lock operations; future Live
  orchestration must own locks and reservations outside Wallet and Registry.

## 2026-07-23 — Validated tip API surface

- Removed the standalone `Rcm` and `Psi` exports. Registry state no longer
  exposes free scalar components that callers could combine into an
  unvalidated Name Note tip.
- Registry tips and transition errors are re-exported from the state module;
  exact validated note storage remains private behind `Tip::received`.

## 2026-07-23 — Opaque fee-input reservation surface

- Registry assembly exports an opaque exact fee-input plan plus a reservation-
  aware selector. Callers can reserve its locators but cannot substitute them.

## 2026-09-17 — The law is `accept_*`; `apply_block` owns sequencing (issue #55)

- `Registry::apply_block` and `ReceivedNameNote` are deleted. The
  confirmation pass lives in `mint::apply_block`; the Registry exposes
  the law: `adopt_anchor`, `accept_claim`, `accept_update`,
  `accept_release`, `names_spent_by`.
- Claims swap the pool atomically inside `accept_claim` — retire the
  spent anchor, insert the successor, snapshot the pool — with one new
  invariant: a claim spends exactly one anchor; assembly never batches.
- The Registry mutates in place. The per-block `self.clone()` is gone,
  and `derive(Clone)` is dropped with it — whole-state forks are
  unrepresentable.
- `claim_anchor_height` stays as the reorg floor: it is the boot
  checkpoint, a joint constraint the wallet seed shares — deriving it
  from `MINT_BIRTHDAY` would permit reorgs the wallet cannot survive.
  This amends #55's body; the backup's `MINT_BIRTHDAY` simplification
  held only for a seed at the birthday.
- `NameRecord::from_received` takes `(note, nullifier)` directly.
