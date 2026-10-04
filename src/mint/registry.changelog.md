# Registry module changelog

Tracks design-relevant changes to `src/registry.rs`.

## 2026-10-03 — The request gate joins the authorize family

- `Registry::authorize_challenge` is the request-side twin of
  `authorize_update`/`authorize_release`: the note unspoken-for (the
  `NameNoteQueue` consulted, not left to the lanes), both §4.5 clocks
  live at `mtp_now`, the request newer than the record, forever names
  taking no term. It returns the record when a challenge may proceed;
  the paying lanes add the fee check. `allows_challenge` narrows to
  the private clock-and-verb check behind it.
- A name past its liveness deadline can no longer buy a challenge,
  even with purchased term remaining: the update such a request buys
  is one `authorize_update` always voids, and the request and renewal
  payments were kept. The gate and the law now answer the clocks with
  one verdict.
- Release challenges from a liveness-due controller are refused alike;
  the lifecycle sweep releases without a challenge.

## 2026-10-03 — A claim built before a release does not register after it

- `accept_claim` takes the transaction expiry. When the name's latest
  record is a release, a transaction whose expiry falls inside the
  standard expiry window of that release is refused. Its anchor still
  retires, and its successor stays out.
- A claim built after the release, with expiry past that window, registers.

## 2026-10-03 — A rejected claim does not seat its successor

- `accept_claim` still retires every live anchor the transaction
  spent. The successor joins only when the claim is admitted: one
  anchor, no Name Note, and a free or released name.
- A duplicate on a live name, or a claim that also spends a Name
  Note, leaves the successor out. The registration stands, except
  where a spent name is marked released.

## 2026-10-02 — Ceremony fill is the keygen transaction

- `apply_block` adopts zero-value registry outputs only from a
  transaction that carries all 40 and no name note. A note outside
  that transaction does not join. A claim successor still enters
  through `retire_spent`.

## 2026-09-29 — Ceremony adoption closes once (#236)

- The pool records the block where ceremony adoption first reaches
  40, kept apart from the live set so a later spend in that block
  can shrink the pool without reopening it. Ordinary zero-value
  outputs after that do not refill a vacancy. A successor still
  enters when exactly one live anchor was spent. Rewind clears the
  close only when that completion block is removed; a rewind to
  the block itself, or to a later depleted state, keeps it closed.

## 2026-09-23 — A refused update extension leaves the OTP

- `authorize` computes `expires_at.extend` before `challenges.accept`.
  An illegal or overflowing term returns `None` with the challenge
  still pending.

## 2026-09-22 — Confirm-time clocks; malformed spends return false

- `accept_update` re-checks expiry and liveness at block MTP. A
  well-formed spend after either clock marks the name released (the
  predecessor was spent) and returns false.
- `authorize` refuses an update under the same clocks.
- `predecessor_spent` and the update/release `prev_rcm` check return
  `None`/`false` on malformed spends instead of panicking.
- `accept_claim` does the same for a record spend, a batched anchor
  spend, or a missing successor: the pool still follows spent anchors,
  spent names are marked released, and the claim is not registered.
- Every rejected path now follows the chain: a malformed update or
  release retires the anchors it spent and marks its consumed names
  released, and a `prev_rcm` mismatch releases the name at the
  successor nullifier instead of leaving a live record.
- `follow_spends` retires spent anchors and marks spent names
  released when `apply_block` sees a Registry spend without exactly
  one Name Note.
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
