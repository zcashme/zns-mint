# 07 - Mint Run Loop

This document defines the runtime phase boundary. `main.rs` remains a thin
orchestrator; canonical replay and operational transaction work must never
share one capability-bearing function.

## Current Safety Baseline

The current runtime is intentionally passive. It boots from the pinned
birthday checkpoint, scans continuous blocks, applies Wallet and Registry
state, advances its exact cursor/history, and recomputes canonical gauges.

Catch-up does not interpret requests, generate or verify OTPs, reserve names or
notes, run Treasury policy, prove or sign transactions, submit bytes, reconcile
submissions, or emit lifecycle event counters. Transaction and authorization
libraries remain unwired until the phase architecture below is implemented.

Rebuild compares height and hash even when Zebra is at the same or a shorter
height. It searches from the lower comparable height, rewinds to one retained
exact ancestor, and replays passively. Behavioral fault, property, and Zebra
branch evidence remains required before this boundary is considered tested.

## Target Phase Shape

The runtime has three explicit phases:

1. `Boot` establishes the attested process, derives accounts, and seeds the
   birthday checkpoint.
2. `Rebuild` captures an exact fresh Zebra `(height, hash)` target and folds
   canonical blocks without operational effects.
3. `Live` begins only when the fully-applied cursor exactly equals that target
   and Zebra still reports the same canonical hash.

There is no durable Wallet, Registry, witness, intent, or submission authority.
Canonical state is rebuilt from chain on every boot.

```text
boot
target = zebra_exact_tip() // one checked height/hash pair

while cursor != target:
  block = fetch_continuous_canonical_successor(cursor)
  apply_canonical_block(block, scanning, wallet, registry,
                        cursor, accepted_history)

require cursor == target
require zebra_block_hash(target.height) == target.hash
require zebra_exact_tip() == target
publish canonical gauges from installed cursor
enter Live
reconcile live work from canonical Wallet + Registry + cursor

loop:
  canonical change:
    commit canonical blocks passively
    verify the exact tip
    reconcile live work from installed canonical state

  reorg:
    invalidate cursor-bound operational work
    rewind every canonical subsystem to one exact ancestor
    capture a fresh exact target
    replay the replacement branch passively
    re-enter Live only after exact target verification
```

Intermediate rewind/replay state is not published. Canonical gauges continue
to describe the last fully verified target until the replacement target passes
all three final checks.

## Canonical Fold Boundary

The target interface is:

```text
apply_canonical_block(...) -> Result<(), RuntimeError>
reconcile_live_work(canonical state, operational state, narrow capabilities)
```

`apply_canonical_block` may receive only:

- a block and scanning inputs;
- Wallet and Registry derived state;
- the fully-applied cursor and accepted chain history.

It may not receive:

- spending keys, a prover, signer, or submitter;
- RPC submission capability;
- intents, submissions, OTP state, or entropy;
- Treasury policy;
- live event counters.

One block commits in this order:

1. scan and validate the next continuous block;
2. simulate Registry transitions against pre-block canonical Wallet state;
3. apply Wallet balances, nullifiers, and all three commitment trees;
4. install the simulated Registry result;
5. advance exact cursor and accepted history last;
6. return success without an event payload.

No request observation is lost: raw Treasury memos, txids, received/spent
notes, nullifiers, and validated Name Notes remain canonical evidence. Rebuild
does not interpret that evidence operationally. Live derives desired work from
the installed Wallet, Registry, and cursor rather than replaying block events.

## Live Responsibilities

Only `Live` may own or invoke:

- request interpretation and semantic claim reconstruction;
- name, payment, fee-note, and OTP reservations;
- OTP issuance and verification;
- Treasury funding and sweep policy;
- intent expiry, confirmation, and replacement;
- proving, signing, retry, and submission;
- lifecycle event counters.

Live is a state reconciler, not a block-event consumer. Restart and reorg first
reconstruct canonical state; only then may reconciliation determine which work
is still pending.

Operational locks and reservations are cursor-bound state outside canonical
Wallet and Registry values. A reorg invalidates them before replacement replay.
Orphan-bound serialized transactions never become automatically submit-ready.

Canonical facts are gauges recomputed from committed state. Replay lifecycle
work, if measured, uses a separate process metric rather than replaying user
events.

## Deferred Policies

Atomic claim recovery must be semantic: the exact payment spend plus a valid
matching Name Note in one canonical transaction settles a claim. It must not
depend solely on an in-memory submission txid.

Replacement of reconstructed claims after restart remains blocked on the
approved maximum transaction-expiry waiting policy and its implementation.

OTP recovery remains a separate task. Restart loses ephemeral OTP knowledge;
reissuing while an old relay may still confirm requires an explicit burn and
reissue policy.

## Failure Policy

Boot and canonical trust-path failures are fatal. Transport failures may retry
without advancing state. Per-request failures belong to Live and must be
redacted, isolated, and non-authoritative.
