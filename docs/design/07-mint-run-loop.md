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

The current reorg detector handles a divergent fetched successor, but it does
not yet detect every same-height or shorter reorg. This is a release blocker,
not an implied property of the passive cleanup.

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
target = zebra_exact_tip()

while cursor != target:
  block = fetch_continuous_canonical_successor(cursor)
  committed = apply_canonical_block(block, scanning, wallet, registry,
                                    cursor, accepted_history)

require zebra_hash(target.height) == target.hash
enter Live

loop:
  canonical change:
    commit canonical blocks passively
    project optional Live effects only from committed evidence

  reorg:
    invalidate cursor-bound operational work
    rewind every canonical subsystem to one exact ancestor
    capture a fresh exact target
    replay the replacement branch passively
    re-enter Live only after exact target verification
```

## Canonical Fold Boundary

The target interface is:

```text
apply_canonical_block(...) -> Result<CommittedBlock, RuntimeError>
project_live_effects(..., CommittedBlock) -> ...
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
6. return immutable committed evidence.

No request observation is lost: raw Treasury memos, txids, received/spent
notes, nullifiers, and validated Name Notes remain canonical evidence. Rebuild
does not interpret that evidence operationally.

## Live Responsibilities

Only `Live` may own or invoke:

- request interpretation and semantic claim reconstruction;
- name, payment, fee-note, and OTP reservations;
- OTP issuance and verification;
- Treasury funding and sweep policy;
- intent expiry, confirmation, and replacement;
- proving, signing, retry, and submission;
- lifecycle event counters.

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
