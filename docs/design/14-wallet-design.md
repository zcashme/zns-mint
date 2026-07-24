# 14 - Wallet Design

This document defines the current in-memory Wallet boundary. The Wallet is a
replayable cache of canonical chain observations for the Treasury and Registry
accounts. It is not ownership authority and it does not own operational work.

## Scope

One seed derives two ZIP-32 accounts:

- Treasury account `0` receives user payments and request memos.
- Registry account `1` receives ordinary fee liquidity and is the account whose
  separate signing capability authorizes Name Note transactions.

Wallet holds unified full viewing keys for scanning. It never holds spending
keys, OTP credentials, Treasury policy, submissions, intents, name locks, or
note reservations.

The selected Zcash best chain is authoritative. Wallet is in-memory only and is
rebuilt from the pinned birthday checkpoint on every process start.

## State

`Wallet` owns exactly three categories of state:

```text
Wallet
├── ufvk_map     read-only account scanning inputs
├── balance      rewindable notes, nullifier indexes, and transaction history
└── trees        Sapling, Orchard, and Ironwood ShardTrees
```

`WalletBalance` maintains separate per-account unspent indexes for all three
shielded pools. Canonical transaction records retain txid, height, received
notes and memos, and owned spends with the original note. Pool-specific
nullifier indexes make spend detection reconstructible after restart.

`ShardTrees` retains the full ordered commitment stream for Sapling, Orchard,
and Ironwood, including commitments unrelated to either account. Every accepted
height is checkpointed in all three pools so one exact rewind height exists
even when a pool is quiet.

Registry Name Note tips and their undo history are not Wallet fields. They live
in `registry::state::Registry`, which consumes scanner-validated Name Note
evidence against pre-block Wallet state.

## Scanner Boundary

`sync::scan_block` receives one verified full block plus both accounts'
scanning inputs and returns immutable `BlockOutput`. It mutates no Wallet or
Registry state.

`BlockOutput` supplies:

- scanner-derived exact block metadata;
- wallet-relevant ordinary received/spent evidence and raw memos;
- opaque validated Name Note evidence;
- complete ordered commitment streams for all three pools.

The scanner runs once per block with one `ScanningKeys` set containing both
accounts. Wallet routes ordinary notes by their scanner-provided `account_id`;
it does not interpret their memos as operational requests.

## Canonical Application

The orchestrator commits one continuous block in this order:

1. scan the block against the fully-applied cursor;
2. simulate Registry transitions against pre-block Wallet state;
3. prepare the next Wallet balance on a clone;
4. append commitments and checkpoint Sapling, Orchard, and Ironwood;
5. expose the prepared balance only after every tree operation succeeds;
6. install the simulated Registry;
7. install bounded scanner-derived accepted metadata;
8. promote the scanner-derived cursor last.

If tree application fails, Wallet truncates all three trees to the prior
accepted checkpoint and discards the prepared balance. A rollback failure is a
fatal trust-path failure.

The current applicator receives the prior accepted height only for this
rollback target. It does not accept a second caller-supplied current height;
the accepted current height comes from scanner output.

## Reorg Rewind

Canonical rewind targets one exact accepted ancestor:

1. truncate Wallet transaction history, unspent notes, and nullifier indexes;
2. truncate all three trees to that ancestor's checkpoint;
3. truncate Registry tips/history;
4. prune accepted metadata history and restore the exact cursor.

Wallet and Registry contain no operational state to reconcile. A future Live
owner must invalidate cursor-bound OTPs, intents, submissions, locks, and
reservations before passive replacement-branch replay.

The runtime compares one exact Zebra target by both height and hash before
declaring Rebuild complete. Same-height and shorter targets therefore enter
the same common-ancestor path as taller divergent branches.

## Exact Transaction Planning

`NoteLocator` is a neutral typed identity across Orchard, Sapling, and
Ironwood. Exact note lookup lets an opaque transaction plan bind assembly to
the note that was selected without rerunning selection.

Operational exclusion state is caller-owned. Pure selection functions receive
explicit pool identity sets, and Registry fee planning receives
`&BTreeSet<NoteLocator>`. Wallet never infers or stores which Live intent owns a
note.

## Module Ownership

- `sync.rs`: extraction and validation only.
- `wallet.rs`, `wallet/balance.rs`, `wallet/trees.rs`: canonical account
  observations, nullifier indexes, transaction history, and trees.
- `registry/state.rs`: canonical name tips and undo history.
- `main.rs`: passive application ordering, cursor, accepted metadata history,
  and canonical rewind.
- future Live orchestration: request interpretation, reservations, OTPs,
  Treasury policy, proving/signing, submission, and lifecycle events.

Transaction/auth/Treasury libraries exist but are intentionally unwired from
passive replay.

## Remaining Evidence

- failure injection before and after every canonical commit stage;
- deterministic restart/replay equivalence over long histories;
- per-pool append/checkpoint/rollback failures;
- executed same-height, shorter, and multi-block reorg fixtures;
- Zebra root comparison and witness-spend integration;
- Live reservation concurrency once the external owner exists.

## Related Files

- `docs/design/07-mint-run-loop.md`
- `docs/design/08-chain-sync.md`
- `docs/design/09-transaction-assembly.md`
- `docs/design/14a-wallet-storage-rationale.md`
- `src/wallet.rs`
- `src/wallet/balance.rs`
- `src/wallet/trees.rs`
- `src/registry/state.rs`
