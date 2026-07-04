# 07 - Mint Run Loop

This document describes the target shape that `main.rs` should eventually
orchestrate. It is not a demand to put all logic in `main.rs`; `main.rs` should
remain a thin phase orchestrator.

## Phase Shape

The mint runtime has three broad phases:

1. boot;
2. catch up to the best chain;
3. run forever on chain and submission events.

There is no "restore" phase. The mint holds no durable wallet, name, witness,
or scan-checkpoint state across restarts; on every boot it replays from the
static birthday checkpoint and rebuilds wallet/name state purely from chain.
See `08-chain-sync.md` "Birthday Checkpoint": the only durable artifact the
mint depends on is the birthday checkpoint itself; all wallet/name state is
rebuilt from it on every boot.

In rough pseudocode:

```text
init tracing
accounts = boot()

catch_up_from_birthday(accounts)

loop:
  event = next_chain_or_submission_event()
  match event:
    new_block(block):
      verify_block_shape(block)
      scan_accounts(block)
      apply_detected_name_notes(block)
      process_detected_treasury_requests(block)
      assemble_ready_transactions()
      submit_ready_transactions()

    reorg(common_ancestor):
      rewind_wallet_state(common_ancestor)
      rewind_name_state(common_ancestor)
      replay_best_chain_from(common_ancestor)

    mempool_or_submit_result(result):
      update_submission_state(result)
      retry_or_mark_failed(result)

    shutdown:
      exit
```

## Boot Responsibilities

Boot proves that the chain source is alive and serving structurally valid data,
then derives accounts. Seed material should not be touched before the chain
source passes the boot checks.

Boot does not own sync policy, request policy, transaction policy, or run-loop
state machines.

## Rebuild Responsibilities

Because there is no durable state, the catch-up phase *is* the rebuild. The
mint seeds its in-memory wallet from the static birthday checkpoint and scans
forward from there. There is no "load state" step and no "fail loudly on
inconsistent state" branch, because the only durable artifact is the birthday
checkpoint itself, which is created and validated once (see
`08-chain-sync.md`).

## Catch-Up Responsibilities

Catch-up scans from the birthday checkpoint to the current tip. It must:

- scan Treasury and Registry accounts in one pass;
- surface incoming Treasury request memos;
- surface incoming Registry Name Note memos;
- apply confirmed Name Notes in chain order;
- process Treasury request memos only after the state needed to validate them is known;
- update witness data for spendable Registry Name Notes.

## Live Responsibilities

The live loop consumes best-chain changes and submission results. For each new
block it should scan once and fan out observations to account-specific logic.

The live loop should not duplicate the full block scan for Treasury and Registry
forever. The current code does this for simplicity; production should share the
block fetch/decode pass and apply both accounts' scanning keys.

## Request Processing Order

Within a block, confirmed Name Notes should be applied before request memos that
depend on the resulting state. Across blocks, chain order is authoritative.

The run loop must distinguish:

- observed Registry Name Notes, which update confirmed name state;
- Treasury-received claim requests, which can produce claim transactions;
- Treasury-received update/release requests without OTP, which produce
  Treasury OTP relay transactions;
- Treasury-received update/release requests with OTP, which produce Registry
  Name Note transactions once witnesses and funding are available.

## Output Queues

The run loop needs explicit queues for:

- Treasury OTP relay memos awaiting transaction assembly;
- claim bundles awaiting Registry fee funding and broadcast;
- update/release operations awaiting witness data;
- assembled transactions awaiting submission;
- submitted transactions awaiting confirmation or retry.

No queue entry should contain plaintext seed material or spending keys.
Pending OTPs are in-memory authorization state and expire 30 minutes after
issuance.

## Failure Policy

Boot and trust-path failures are fatal.

Per-request failures are not fatal. They should produce redacted rejection logs
and leave the mint running.

Birthday-checkpoint corruption is fatal: the static checkpoint is the one
durable artifact the rebuild depends on, and a corrupt or missing checkpoint
that cannot be re-derived from trusted Zebra leaves the mint with no
authoritative starting state.
