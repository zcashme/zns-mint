# 13 - Implementation Slices

This document breaks the ZNS mint into small programming problems.

The goal is to keep each slice small enough to code, test, and review without
changing the protocol accidentally. Each slice should end with the crate
building and the relevant tests passing.

## Slice 0 - Restore A Green Baseline

Purpose: make the current source compile before adding new behavior.

Work:

- fix syntax and stale test references in `payload.rs`;
- run `cargo check`;
- run focused payload tests;
- run `cargo clippy --all-targets -- -D warnings` once the syntax is clean.

Done when:

- the crate compiles;
- payload vectors still pass;
- no protocol docs need correction for the fix.

## Slice 1 - Name The Runtime Model

Purpose: keep terminology stable.

Work:

- use "attested issuer" for the role of `zns-mint`;
- use "mint runtime" for the running process;
- use "Registry spending key" for the write authority;
- use "Zcash best chain" for source of truth.

Done when:

- protocol docs no longer describe the mint as merely a daemon or as a smart
  contract;
- resolver docs say anyone can run a resolver with the Registry UFVK and chain
  data.

## Slice 2 - Define The In-Memory Wallet Data Model

Purpose: decide what state the in-memory wallet holds, and the narrow types
that hold it.

Module: `wallet.rs` plus `registry.rs` (peer newtype over the name chain).

State to represent:

- chain checkpoint: height, block hash, tree sizes/frontiers;
- wallet notes for Treasury and Registry;
- note nullifiers and spent status;
- Registry Name Note witnesses;
- name index derived from confirmed Name Notes.

Rules:

- no seed material;
- no spending keys;
- no operator-readable secret config;
- local state is rebuildable from chain;
- best-chain replay wins over in-memory disagreement;
- no durable state: the wallet is a pure cache, rebuilt from the birthday
  checkpoint on every boot.

Done when:

- there is a documented data model;
- code has narrow types for the in-memory records;
- tests prove records round-trip without exposing key material.

## Slice 3 - Turn Sync Output Into Wallet Observations

Purpose: make scanning feed the wallet boundary instead of returning only a
summary.

Work:

- keep the scanner role-agnostic;
- emit observations for Treasury-received request memos, Registry-received Name
  Note memos, spent notes/nullifiers, and value notes for both accounts;
- avoid logging memo contents;
- keep block verification fail-loud.

Done when:

- a scanned block can update wallet state through a narrow interface;
- Treasury request detection and Registry Name Note detection both work;
- Treasury and Registry scans use the same observation model.

## Slice 4 - Track Registry Name Note Witnesses

Purpose: make update/release spendable.

Work:

- identify Registry-received Name Notes;
- store the decrypted note data needed by Orchard;
- maintain Merkle witness data as blocks advance;
- mark a Name Note spent when its nullifier appears;
- bind the current name tip to the spendable note.

Done when:

- for a live name, the mint can locate the prior Name Note and witness needed
  by the future Registry Name Note transaction path;
- release/update no longer stop only because witness data is missing.

## Slice 5 - Transaction Assembly

Purpose: turn signed/proven bundles into real Zcash transactions.

Work:

- assemble a full transaction around Registry Name Note actions;
- compute the real v5 sighash;
- fund Name Note fees from the Registry account;
- fund OTP relay fees from the Treasury account;
- keep Name Notes value `0`;
- keep payment-for-name separate from Name Note value;
- produce a transaction ready for Zebra submission.

Done when:

- claim builds a broadcastable transaction;
- OTP relay builds a broadcastable transaction to the current UA;
- update/release build broadcastable transactions once witnesses exist;
- tests or smoke checks prove signatures are over the real transaction sighash,
  not a stand-in.

## Slice 6 - Zebra Submission

Purpose: use Zebra as the chain interface for outgoing transactions.

Work:

- choose the exact Zebra submission RPC surface available to deployment;
- add a narrow submit client;
- record txid and submission status;
- retry only according to explicit policy;
- do not hide permanent failures.

Done when:

- assembled transactions can be submitted through Zebra;
- submission results update `PENDING_TX`;
- failures are redacted but actionable in logs/metrics.

## Slice 7 - Live Best-Chain Loop

Purpose: replace one-shot scan with the real mint loop.

Work:

- subscribe to or poll best-chain changes through Zebra;
- fetch and verify blocks;
- update wallet state and name state at coherent block boundaries;
- process request outputs;
- submit ready transactions;
- handle reorg rewind/replay.

Done when:

- `main.rs` is still a phase orchestrator;
- the mint continuously follows the best chain;
- reorg handling rewinds wallet, witness, name, and submission state together.

## Slice 8 - Metrics

Purpose: expose operational health after state transitions are clear.

Likely metrics:

- boot success;
- best observed height;
- last processed height;
- loop heartbeat timestamp;
- detected ZNS requests;
- rejected requests by coarse reason;
- OTP issued/accepted/expired;
- submitted transactions;
- confirmed transactions;
- reorg count.

Done when:

- metrics describe the mint runtime without leaking names, UAs, OTPs, memos, or
  key material.

## Slice 9 - TEE Seed Blob

Purpose: replace the dev zero seed.

Work:

- decrypt the attestation-bound seed blob inside the TEE;
- derive Treasury and Registry accounts;
- zeroize plaintext immediately;
- fail loudly if blob intake or attestation binding fails.

Done when:

- no dev seed remains in production path;
- no env vars, CLI flags, or plaintext config are introduced;
- key material remains impossible to observe through logs or debug surfaces.
