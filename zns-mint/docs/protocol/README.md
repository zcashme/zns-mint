# ZNS Mint Protocol

This directory is the design source for `zns-mint`: the Zcash Name Service
mint.

`zns-mint` is the attested issuer for ZNS Name Notes. It runs inside an
attested TEE, derives two ZIP-32 accounts from one seed, scans Zcash chain data,
detects shielded ZNS memos, and creates Orchard Name Notes that encode name
ownership and lifecycle state.

The central security question is: can the Registry spending key ever be seen by
a human? The intended answer is no. The Registry key must exist only inside
attested hardware, and every protocol, boot, sync, and run-loop decision must
preserve that boundary.

## Document Map

- [00-overview.md](00-overview.md) defines the system goal, scope, and current
  implementation state.
- [01-trust-model.md](01-trust-model.md) defines parties, capabilities, and
  trust boundaries.
- [02-accounts-and-keys.md](02-accounts-and-keys.md) defines the seed, Treasury
  account, Registry account, and key-handling constraints.
- [03-name-note.md](03-name-note.md) defines the Orchard Name Note artifact.
- [04-memo-grammar.md](04-memo-grammar.md) defines request, Name Note, and OTP
  memo formats.
- [05-lifecycle.md](05-lifecycle.md) defines claim, update, release, and the
  per-name chain rule.
- [06-authorization.md](06-authorization.md) defines v1 authorization policy and
  OTP flow.
- [07-mint-run-loop.md](07-mint-run-loop.md) sketches the long-running
  `main.rs` orchestration target.
- [08-chain-sync.md](08-chain-sync.md) defines chain scanning, checkpointing,
  reorg, and witness expectations.
- [09-transaction-assembly.md](09-transaction-assembly.md) defines the missing
  bridge from signed Orchard bundles to broadcastable Zcash transactions.
- [10-resolution-and-verification.md](10-resolution-and-verification.md)
  defines how resolvers and independent verifiers consume Name Notes.
- [11-open-questions.md](11-open-questions.md) records decisions not yet fixed.
- [12-programming-model.md](12-programming-model.md) explains the concrete
  software shape, database responsibilities, Zebra interaction, and run-loop
  pipeline.
- [13-implementation-slices.md](13-implementation-slices.md) breaks the mint
  into small implementation slices with module boundaries and verification
  gates.
- [14-wallet-design.md](14-wallet-design.md) defines the in-memory wallet:
  per-account note maps, nullifiers, witnesses, undo buffer, ZNS-specific
  Registry view, sync flow, and integration with the treasury and registry
  layers.
- [15-treasury-module.md](15-treasury-module.md) defines the `treasury.rs`
  module: Treasury wallet view, fund selection, request memo classification,
  auto-sweep, Registry funding, and claim payment detection.

## Working Rule

When source code implements or changes protocol behavior, update the matching
document in this directory in the same change. If the code and docs disagree,
stop and resolve the protocol decision before continuing.
