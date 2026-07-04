# 00 - Overview

## What We Are Building

`zns-mint` is the Zcash Name Service mint: the attested issuer for ZNS Name
Notes. It maintains the authoritative write path for ZNS names by holding the
Registry spending key inside the TEE and emitting chain-verifiable Name Notes.

A ZNS name is a human-readable handle, such as `alice`, that maps to a Zcash
Unified Address. Owning a name means being able to reassign the address it
points to, or release the name so it can be claimed again.

The on-chain artifact for ownership is an Orchard Name Note: an Orchard note
whose memo carries the canonical ZNS payload and whose commitment is produced
through the ZNS Orchard fork. The Registry account can spend Name Notes, so the
Registry spending key is the sole namespace authority.

## Scope

The mint must:

- derive Treasury and Registry accounts from one seed;
- keep the Registry spending key inside the attested boundary;
- connect to Zcash chain data through Zebra or another approved chain source;
- scan Treasury and Registry accounts;
- detect shielded ZNS request memos received by the Treasury;
- detect shielded ZNS Name Notes received by the Registry;
- rebuild confirmed name state from observed Name Notes;
- validate user requests against that state;
- authorize updates and releases;
- build, prove, sign, fund, and broadcast Name Note transactions;
- rebuild in-memory chain and wallet state from the birthday checkpoint on
  every boot, with no durable state across restarts.

## Current Implementation State

The current crate has the protocol kernel, full-block scanner, OTP credential
store, and key derivation. It does not yet have Orchard bundle signing,
production transaction assembly, fee funding, broadcast, reorg handling, live
subscription, or TEE seed-blob decryption.

The current code is therefore a foundation, not the finished mint. The docs in
this directory describe the target protocol and run-loop shape that the code
should converge toward.

## Non-Negotiable Constraints

- No environment variables, CLI flags, or config files for secrets or trust
  inputs.
- Boot failures are fatal.
- Key material is never logged, displayed, serialized, or debug-formatted.
- The Registry spending key is reachable only by the attested Registry
  transaction path; the Treasury spending key is reachable only by the attested
  Treasury transaction path. Neither key is exposed to modules that do not
  sign.
- The protocol kernel is byte-stable against `zns-verify` vectors.
- The mint holds no durable state. Canonical ownership comes from confirmed
  Name Notes on the best chain; in-memory state is a cache rebuilt from the
  birthday checkpoint on every boot.
