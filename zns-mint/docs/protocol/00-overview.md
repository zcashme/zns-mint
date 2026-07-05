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

### What exists and works

- **Protocol kernel** (`mint.rs`): `Action`, `Name`, `zns_psi_rcm`,
  `encode_name_note`, `decode_name_note` — the ZNS payload derivation and memo
  codec.
- **Key derivation** (`key.rs`): `Keys::from_seed`, UFVK accessors, spending
  key accessors (`pub(crate)`).
- **Boot sequence** (`boot.rs`): Zebra liveness check, gRPC + JSON-RPC
  cross-validation, chain integrity verification, wallet initialization.
- **In-memory wallet** (`wallet.rs`, `wallet/selection.rs`): per-account note
  maps, nullifier index, Orchard commitment tree, fund selection (best-fit
  strategy).
- **Registry state machine** (`registry.rs`): `Registry` (name → tip map),
  `Tip`, `NameNoteRequest`, `authorize_claim` / `authorize_update` /
  `authorize_release`.
- **Block scanner** (`scanner/scan.rs`): `scan_verified_block` — decrypts
  Orchard outputs, routes notes by account, parses Name Note memos, updates
  wallet and registry.
- **Reorg buffer** (`scanner/reorg.rs`): `ReorgBuffer` cursor and `UndoState`
  structure (stub — only `height` is populated).
- **Chain reader** (`zcash/chain.rs`): Zebra gRPC client — tip reads, full
  block fetch/parse/verify, block poller.
- **Zebra client** (`zcash/zebra.rs`): gRPC chain observer, JSON-RPC client,
  birthday checkpoint load/create from `z_gettreestate`.
- **Treasury memo parser** (`treasury/memo.rs`): `RequestMemo` parsing for
  claim/update/release request memos.
- **Treasury fee matching** (`treasury/fee.rs`): `match_fee` — claim payment
  detection (simplified — matches by exact value, not yet by memo content).
- **Treasury auto-sweep** (`treasury/sweep.rs`): `sweep_policy` — produces
  `SweepRequest` when Treasury balance exceeds threshold.
- **Treasury Registry funding** (`treasury/fee.rs`): `registry_funding_policy`
  — produces `RegistryFundingRequest` when Registry balance is below floor.
- **Metrics** (`metrics.rs`): Prometheus server.

### What exists but is stubbed

- **OTP credential store** (`auth.rs`): `OtpStore` with `issue` and
  `verify_consume` — written and tested, but **commented out in `lib.rs`**
  (`// pub mod auth;`) because it imports a non-existent `payload` module.
- **Scanner bootstrap** (`scanner/scan.rs::bootstrap`): returns a stub cursor,
  does not load `birthday.json` or seed the wallet tree.
- **Scan-to-tip loop** (`scanner/scan.rs::scan_to_tip`): empty `TODO` body.
- **Birthday checkpoint** (`src/checkpoints/`): directory exists but is empty —
  no `birthday.json` has been written.
- **Transaction assembly** (`registry.rs::build_transaction`): `todo!()` —
  no witness derivation, sighash, fee funding, or broadcast.
- **Mempool observer** (`zcash/mempool.rs::spawn_observer`): stub loop, not
  wired to a real gRPC endpoint.
- **TEE seed intake** (`boot.rs::obtain_key_source`,
  `boot.rs::decrypt_sealed_blob`): `todo!()` — the mint cannot boot in
  production until this is implemented.

### What does not exist yet

- Orchard bundle building, proving, and signing.
- Real v5 sighash computation.
- Fee funding integration (selecting notes, constructing spends).
- Transaction broadcast and submission tracking.
- Reorg rewind/replay (the `UndoState` shape is present but unwired).
- Live best-chain subscription loop.
- TEE-sealed-blob decryption.
- Confirmation tracking and retry.

The current code is a foundation, not the finished mint. The docs in
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