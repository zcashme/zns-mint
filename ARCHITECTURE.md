# ZNS Producer ("the mint") — Architecture & Definitions

**One-word problem analogy**: The mint is **the Registrar** for Zcash names.

Just as a traditional domain registry (or the ENS registrar) is the sole authorized party that can record and update the official (name → address) binding in its authoritative store, `zns-mint` is the sole system authorized to record the official binding for a ZNS name by minting the special verifiable Orchard Name Note that makes that binding real and independently checkable on the Zcash chain.

## What "the mint" (the producer) is

The mint is the *only system authorized to create valid ZNS v1 Name Notes on the Zcash chain*.

Its job is to materialize one specific, long-term Orchard spending authority and use that authority, and only that authority, to produce value-0 self-addressed Orchard notes whose:

- `(ψ, rcm)` are derived exactly as `signer::derive::zns_psi_rcm` (domain tag `ZcashName/v1`, length-prefixed BLAKE2b-512, field tags "psi"/"rcm", action bytes from `zns_core::Action`, name, ua, prev_rcm).
- Memos are the canonical registry-authored form `ZNS:<verb>:<name>:<ua>:<prev_rcm_hex>` (encoded by `zns_core::memo::encode_name_note`, never a user request form).
- The only value destinations the authority is ever allowed to create are (per `signer/src/policy.rs:7`):
  1. The value-0 Name Note itself, sent to the registry self-address (derived from the same authority).
  2. Change back to that same self-address.
  3. (When sweeps are enabled) a sweep of excess hot float to a single, policy-hard-coded cold address.

Everything else in the workspace (scanning, parsing, auth challenges, persistence, reorg handling, crash reconciliation, treasury note selection, the poll loop) exists to feed this writer safely, to make its output replayable/auditable from chain data alone, and to bound the damage if the untrusted host/orchestrator is fully compromised.

The producer is deliberately separate from the consumer verification kernel (`zns-verify`). The producer must be able to be checked against the verifier; it must never call into it for its own derivations or decisions (N-version integrity).

The producer is also the only thing that holds the registry's spend key. See the next section.

## The spend key / registry authority — current reality (no assumptions)

In the code that exists today (2026-06-14):

- The authority is a single ZIP-32 Orchard `SpendingKey` at `AccountId::ZERO`.
- It is created exactly here:
  - `DaemonConfig::load()` in mint/src/bin/zns-mint.rs (lines ~336-349) currently does:
    ```rust
    tracing::warn!("using a zero spend seed (testing only)");
    let seed = [0u8; 32];
    ...
    ```
  - Then `signer()` (lines ~417-449) calls:
    ```rust
    Signer::new(self.seed, self.coin_type(), zip32::AccountId::ZERO, policy)
    ```
  - Inside signer/src/sign.rs `Signer::new` stores a `Zeroizing<[u8; 32]>` copy. The only place the real `SpendingKey` is ever materialized is the transient `spending_key(&self)` method (line 104), which re-derives it on the stack for the duration of `sign_mint` / `sign_relay` / `sign_sweep` and then drops it.
- From this key the following are derived at construction (and exposed for the host side):
  - `FullViewingKey` (public) — used by the scanner (`chain`) for IVK trial-decrypt of incoming requests and by the treasury `NoteState` (`state/treasury.rs`) to import a *view-only* account into a `zcash_client_sqlite::WalletDb`.
  - The registry "self-address" (Orchard receiver at index 0, external scope) — this is `registry_addr` in `SpendPolicy`. Every Name Note and all change is sent here.
  - The Unified Incoming Viewing Key (UIVK, external scope only) — printed by `zns-mint viewkey`. This is the key that external resolvers are expected to use to scan for Name Notes addressed to `addr_reg`. It is the "published" key referenced in Claude.md and the binary comments.
- The `SpendPolicy` (constructed in the same `signer()` method) hard-codes:
  - `registry_addr`
  - `cold_addr` (today, if `COLD_ADDR_UA` is the empty string in the binary, this falls back to `registry_addr` and sweeps are force-disabled).
  - Fee caps, watermarks, velocity limits, etc.

There is **no other mechanism** in the current tree for creating or loading the long-term Orchard spend authority.

### What does *not* exist in the code or docs for the spend key (the protocol-level gap)

- No key generation ceremony (multi-party, air-gapped, hardware, etc.) for the seed that will become the long-term registry authority.
- No threshold signing (FROST over Pallas) for the hot key itself. custody-check.md explicitly calls this out as future work.
- No on-chain or spec-level "root of trust" binding beyond "the key whose IVK we publish and from which `addr_reg` is derived."
- No process described for the initial capital inflow that seeds the self-funding treasury (someone must send ZEC to the derived UA; after that, change from funded mints/relays keeps the float alive).
- The cold destination is still an Orchard address in the policy today (the 3-of-5 transparent P2SH work in `tools/` and custody-check.md is preparatory and not yet wired into `SpendPolicy` or `build_sweep`).
- The binary has no real secret loading (env, file, KMS, enclave sealing, etc.). Everything is a compile-time or `load()` constant for the current dev/attestation story.
- No key rotation story, no compromise recovery procedure, and no interaction defined between key continuity and a future `ZcashName/v2` domain tag bump.

The most candid document in the tree on this topic is custody-check.md (dated 2026-06-12). It treats the single hot Orchard key as an audit finding and describes the hot-float + policy-fixed cold sweep direction as the pragmatic interim step.

## Crate boundaries and "each crate does one job"

The workspace uses a zebra-inspired split (see workspace `Cargo.toml` comments and Claude.md). The explicit goal visible in the code (especially `signer/src/policy.rs:3` and the "host proposes / signer decides" comments in the binary and `mint/src/lib.rs`) is to make a fully compromised orchestrator ("the host") unable to redirect value or cause unauthorized Name Notes.

Current responsibilities (post-refactor):

- `core`: Pure domain types + the strict, producer-side memo grammar and name validator. No crypto, no I/O, no state. (One job: define the protocol surface that must be bit-identical with the verifier.)
- `chain`: Untrusted network I/O only — compact block intake for `addr_reg` (IVK trial decrypt + full-tx memo fetch) and gRPC broadcast to lightwalletd/zebrad. Pulls data (notes, blocks, reorg signals) from the chain. No keys, no policy, no persistence decisions. Good separation.
- `state`: Owns SQLite persistence. `State` struct owns the Connection(s). Exposes high-level push methods (apply_mint, apply_reorg, etc.) and pull methods (get_record, list_intents, etc.). Tables: names (live tip), name_events (history), processed_notes, pending_challenges, mint_intents. Internal reorg/apply logic. Supports WAL multi-connection (writer for pushes, readers for pulls). Separate from treasury note-state (WalletDb wrapper).
- `auth`: Pure, deterministic OTP challenge/response logic (block-height TTL, no clocks, no I/O). Good.
- `signer` (the crate aliased `zns-mint`): The privileged job. Owns the seed (Zeroizing), the `SpendPolicy` constants, the `SpendGuard` (replay + velocity), the re-derivation of `(ψ, rcm)`, all bundle building (`add_zns_output`, the funded mint path, relay, sweep), proving, and signing. The policy comment states the contract explicitly: the host may only ever propose *intent*; the signer authors recipients, amounts, and the deterministic fields. This crate is the only one that pulls the `zns-orchard` proving stack or ever sees the real `SpendingKey`.
- `mint` (the crate aliased `zns-registry`, home of the `zns-mint` binary): The daemon orchestrator / thin coordinator. Owns the poll loop, wiring of the other crates, `Registry` (sequencing for claim vs. challenge/confirm, calls to chain for pulls, calls to state for pushes via high-level methods, treasury sync + funding selection + sweep decision, RPC surface). Proposes intents and recovery actions to the signer; never touches the seed. No raw DB ownership.

Does "one job per crate" hold?

It successfully enforces the critical safety property (value redirection and arbitrary minting are impossible from a compromised host). The `signer` crate is a clean trust boundary.

The refactored pattern cleanly separates pull (chain) from push (state). `mint` is now a thin coordinator. State owns persistence and its invariants. This matches the zebra cf. comments and the goal of crate boundaries mirroring data/trust boundaries.

## Data flow (post-refactor)

```
lightwalletd / zebrad
        ^
        | (gRPC: compact blocks, txs, mempool, broadcast)
        |
zns-chain (scanner + grpc)
   - pulls: notes (scan_incoming / scan_mempool), block hashes, tip, tx existence
   - no persistence, no policy
        |
        v (IncomingNote batches, reorg signals)
zns-state (owns Connection(s) + schema)
   - pushes: apply_mint, apply_reorg (internal deletes + rebuild), put_intent, put_challenge, mark_processed, etc.
   - pulls: get_record, list_intents, is_processed, last_processed_height, etc.
   - tables: names (live), name_events (history + PK on (name,height)), processed_notes, pending_challenges, mint_intents
   - WAL + pragmas for multi-conn (writer pushes, concurrent readers for pulls)
   - atomic tx for apply paths
        ^
        | (pull current state for decisions)
        | (push decisions/results)
        |
mint (orchestrator, thin Registry)
   - poll loop (bin)
   - pulls from chain (notes, reorg detection via hashes)
   - pulls from state (tips, challenges, intents for auth/sequencing)
   - calls signer (propose only)
   - pushes to state (via high-level apply_*)
   - owns RPC (read-only), treasury NoteState
```

Critical: writes-before-broadcast (intent written before tx broadcast; persistence only after confirmed or via reconcile). Reorgs pushed to state. N-version: signer re-derives independently.

## How the producer actually runs (one paragraph from the binary)

The binary (`mint/src/bin/zns-mint.rs`) is a forever loop (15s ticks):
- Advance signer velocity window.
- Reorg check (pull hashes from chain + state) + push rollback to state (apply_reorg) + release of replay slots.
- Intent reconciliation (pull from state, check tx via chain, push via apply_mint or delete).
- Historical rescan via chain (pull notes) + unsettled filter (pull via state) + mempool (confirms only).
- Treasury `NoteState` sync + pick funding note.
- Policy-driven sweep (signer authors).
- `Registry::process_notes`: for each unsettled note, dispatch (fee gates, name existence via state pull, durable challenge via state push, do_mint which writes intent via state push *before* broadcast, then atomic push via apply_mint that appends history, updates tip, consumes challenge, clears intent).

All of this exists so that the only transactions that ever get signed by the authority are ones the policy would have allowed from public request data + the on-chain name history.

## Current implementation shortcuts (call them out)

- Zero seed + "testing only" warning.
- All paths, DB names, poll interval, watermarks, `COLD_ADDR_UA`, network, birthday, RPC port, etc. are compile-time or `load()` constants.
- `zns-mint address` / `viewkey` / `scan` are the only "operator" commands; there is no clap.
- Unfunded (value-0, no treasury) mode is supported for exercising the unfunded `build_name_note` path.
- No enclave / secret store / attested measurement wiring yet (the policy comments talk about it as the production shape).

These are not bugs; they are the current state of the producer harness while the protocol logic and the hot/cold custody direction are being hardened.

## How to explore / extend

- The critical comments to read (in code):
  - `signer/src/policy.rs:3` ("fully compromised host is worthless")
  - `mint/src/bin/zns-mint.rs:1` (the loop + config story)
  - `mint/src/lib.rs:520` (`do_mint` and the intent-before-broadcast protocol)
  - `state/src/lib.rs:1` (why State owns persistence)
  - `custody-check.md` (the honest single-key assessment)
- To change what the authority is allowed to do: change `SpendPolicy` + the three sign methods in `signer`. Do not add host-supplied recipients.
- To change name lifecycle rules or crash safety: that lives in the high-level apply methods in state + sequencing in mint.
- Key material changes are a protocol + custody design task, not a local refactor. See the gaps section above.

This document should be updated in the same change as any modification that affects what Name Notes the producer is allowed to emit or how its authority is realized.

## Post-refactor data boundaries (pull / push)

- Chain: pull only.
- State: owns DB; high-level push (apply_*) for mutations/reorgs/intents; high-level pull for queries.
- Mint: coordinator; pulls from chain + state; pushes decisions to state; proposes to signer.
- Signer: decides and signs.

See crate responsibilities above for details.