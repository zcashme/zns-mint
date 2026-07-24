# 08 - Chain Sync

## Chain Source

The current implementation uses two Zebra interfaces:

- indexer gRPC `ChainTipChange` as a wake-up/liveness stream;
- a read-only JSON-RPC facade over `getblockchaininfo` and `getblock` for
  point-in-time best-chain reads.

The JSON-RPC `getblock` response contains raw block bytes, not an independent
server-reported hash. The mint parses those bytes, derives the claimed height
and header hash, and checks continuity against its exact prior metadata.
Selected-best-chain membership and full consensus validity remain Zebra's job.

## Birthday Checkpoint

Scanning from an arbitrary post-Sapling height requires prior tree state. The
current code uses the block immediately before NU6.3/Ironwood activation as the
ZNS origin checkpoint. It fetches that tree state from local Zebra through
`z_gettreestate` and requires its block hash to match the attested binary's
pinned origin hash. After boot, wallet state lives in memory and is rebuilt by
replaying from that checkpoint on restart. There is no durable wallet state
across restarts.

## Scanner Boundary

The sync module is a **pure, non-mutating library**: verified `Block` + UFVKs
in, opaque `BlockOutput` evidence out. It owns no run loop and mutates no wallet
or Registry state. The orchestrator owns catch-up, reorg detection, and the
state-transition boundary.

Ordinary notes use pinned `zcash_client_backend` decryption and scanning. Name
Notes require a supplemental pass over Ironwood V3 actions with the exact
Registry external IVK/address because their memo-derived commitment opening is
not a standard Orchard-family note opening. The Orchard fork's private-domain
facade returns an opaque validated note only when the decrypted memo-derived
opening matches the action commitment. This is not Registry authorship; the
Registry state machine requires same-transaction Registry input evidence and a
legal transition.

## Block Output

Scanning one block produces a `BlockOutput` carrying two distinct concerns:

- **transaction evidence** — every Ironwood transaction, plus standard
  transactions with wallet-relevant decrypted outputs or spends. Each
  immutable `TxOutput` binds its source txid and block index to received notes
  and the raw public Orchard, Sapling, and Ironwood nullifiers retained for
  that transaction. Wallet spend detection resolves those nullifiers against
  rewindable local indexes.
- **`orchard_commitments` / `ironwood_commitments` /
  `sapling_commitments`** — the separate *full ordered commitment streams* for
  the block: every action's `cmx` and every output's `cmu`, wallet-relevant or
  not. The wallet's per-pool `ShardTree`s must append all of them to stay in
  sync with the chain; skipping non-wallet actions or mixing Orchard and
  Ironwood would break witnesses.

## Memo Capture

Upstream `decrypt_block` / `scan_block` drop the memo in their output types
(`WalletOutput` has no memo field), and `BatchResult` that carries the memo
is opaque. The public memo path is `zcash_client_backend::decrypt_transaction`
(`decrypt.rs:123`): takes UFVKs directly, returns `DecryptedTransaction` with
`DecryptedOutput`s carrying `MemoBytes` in-band. Sync calls
`decrypt_transaction` per tx for notes + memos + accounts, and `scan_block`
(upstream) for positions and the full commitment stream. UFVK → memo happens
in one upstream call for ordinary notes. The separate Name Note supplement
uses only the fork's validating facade and the Registry external IVK; it never
exposes the relaxed decryption domain.

Memos are wrapped in the `Memo` newtype (`mint.rs`) at the sync extraction
boundary. `Memo` is a newtype around upstream `MemoBytes` with `Debug`
redacted — ZNS memo contents are shielded user data and must not leak to
logs (AGENTS.md "treat key material as radioactive").

## Memo Detection

Treasury-received Orchard memos are shielded user request data. Sync surfaces
raw decrypted memos to the caller; it must not log them (the `Memo` newtype's
`Debug` is redacted for this reason).

Memo grammar alone never creates a Name Note. Ordinary Registry Ironwood notes
remain ordinary even if their memos contain ZNS-shaped bytes. Only a value-zero
Ironwood V3 output to the exact Registry address whose memo-derived opening
matches its action commitment enters the opaque candidate lane. Unauthenticated
candidates are ignored by Registry replay and cannot halt chain following.

## Witness Tracking

Update and release require spending prior Registry Name Notes. The supplement
records exact `(block hash, height, tx index, txid, action index, position)`
identity, cross-checks the upstream commitment stream, and promotes the
corresponding retention mark. Registry tips retain that exact validated note
and locator for later witness lookup.

## Reorg Handling

Reorg handling must rewind:

- wallet scan state;
- nullifier state;
- note witnesses;
- confirmed Name Note state;
- the fully-applied cursor and accepted metadata history.

The runtime retains exact accepted `BlockMetadata` for each applied height.
Common-ancestor search compares local and Zebra hashes at the same height;
rewind restores that ancestor's real hash and all three tree sizes. If the
reorg extends below retained history, the mint fails closed and rebuilds from
the pinned origin on process restart rather than fabricating cursor metadata.
The current process aborts on `ReorgBeyondHistory`; it does not perform an
in-process rebuild. Accepted metadata and each tree retain 101 checkpoints:
the current accepted height plus 100 predecessors. Metadata therefore cannot
nominate an ancestor whose tree checkpoint was intentionally pruned.

Rewind preflights the exact Sapling, Orchard, and Ironwood checkpoints before
mutating any pool. The trees truncate first; only then do the infallible Wallet
balance/nullifier history, Registry history, accepted metadata, and cursor
truncate.

Operational intents, submissions, OTPs, locks, and reservations are not fields
of canonical Wallet or Registry state. The future Live owner must invalidate
all cursor-bound operational work before rewind, replay the replacement branch
without effects, and reconstruct/revalidate work only at a freshly verified
exact Zebra tip.

Confirmed name state must always match the selected best chain.

ZNS uses immediate best-chain finality: the current Zcash best chain is the
truth. Reorgs are handled by rewinding and replaying, not by waiting for a
protocol-level confirmation depth.

Passive Rebuild captures one checked `(height, hash)` from
`getblockchaininfo`, compares from `min(local height, target height)`, and
replays only through that target. It succeeds only when the installed cursor,
the target block bytes, and a second exact-tip response still agree. A target
that changes during replay is discarded and recaptured without operational
effects. Every successful block read and every common-ancestor result,
including an apparent retained-history exhaustion, is followed by an exact-tip
recheck before the result is used.
