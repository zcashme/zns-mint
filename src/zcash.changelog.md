# Zcash I/O changelog

## 2026-09-20 — Keepalive claims verified against regtest Zebra (#88)
- The doc comments' keepalive claims are now measured facts, not
  assertions: wire-level probe against regtest (node frozen mid-stream)
  — PING every 30s after the last received frame, connection torn down
  `hyper::Error(Http2, KeepAliveTimedOut)` at ping + 15s, open stream
  surfaces the death as an `Err` ~35s after its last live frame;
  without keep-alive, `next()` hangs silent past 60s. Fresh
  subscriptions deliver the current tip immediately (three runs).
- Zebra's server runs its own 30s keep-alive: pings are bilateral.
- Doc comments on `ChainClient::connect`, `TipSession`, and
  `next_tip` rewritten to the measured facts; keep-alive constants
  scoped private to `chain.rs` (single consumer).

## 2026-09-19 — TipSession owns the tip stream (#88)

- The tip stream's lifecycle lives in one place now: `TipSession` in
  `chain.rs` holds only what nothing else holds — the subscription and
  the client it rides on. `main` wakes on `next_tip` and never sees
  transport state; the bare `tips` local, the inline reconnect policy,
  and `main`'s `tip_stream` helper are gone.
- Truth is self-derived: `next_tip` re-reads the canonical tip via
  `getblockchaininfo` before answering, so a notification is a wake-up,
  never an answer. The fresh-subscription immediate-tip delivery
  (Zebra's never-seen master receiver + the cloned watch's inherited
  staleness) that made reconnects recover today is documented as an
  optimization, never a dependency.
- Recovery is immediate and on our clock: a stream error or end pauses,
  re-opens the subscription, and returns a freshly read tip — never
  waiting for an announcement a change-only stream may owe only after the
  next block. A repair may leave the fresh snapshot unconsumed; the next
  wake then re-derives an unchanged tip and runs a harmless idempotent
  pass.
- Silence is detectable: `ChainClient::connect` configures HTTP/2
  keep-alive (`KEEP_ALIVE_INTERVAL` 30s, `KEEP_ALIVE_TIMEOUT` 15s,
  while-idle). A half-open connection — receive-only after the headers,
  so invisible to the application — now surfaces as a stream error in
  bounded time instead of an eternal `next()` hang.
- `chain_tip_change_stream`, `TipStream`, and `tip_height_hash` are now
  `pub(crate)`: the session is the only consumer of the stream
  internals; `TipSession` is the exported surface.

## 2026-09-16 — `JsonRpc::get_subtree_roots` (`z_getsubtreesbyindex`)

- New method, generic over `Node: HashSer`. Boot calls it for `"sapling"`
  and `"ironwood"` (not `"orchard"` — no Orchard spend path).
- Cross-checks echoed `pool` and `start_index` (`BadNodeData` on mismatch).
  Root hex is canonical HashSer, not display-order reversal; tests lock
  that with an asymmetric field element.

## 2026-09-01 — `CanonicalTip` deleted; tips are `(BlockHeight, BlockHash)` tuples

- `CanonicalBlockSource::exact_tip()` returns `(BlockHeight, BlockHash)` —
  the same shape as the gRPC side's `tip_height_hash`. One concept (a
  best-chain tip observation), one shape across both transports.
- The parse-atomicity guarantee the struct documented ("height and hash
  parsed from the same response") always lived in the parse function, not
  the type: it now lives in `BlockchainInfo::canonical_tip()`'s doc, where
  it is enforced. The private-field struct additionally prevented external
  fabrication of a tip, but `exact_tip` was already the sole producer with
  no hand-assemblers — that protection had nothing to stop. The tuple can
  be hand-assembled; accepted because no fabricator exists and `BlockMetadata`
  remains the distinct scan-cursor concept (never conflated with tip
  identity — the reorg loop compares them deliberately).

## 2026-09-01 — Mempool-ready transport

- Bumped `zebra-indexer-proto` to 2.5 and adopted its typed layer. The
  bespoke `MempoolEvent` enum is deleted: it re-wrapped
  `(MempoolChangeKind, TxId)` — both upstream types — with no added
  invariant. `mempool_events()` now streams that pair directly; the
  correspondence between wire values and meaning is owned by the proto
  crate's generated enum, and this module keeps only the display-order →
  `TxId` byte reversal (the proto crate carries no librustzcash
  dependency, by design).
- `mempool_events` returns `impl Stream` over `Result<(kind, txid),
  TransportError>` items, not `tonic::codec::Streaming<...>`:
  `StreamExt::map` yields a `Map` adaptor (futures-util
  `stream/stream/map.rs:15`), never a `Streaming` (whose inherent
  methods are constructors plus `message`/`trailers`, tonic
  `codec/decode.rs:60-361`), and every item is a `Result`
  (`decode.rs:398`). `Status` items are folded into `TransportError`
  inside the closure via the `Tonic` variant; the `and_then` conversion
  runs after `map_err` because the two error types cannot unify in the
  other direction. Errors are terminal: `Streaming` yields one `Err`
  then `None` forever (`decode.rs:405-407`), so the caller contract is
  any-`Err` → reconnect + `get_raw_mempool` re-baseline. Unknown
  discriminants surface as `BadNodeData`; the run-loop slice should
  decide whether newer-server values are ignorable (proto3 open enums)
  instead of errors. (`txid_from_display` is retained —
  `get_raw_mempool` consumes it too.)
- The mempool surface is now usable end to end, with lifecycle policy left
  to the future live owner:
  - `ChainClient::mempool_events()` replaces `mempool_change_stream()`,
    converting the generated `MempoolChangeMessage` into a typed
    `MempoolEvent {Added, Invalidated, Mined}(TxId)`; the generated type no
    longer crosses the module boundary. `auth_digest` is dropped — it only
    disambiguates pre-v5 malleable IDs, and every transaction this mint can
    see is v5+. `tx_hash` is `mined_id` in display byte order (pinned from
    the Zebra indexer server, `indexer/methods.rs`), reversed by the same
    idiom as `block_hash_from_display`.
  - `JsonRpc::raw` (stringly, zero callers) is replaced by
    `get_raw_transaction(network, TxId) -> Option<Transaction>` — mempool
    first then chain, parsed under boot-proven parameters. RPC -5 (no
    information) and a null result map to `Ok(None)`: a normal outcome when
    racing an `Invalidated`, not a transport failure.
  - `JsonRpc::get_raw_mempool() -> Vec<TxId>` is the reconnect snapshot —
    the server drops stalled consumers after its send timeout, so the owner
    re-baselines by diffing the snapshot against its pending set.

## 2026-09-01 — `z_gettreestate` returns the upstream `ChainState`

- Ironwood `finalState` decode no longer swallows errors, and the tree
  state is treated as mandatory (NU6.3 is active): a missing `ironwood`
  field or a present-but-undecodable value fails with `BadNodeData` /
  `BadCheckpoint` (the same paths as Sapling/Orchard) instead of silently
  seeding an empty tree — which would desynchronize every later Ironwood
  commitment position. A null or empty `finalState` still decodes to the
  empty frontier, which is the genuine value Zebra returns for the
  activation−1 height boot's origin checkpoint queries.
- Deleted the bespoke `CheckpointData` struct. `JsonRpc::get_checkpoint` is
  now `JsonRpc::chain_state_at(height) -> ChainState` — the upstream
  `zcash_client_backend::data_api::ChainState` value (chain.rs:506), which is
  the same type the run loop must hand `WalletWrite::put_blocks` as its
  `from_state` connection point.
- "No tree at this height yet" (pre-NU6.3 Ironwood: omitted field or empty
  `finalState`) normalizes to `Frontier::empty()`, not an `Option` — an
  absent tree and an empty tree are the same value to every consumer.
- `decode_tree` now returns the frontier directly: every consumer wants the
  frontier form (`ChainState` carries frontiers), so the
  `read_commitment_tree` → `to_frontier` conversion folds into the helper.
- Boot derives its `ChainCursor` `BlockMetadata` from the `ChainState`
  frontiers via `Frontier::tree_size()` (frontier.rs:324), mirroring what
  upstream `ScannedBlock::to_block_metadata` computes from `final_tree_size`;
  `seed_trees` consumes the frontiers directly. The mint's cursor currency
  stays the upstream continuity value while the trees are seeded from the
  same single RPC response.

- Sealed the `ChainClient` facade: the raw `client() -> &mut ZebraClient`
  passthrough is deleted. The generated gRPC type no longer crosses this
  module boundary; the public surface is exactly `chain_tip_change_stream`
  and `mempool_change_stream` (the same sealed-facade discipline as
  `CanonicalBlockSource`). Boot's split-brain check and the run loop's three
  stream-open/reopen sites migrated to the typed method.

## 2026-08-01 — Mempool change stream transport

- Added `ChainClient::mempool_change_stream()`, a typed wrapper around the
  Zebra indexer gRPC `MempoolChange` RPC. Returns a `Streaming<MempoolChangeMessage>`
  so callers can receive mempool `ADDED`, `INVALIDATED`, and `MINED` events.
- Added `ChainClient::chain_tip_change_stream()` for symmetry, replacing the
  raw `client().chain_tip_change(Empty {})` callsite shape in the run loop.
- Added `TransportError::Tonic` to carry gRPC status failures, classified as
  retryable when the status code is `UNAVAILABLE`.

## 2026-07-30 — Boot-proven consensus parameters

- Removed the global `NETWORK` constant. Network-sensitive block parsing now
  accepts the immutable consensus parameters established by boot, so this I/O
  module owns transport and parsing but does not choose a network.
- Added hash-only `getblockhash` retrieval for the boot identity check.
  [`zcash_primitives::block::Block::read`] deliberately rejects height 0, so
  genesis identity must not be coupled to full-block parsing.

## 2026-07-25 — Mainnet genesis hash constant

- Added `MAINNET_GENESIS_HASH`, a protocol-constant `BlockHash` in internal
  byte order, used by the boot-time network-identity verification.
- Added a round-trip test proving the constant matches the well-known display
  form `00040fe8...973dce08`.

## 2026-07-24 — Checked exact canonical tip

- Added `CanonicalTip`, a private-field height/hash pair parsed from one
  `getblockchaininfo` response.
- `CanonicalBlockSource` now exposes `exact_tip` rather than raw blockchain
  info, so passive Rebuild cannot ignore `bestblockhash`.
- Height-indexed `getblock` reads now reject a parsed block whose claimed
  height differs from the requested best-chain height.

## 2026-07-23 — Read-only canonical replay capability

- Added `CanonicalBlockSource`, a narrow facade exposing only chain-info and
  full-block reads. Canonical catch-up can no longer reach raw-transaction or
  submission methods through its RPC argument.
- Classified retryable read failures explicitly. Malformed/invalid node data,
  checkpoint failures, request construction, serde, and RPC-semantic errors
  remain fatal; only transport availability failures may retry.
