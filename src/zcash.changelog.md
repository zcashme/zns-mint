# Zcash I/O changelog

## 2026-09-01 — `z_gettreestate` returns the upstream `ChainState`

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
