# Zcash I/O changelog

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
