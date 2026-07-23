# Wallet changelog

Tracks design-relevant changes to `src/wallet.rs` and `src/wallet/trees.rs`.

## 2026-07-24 — Accepted height comes from scanner metadata

- `Wallet::apply_block` now derives the block height from the immutable
  `BlockOutput` metadata rather than a duplicate output field.

## 2026-07-23 — Canonical cache excludes operational reservations

- Removed the in-flight reservation set and its mutation/exclusion API from
  `Wallet`; replayable Wallet state is now only viewing inputs, balances,
  nullifier/note history, and the three commitment trees.
- Retained `NoteLocator` and exact note lookup as neutral transaction-planning
  identities. A future Live owner must supply exclusion sets explicitly.
- Clarified the existing failure boundary: balance installation is staged, but
  tree append/truncate mutates in place. Failure to restore all three pools is
  process-fatal; staged tree atomicity and fault evidence remain open.

## 2026-07-23 — Read-only ordinary Ironwood spend authentication

- Added a read-only nullifier lookup for ordinary unspent Ironwood notes.
- The Registry transition validator uses it before wallet mutation to prove
  that a transaction spent a positive-value Registry fee note.
- Validated Name Notes remain type-distinct and are intentionally absent from
  this ordinary-note index.

## 2026-07-23 — Restart-safe shielded spend detection

- Wallet application now resolves every raw Orchard, Sapling, and Ironwood
  transaction nullifier against its own rewindable indexes.
- Spend detection no longer depends on upstream's ephemeral `Nullifiers`
  cache, which has no public reconstruction API and could not survive restart
  or deterministic reorg rewind.

## 2026-07-23 — Atomic wallet block application

- A block's complete next `WalletBalance` is prepared on a clone before any
  accepted balance mutation.
- All three commitment streams append fallibly. Any append failure truncates
  every tree to the prior accepted checkpoint; the prepared balance is then
  discarded.
- The new balance becomes visible only after all tree appends succeed.
- Every accepted height is checkpointed in all three pools, including a pool
  with no commitments in that block. Rollback now rejects a missing target
  checkpoint instead of silently leaving one pool ahead of accepted state.

## 2026-07-23 — Exact planning and set reservation

- Added exact Orchard and ordinary Ironwood locator lookups; transaction
  assembly can consume a plan's reserved notes without rerunning selection or
  reparsing memos.
- Added all-or-nothing reservation for a set of note locators. If any member is
  already reserved, wallet reservation state remains unchanged.

## 2026-07-22 — Latest Ironwood anchor for output-only bundles

- Added a read-through accessor for the newest retained Ironwood checkpoint
  root using `ShardTree::root_at_checkpoint_depth_caching(Some(0))`.
- Output-only Ironwood bundles need a real root but do not need an exact-height
  witness. When no Ironwood commitments occur in the target block, the newest
  checkpoint root is still the current pool root; requiring a checkpoint with
  the target block's ID would incorrectly reject assembly.
- Kept the exact-height `ironwood_anchor(height)` API unchanged for bundles that
  spend Ironwood notes and therefore bind witnesses to a selected checkpoint.
- Added a unit case showing that a latest root is available even when an exact
  later checkpoint ID is absent. The test is written but was not executed in
  this pass.
