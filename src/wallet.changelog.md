# Wallet changelog

## 2026-08-22 — Upstream-shaped in-memory WalletDb storage

- Replaced the stored `MintAccount` registry with the fixed
  `BTreeMap<AccountId, UnifiedFullViewingKey>` requested by the mint. Account
  birthday and ZIP-32 derivation facts remain application identity, not wallet
  table columns.
- Replaced the bespoke `ShardTrees`, `SubtreeRoot`, and local tree-alias module
  with the three direct upstream `ShardTree<MemoryShardStore<...>>` values and the same
  `Address -> BlockHeight` subtree-end-height maps used by
  `zcash_client_memory::MemoryWalletDb`.
- The database now has only upstream transaction, scanned-output, memo,
  nullifier, sent-output, transparent-output, lock, and block-metadata values
  in standard B-tree indexes. There is no scan queue, custom note identity,
  custom nullifier enum, block-delta log, or mutable account registry.
- `last_zebra_tip` is retained because upstream `WalletRead::chain_height`
  explicitly reports the height supplied to `WalletWrite::update_chain_tip`;
  it is not a scan queue or a second chain authority.
- Boot extracts verified Zebra frontiers and passes them to `Wallet::seed_trees`;
  wallet storage no longer depends on the chain-client `CheckpointData` type.

## 2026-08-22 — Remove the bespoke wallet API before adopting the upstream one

- Deleted the local `WalletRead` and `WalletWrite` traits and their bespoke
  implementations. The replacement boundary is the current
  `zcash_client_backend` data API; it will be introduced only after its table
  and trait contracts have been read against the mint's exact dependency.
- Deleted the position-based `NoteRef`, cross-pool `Nullifier` enum,
  `NoteEntry`, `BlockDelta`, `tracked_nullifiers`, and `history`. A commitment
  position is witness data, not the identity of a transaction output, and the
  hand-maintained undo journal is not carried into the upstream-shaped store.
- Retained only the boot-installed UFVK map and Sapling/Ironwood tree seeding.
  The next refactor slice will replace the removed state using upstream
  `NoteId`, `OutputRef`, and the current `WalletRead`, `InputSource`,
  `OutputLockStore`, `WalletWrite`, and `WalletCommitmentTrees` contracts.
- This deliberately leaves the worktree architecturally incomplete; no Cargo
  command was run and compilation is not a goal of this deletion pass.

## 2026-08-15 — Orchard state deleted; Ironwood is the only Orchard-family lane

- The wallet holds no Orchard state of any kind: `NoteLocator::Orchard`,
  `ReceivedOrchardNote`/`SpentOrchardNote`, the Orchard unspent/nullifier
  indexes, the Orchard `ShardTree` (and its seeding, appends, anchors,
  witnesses), and the Orchard accessors are deleted. Checkpoint and reorg
  atomicity (`checkpoint_all`, `truncate_to_checkpoint`) now covers exactly
  the Sapling and Ironwood pools with the same preflight discipline.
- Rationale: NU6.3 disables Orchard cross-address transfers, so no user can
  send the wallet an Orchard note, the mint never builds Orchard outputs, and
  the mint is undeployed (no legacy balance). An Orchard anchor or witness can
  never be needed. Ironwood — the mint's only Orchard-family pool — keeps
  using the Orchard-family note, nullifier, and `MerkleHashOrchard` types.
- `treasury_excluded_rhos` projects `NoteLocator::Ironwood` entries for the
  Treasury account instead of Orchard locators.
- Deleted the dead Orchard selector `wallet::selection::select_funds`;
  `select_sapling_funds` is retained untouched.
- The upstream scanner still trial-decrypts Orchard outputs with the
  accounts' Orchard-family keys (excluding them requires naming
  `zcash_client_backend`'s `pub(crate)` Ironwood domain types); no Orchard
  result is surfaced or stored. The Orchard tree in boot's
  `z_gettreestate` checkpoint is still parsed because upstream
  `BlockMetadata` continuity carries its size.

## 2026-07-28 — Exact locator validation after reorg

- Added a read-only `contains_unspent_locator` boundary across Orchard,
  Sapling, and ordinary Ironwood notes. Live reorg handling uses it to discard
  an unconfirmed submission only when its exact planned funding input no
  longer exists on the rebuilt canonical branch.

Tracks design-relevant changes to `src/wallet.rs` and `src/wallet/trees.rs`.

## 2026-07-24 — Preflighted canonical rewind

- Replaced the orchestrator's separate mutable balance/tree access with
  `Wallet::rewind_to_height`.
- Rewind preflights the exact checkpoint in Sapling, Orchard, and Ironwood
  before mutating any pool, then truncates the fallible trees before the
  infallible balance and nullifier history.
- A missing retained checkpoint now fails before any Wallet mutation.
- The retention count is explicitly current plus 100 predecessors, and every
  accepted `checkpoint_all` call verifies that all three exact checkpoint IDs
  exist. Boundary tests cover each missing pool and the retention floor.

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
