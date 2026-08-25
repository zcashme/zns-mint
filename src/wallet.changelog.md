# Wallet changelog

## 2026-09-01 — Local named tree depths; `seed_trees` consumes `ChainState`

- Depth and shard height are no longer spelled via pool-crate or
  backend-crate constants. The wallet owns four private constants —
  `SAPLING_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32`,
  `ORCHARD_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32` (Ironwood shares the
  Orchard shape), and the matching shard heights
  `SAPLING_SHARD_HEIGHT`/`ORCHARD_SHARD_HEIGHT: u8 = 16` — and every
  `ShardTree` parameter (storage fields in `wallet.rs`, trait callback bounds
  in `trees.rs`) names them. The only pool-crate paths left are the
  unavoidable value types (`sapling::Node`,
  `orchard::tree::MerkleHashOrchard`).
- Correctness does not trust the literals: the `WalletCommitmentTrees` impl
  signatures must normalize to the upstream trait's declared types, and every
  frontier meets a tree through `insert_frontier`'s `Frontier<H, DEPTH>`
  parameter — a wrong number is a compile error, not a silent divergence.
  This replaces the deleted `const _: ()` assertion (depth == 2 × shard
  height), which existed only because depth was spelled in several unrelated
  ways (including bare `32` in `seed_trees`).
- `Wallet::seed_trees` is deleted; its work is folded into `Wallet::new`,
  which now takes `(ufvks, &ChainState)` and returns
  `Result<Self, TreeError>`. Every wallet is born from the verified Zebra
  checkpoint, and an unseeded wallet — whose trees would witness against a
  missing pre-checkpoint history, silently invalidating every later witness
  — is no longer a representable state. Folding also makes construction
  atomic: a mid-seed failure drops the partially-built `Self` instead of
  leaving a mutated wallet in the caller's hands. Boot fetches the
  checkpoint first and constructs the wallet in one step (`boot.rs`); the
  `BlockMetadata` derivation from the frontiers is unchanged.
- The chain-tip field is renamed `last_zebra_tip` → `zebra_tip`: it is the
  tip as last supplied by `WalletWrite::update_chain_tip`, and the name
  should say what it is, not when it was set.

## 2026-08-22 — Upstream trait layer completed

- Implemented `WalletRead` (`wallet/read.rs`), `InputSource`
  (`wallet/input.rs`), and `WalletWrite` + `OutputLockStore`
  (`wallet/write.rs`) against the pinned `zcash_client_backend`
  0.24.0-rc.7 trait surface. Every feature-gated method (our features are
  `orchard` + `transparent-inputs`) is overridden with an honest
  non-panicking value; inherited defaults panic inside the TEE.
- The unit error `FixedAccountsOnly` was replaced by the `WalletError` enum
  (`FixedAccountsOnly`, `AccountUnknown(AccountId)`, `ChainDiscontinuity`,
  `TruncationTargetUnavailable`, `CommitmentTree`, `Balance`): the completed
  write surface has real failure modes beyond fixed-account refusal, and one
  unit type can no longer express them. `AccountUnknown(account)` separates
  "named a nonexistent account" from "this wallet categorically cannot",
  following the upstream in-memory backend's error precedent
  (`zcash_client_memory` `error.rs:32`). The single shared type is forced by
  the upstream `WalletWrite` supertrait, which pins `OutputLockStore::Error`
  to `WalletRead::Error` (`data_api.rs:3540`).
- Added exactly one wallet field: `trusted_transactions: BTreeSet<TxId>`,
  required by `WalletWrite::set_tx_trust` and consulted by the shared
  trusted/untrusted confirmation classifier in `wallet/input.rs` ([ZIP 315]).
  Balance reporting (`get_wallet_summary`) and input selection reuse that
  one classifier, so they cannot disagree.
- `put_blocks` is the sole note-lifecycle writer. It validates sequential
  heights and `from_state` continuity (height and recorded block hash)
  before any mutation, appends commitments with the scanner-provided
  retention markers, backfills a checkpoint at every accepted height in all
  three pools (the Orchard tree included, as compatibility state), and only
  then applies the infallible tables. Spends are resolved from the block's
  full `nullifier_map` so a note created and spent within one batch is
  still marked spent (the scanner's prior-nullifier set cannot see
  same-batch spends). Tree failure leaves tables untouched; truncation
  repairs trees that are ahead.
- `store_decrypted_tx` stores the raw transaction, memos, and status only;
  it never creates notes, because a `DecryptedOutput` carries no nullifier
  or commitment position. `store_transactions_to_be_sent` records spends
  from the raw bundle nullifiers and transparent inputs and releases the
  lock on every output recorded as spent, as the upstream contract
  requires.
- Truncation follows the upstream sqlite/memory policy: un-mine
  transactions above the truncation point, retain notes/memos/sent outputs
  (unrecoverable data; un-mined notes are excluded from spendability by the
  status-based eligibility rules), drop block records, and truncate all
  three trees to the largest common retained checkpoint. `rewind_to_chain_state`
  never lowers the fixed birthdays; it returns `RewindBeyondBirthdays` when
  a reset was requested below the birthday floor.
- Selection admits only exact-`NoteId`, unspent, lock-admitted, mined
  notes with a retained spending key scope; there is deliberately no dust
  threshold (upstream in-memory wallets apply a 5000-zat heuristic — the
  mint spends exactly what it plans). `select_spendable_notes` accumulates
  oldest-first by commitment position in the caller's pool order,
  `AllFunds` selects everything, and ordinary Orchard is never selected.
  `max_shielding_input_height` is always `None`: the mint never shields
  transparent funds, so no shielded note of this wallet descends from
  transparent inputs.
- Transparent observations (`put_received_transparent_utxo`, scanned
  `WalletTx` outputs) are recorded but never surfaced as spendable inputs
  or balances — the outbound-only policy — and `get_orchard_nullifiers`
  returns empty because the ordinary Orchard tree is compatibility state.

[ZIP 315]: https://zips.z.cash/zip-0315

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
- Split the upstream trait boundary into the requested private modules:
  `wallet/read.rs` (`WalletRead`), `wallet/input.rs` (`InputSource`),
  `wallet/write.rs` (`OutputLockStore` and `WalletWrite`), and
  `wallet/trees.rs` (`WalletCommitmentTrees`). The tree implementation is a
  move of the direct adapter, not a new wrapper layer.
- Added only the concrete return value that upstream `WalletRead::Account`
  requires: a private, ephemeral `FixedAccount` in `wallet/read.rs`. It is
  created from an existing account-0/account-1 UFVK entry, retains no seed or
  spending key, and is not wallet storage. Its fixed birthday is the mint's
  deployment scan floor, `3_400_000`.
- The ordinary Orchard tree is retained solely as a compatibility commitment
  tree: it receives every scanned Orchard commitment and checkpoint, but the
  mint has no ordinary-Orchard received-note, nullifier, or input-selection
  state. Sapling and Ironwood are the only owned shielded input lanes.
- Transparent support is outbound-only. The mint may construct a payment to an
  external transparent recipient, but neither fixed account owns, derives, or
  reserves a transparent receiver. Feature-gated transparent wallet queries
  must therefore return empty results rather than inherit upstream panic
  defaults.

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
