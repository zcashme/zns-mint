# Wallet changelog

## 2026-09-23 — A wallet is born complete (#158)

- `Wallet::new` takes the origin `ChainState` and the pre-birthday
  Sapling and Ironwood subtree-root batches, and seeds frontiers, roots,
  and the shard end-height maps in one construction. A conflicting root
  drops the whole local, so a partial root batch is never returned.
- `put_*_subtree_roots` stay three own bodies (no helper), each honest
  now: save the tree, run the batch, restore on `Err`; the end-height
  map fills only on full success. `clone_shard_tree` becomes `pub(super)`
  with a `TreeError` error. The mint no longer calls them; construction
  does.
## 2026-09-21 — `open_claim_for`: the wallet answers for its open claims (#116)

### Added

- `Wallet::open_claim_for(name, tip) -> Option<TxId>` on the read
  surface, beside `unspent_ironwood_note_by_nullifier`. It scans the
  retained sent transactions (`store_transactions_to_be_sent`'s records:
  raw tx, status, sent-output memos) for one still open — unmined and
  unexpired at `tip`, the same law as `unmined_spend_still_blocks` —
  whose memo decodes to a claim Name Note for `name`. The wallet is the
  only record of the mint's open commitments; the claim lane consults it
  to bridge the mempool lag while a sent claim cannot be seen in the
  Registry yet.

## 2026-09-20 — Checkpoint-seam fixes: Name Note marking and store-door ordering

### Fixed

- `append_block_commitments` marks accepted Name Note commitments with
  plain `Retention::Marked` — the retention the scanner assigns to notes it
  decrypts mid-block. The previous `Checkpoint { id: height, Marked }`
  upgrade collided with the scanner's own block-last checkpoint append at
  the same height: shardtree admits at most one checkpoint-retention append
  per id, so every accepted claim whose Name Note is not the block's last
  Ironwood commitment — the standard claim layout (Name Note, successor
  anchor, Treasury change) — FATALed at the wallet commit with
  `CommitmentTree(Insert(CheckpointOutOfOrder))`. `Marked` retains the
  witness without claiming the height's checkpoint slot;
  `ensure_block_checkpoint` remains the sole per-height checkpoint creator.
  Closes #110.
- `ensure_block_checkpoint` rejects out-of-order heights at its store door.
  Direct `add_checkpoint` bypasses the runtime ordering check that guards
  `ShardTree::append`, so a non-monotonic caller would insert time-inverted
  checkpoints silently. Heights arrive monotonically through
  `put_blocks_marked`'s continuity checks; the check turns that
  precondition into a loud invariant. Closes #112.

## 2026-09-21 — Preserve note witnesses across deep truncation

- `truncate_to_chain_state` merges supplied frontiers into copies of the
  existing trees, restores the target checkpoints, and truncates there.
  Retained note witnesses survive; older notes no longer cause refusal.
- Abandoned checkpoint records are removed before insertion so a full window
  cannot immediately prune the restored checkpoint. Frontier insertion also
  restores pruned boundaries whose checkpoint records still exist.
- All pools succeed before live trees, note records, or the reported tip change.
  When no applied blocks remain, the supplied state becomes the scan origin.
- The upstream truncation scenario is enabled again. The regression captures
  real frontiers and checks surviving witnesses against the target root,
  continued appends and pruning, a shard boundary, and atomic failure when
  the last pool rejects a conflicting frontier.

## 2026-09-21 — The origin checkpoint is the scan origin (issue #108)

### Changed

- `Wallet::new`'s comment rewords the per-pool origin checkpoint from
  "the reorg floor" to the scan origin.

## 2026-09-19 — The three transparent wallet fields go: the mint never receives, stores, or spends transparent money

### Changed

- The axiom, ruled and verified: the mint is paid shielded, spends
  shielded, and touches transparent exactly once per day — the vault
  sweep unshields to the project vault's transparent address. The
  treasury never receives transparent funds from users.
- `transparent_outputs`, `transparent_output_spends`, and
  `transparent_spends` are deleted. No writer could ever fire
  (upstream's `ScanningKeys` is structurally shielded-only, the
  receivers map is empty by policy, `put_received_transparent_utxo`
  has no caller in this tree or upstream's, and no flow spends
  transparent inputs) and no reader exists; the maps were empty in
  every run that has ever passed. The vault unshield consults none of
  them — it needs the recipient constant, the builder's transparent
  output support, and the shielded machinery.
- `put_received_transparent_utxo` now refuses with `FixedAccountsOnly`:
  the trait requires the method, the axiom forbids the store.
  `output_account`'s transparent arm answers `None` on the same
  principle. The `transparent-inputs` feature stays — it serves the
  unshield.
- The send-to-transparent scenarios stay connected and green: they
  exercise the unshield path and read none of the removed state.

## 2026-09-19 — The mint stops reserving inputs through the lock store

### Changed

- `assemble::prepare` no longer locks its selected inputs. The
  select → prove → record window is a single `&mut Wallet` borrow in a
  serial order loop, so the reservation guarded a window the borrow
  checker already seals; after recording, the unmined-spend records
  are the durable protection — a note stays unselectable until its
  transaction mines or expires either way. The random, discarded
  `LockOwner` and the FATAL lock-conflict panic die with the call:
  they were properties of a redundant reservation, not of the wallet.
- The wallet's `OutputLockStore` is now purely conformance surface for
  the upstream corpus (ten locking scenarios): production writes no
  lock at all. If the intake loop ever parallelizes, reservations
  must be designed for that shape — a queue around wallet access, or
  per-flow lock owners — not re-inherited from this protocol.
- `drop_applied_above` no longer cleans lock orphans: with no
  production lock writes there is nothing to orphan, and the corpus
  confirms no connected scenario locks a note and truncates past it.

## 2026-09-19 — Remove unused ZIP 318 anchor retention (#92)

### Removed

- `anchor_retention_interval` field, the `retains_anchor_checkpoint` gate, and
  the `ensure_retained` calls in `put_blocks`. The facility kept (or created)
  checkpoints at 144-block boundaries at or above NU6.3 outside the ordinary
  `MAX_CHECKPOINTS` pruning window; its only consumer is ZIP 318
  (Orchard→Ironwood) pool migration hosting, which this wallet cannot provide:
  it holds no Orchard funds, wires in no migration machinery, and its
  in-memory architecture cannot carry a multi-day pre-signed migration
  schedule. Every spend anchors near-tip inside the ordinary pruning window.
  Trees revert to the ordinary `MAX_CHECKPOINTS` window; no user-visible
  behavior changes.
- The `WalletRead::anchor_retention_interval` impl: the upstream trait
  default (`ZIP_318`) now answers, but the mismatch is inert — only
  migration machinery reads it, and none is invoked.
- Three upstream anchor-retention scenarios
  (`anchor_checkpoints_retained_across_deep_scan` ×2,
  `empty_boundary_blocks_are_checkpointed_and_retained`) together with the
  stale comment above them. The fixture keeps the
  `Option<AnchorRetentionInterval>` parameter the upstream `WalletTest`
  signature requires, and now asserts `None` like `gap_limits`.

## 2026-09-19 — `test_network` retired: conformance account injection is a cfg(test) fixture seam

### Changed

- The `#[cfg(test)] test_network: Option<LocalNetwork>` field is deleted.
  Its only semantic content was "this wallet belongs to the upstream
  conformance harness" — information the build mode already carries: the
  harness exists only in test builds, and
  `UnifiedSpendingKey::from_seed` is generic, so the fixture derives
  against `&wallet.network` (the stored `LocalNetwork` value was never
  needed).
- `WalletWrite::create_account` is now a compile-time seam: test builds
  install the upstream conformance fixture account through
  `wallet::testing::create_fixture_account`; production builds compile
  the branch out entirely (`cfg(test)` / `cfg(not(test))`), preserving
  the invariant that no seed can cross the wallet boundary in
  production: no code exists to receive it. The two cfg attributes are
  adjacent and complementary, so a mismatch is a compile error, not
  silent drift; and the flag no longer needs manual re-preservation
  across the fixture's `*self = Wallet::new(...)` replacement — the
  network travels with the wallet by construction.
- The injection body moves from an inherent method on `Wallet` into the
  `#[cfg(test)]` conformance fixture module (`wallet::testing`), as a
  free function beside the `Factory`, `Cache`, and `WalletTest`
  adapters: everything the suite expects that production does not have
  now lives in one cfg(test) module, and the production trait method
  states the production truth (`FixedAccountsOnly`) with no fixture
  knowledge.
- Closes #89.

## 2026-09-18 — Wallet security findings

### Fixed

- `rewind_to_chain_state`: empty `reset_account_birthdays` errors when every
  account would need its birthday lowered; acknowledged accounts may have
  birthday metadata lowered to `chain_state.height + 1`. Birthdays are stored
  per account.
- Truncation / reorg cleanup (`drop_applied_above`): notes created only on the
  abandoned branch are removed (no phantom pending balance); scanned-only
  spends mined above the surviving tip are cleared so the note is selectable
  again. Locally built spends keep their raw transaction and still block
  until expiry.
- `TxidNotRecognized` spends consult the retained raw transaction's expiry the
  same way as `NotInMainChain`, so inputs unlock after the tip passes expiry
  instead of staying blocked forever.
- `ExceedsPriorSendPercentile` includes notes at the percentile threshold
  (`>=`), and each percentile node in a Combine/Attempt tree evaluates its
  own percentile instead of sharing one pre-extracted threshold.
- Ordinary Orchard is compatibility-tree only: no received-note table. Docs
  no longer claim such notes are stored unspendable; `put_blocks` returns
  `UnexpectedOrchardReceive` if a scanned block surfaces one.
- `put_blocks_marked` and three-tree truncation mutate cloned commitment
  trees and replace the live trees only after the full batch succeeds, so a
  mid-flight tree error no longer leaves pools partially advanced.
  `replace_trees_from` (missing-checkpoint truncate fallback) builds and
  frontiers the three replacements off to the side before swapping them in.
- `store_name_note` returns `InvalidNameNote` unless the height is applied,
  the txid is already mined there, the Ironwood tree witnesses the position,
  and the note id / nullifier do not collide with a different note.

## 2026-09-18 — Upstream wallet conformance (issue #69)

### Fixed

- After scan, the known tip rises to the last applied block when nothing
  higher was set, so balances work without a separate tip update.
- Truncation and rewind: tip moves with the target when needed; missing
  checkpoints land on the supplied frontiers; rewind keeps a tip already
  ahead.
- Expired locks drop out of `get_locked_outputs`.
- Anchor-aligned checkpoints at or above NU6.3 stay retained; the test
  factory can set the interval; account setup keeps a preloaded frontier.
- Checkpoint history and transaction history read real wallet state.
- Note selection: lock-tier preference (unlocked vs locked, then age);
  `AllFunds(Everything)` errors if any note in the pools is unspendable.
- Dust (at or below the ZIP 317 marginal fee) is uneconomic — out of total
  and spendable, still usable as a grace input when selecting.
- Account metadata: no confirmation filter; balance-percentage and
  prior-send-percentile filters use note values and sent outputs.

### Connected

- Dev-only upstream test helpers, plus a small factory, block cache, and
  `WalletTest` adapter (one Treasury account for fixtures).
- Sapling scenarios as thin wrappers in `input.rs` / `write.rs` (scan,
  locks, send/spend, truncation/rewind, ZIP 315 external, anchor
  retention, metadata, and related).

### Disconnected

- Scenarios that need a hole, overlap, or out-of-order `put_blocks`
  (`spend_fails_on_locked_notes`, `birthday_in_anchor_shard`,
  `checkpoint_gaps`, `data_db_truncation`, `reorg_to_checkpoint`). This
  mint only applies the next height after the tip.
- Ordinary-Orchard funding
  (`propose_v5_payment_to_orchard_receiver_is_rejected`,
  `proposal_records_and_serializes_proposed_version`): ordinary Orchard is
  compatibility-tree only; receives are refused, not stored.
- `send_max_spendable_proposal_succeeds_when_unconfirmed_funds_present`:
  history length disagrees with a scanned unconfirmed receive we keep.
- `zip317_spend`: helper keeps dust out of total; body wants dust in.
- `zip_315_confirmations_internal`: Internal uses trusted remaining; the
  fixture expects untrusted unless marked `ExternalTrusted`. External
  arms stay connected.
- Huge preloaded-tree scenarios
  (`stabilized_note_spendable_after_deep_rewind`,
  `newly_discovered_notes_become_stabilized`): would hang the suite.

## 2026-09-18 — The wallet knows its network

- `Wallet` is generic: `Wallet<P: Parameters>` with a `network: P` field, matching
  the reference backends (`zcash_client_sqlite::WalletDb<C, P, CL, R>` stores its
  `params: P` the same way, consulted exactly where the trait surface hands no
  network to the backend — account-key derivation). `Wallet::new` takes the
  network as its third argument; boot passes `network.clone()` from
  `start_with_network`, and `Boot<P>.wallet` is `Wallet<P>`.
- The field is the single authority for network context inside the wallet; the
  free data-api functions keep taking caller-supplied `params` and must be
  passed the same network (one construction site, one params value).
- No default type parameter: every wallet-receiving app function is already
  generic over `P` (boot runs mainnet, testnet, and regtest), so a `MainNetwork`
  default would be unused sugar. One `pub fn network()` getter: the field would
  otherwise be write-only outside tests (`dead_code` under `-D warnings`), and the
  identity deserves a real read surface.
- No behavior change: method bodies are untouched; this is type-level only.
  The conformance harness's `#[cfg(test)] test_network` side-channel (#78)
  retires in its rebase onto this.

## 2026-09-18 — `n == 0` transparent reserve is a no-op

- `create_proposed_transactions` always calls
  `reserve_next_n_ephemeral_addresses`, including `n == 0` (no transparent
  change). The mint does not derive transparent receivers, so the stub
  used to return `Err(FixedAccountsOnly)` for every `n`. A successful
  `propose_transfer` then died as `vault sweep build failed
  error=DataSource(FixedAccountsOnly)`.
- Both `reserve_next_n_ephemeral_addresses` and
  `reserve_next_n_internal_addresses` now return `Ok(vec![])` when
  `n == 0`. `n > 0` stays `FixedAccountsOnly`.

## 2026-09-18 — Upstream corpus skip census

Never-connected scenarios surveyed for PR #78 (comment census). Execution
disconnects after a real run stay under the conformance chapter's
Disconnected list above; this records the design exclusions that were
never wired as wrappers.

### Never connected (by design)

- Transparent spending as inputs (`shield_transparent`,
  `send_max_to_tex_fails_without_transparent_inputs`,
  `transparent_note_locking`): transparent outputs are observations only.
- ZIP-320 multi-step / ephemeral transparent (six scenarios): factory
  rejects gap limits; no ephemeral address support.
- Account lifecycle (`account_deletion`,
  `account_deletion_with_internal_transfer`,
  `external_address_change_spends_detected_in_restore_from_seed`,
  `wallet_recovery_computes_fees`): `FixedAccountsOnly`.
- Ordinary-Orchard funding and pool-crossing family (sixteen scenarios,
  including `orchard_to_ironwood_*`, `canonical_crossing_*`,
  `fully_funded_*`, `multi_pool_checkpoint*`,
  `propose_v5_payment_to_orchard_receiver_is_rejected`,
  `proposal_records_and_serializes_proposed_version`): no ordinary-Orchard
  note table; receives are refused.
- `pczt` feature-gated scenarios (twelve): `pczt` not enabled in the
  mint's test graph.
- Non-contiguous scanning (`scan_cached_blocks_allows_blocks_out_of_order`,
  `scan_cached_blocks_detects_spends_out_of_order`,
  `oldest_note_is_selected_first`, `rewind_after_non_contiguous_scan`):
  `put_blocks` is sequential-only.
- Feature-inverse (`send_max_delivers_via_sapling_when_orchard_is_unavailable`,
  `send_max_to_orchard_only_ua_fails_without_orchard`): we build with
  `orchard`.
- Upstream dead / property (`invalid_chain_cache_disconnected`,
  `check_note_locking_model`): not a live corpus entry here.

### Retry later

- `stabilized_note_spendable_after_deep_rewind`,
  `newly_discovered_notes_become_stabilized`: retried after the preloaded
  frontier is kept on account inject; still hang (>2 min, no finish) on the
  ~131k-leaf initial tree / 65 536-output note block before any assertion.
  `newly_discovered_*` would also need a second account (`FixedAccountsOnly`).
  Stay out of the suite.

## 2026-09-16 — `Wallet::new` seeds pre-birthday shard roots

- New `PreBirthdaySubtreeRoots { sapling, ironwood }`. Orchard omitted:
  the mint has no Orchard spend path.
- `Wallet::new` takes that as a third argument. After the origin frontier
  (rightmost partial shard), it calls `put_sapling_subtree_roots` and
  `put_ironwood_subtree_roots` so post-birthday witnesses can walk
  completed pre-birthday shards without their leaves.
- Boot step 3b fetches the roots. Empty vectors are legitimate (regtest)
  and match the previous constructor.

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
## 2026-08-28 — Wallet file boundaries match their identities

- `assembly.rs` no longer hosts wallet queries. It holds only the V6 Ironwood
  transaction finalizer (`assemble_v6_transaction`) — the one lane upstream's
  `Builder` cannot serve — and its module doc now claims exactly that.
- Note reads (`unspent_ironwood_notes`, `unspent_ironwood_note`,
  `unspent_ironwood_note_by_rho`, `unspent_ironwood_nullifiers`) moved to
  `wallet/read.rs` as "reads beyond the upstream trait surface."
- Tree reads (`ironwood_witness`, `ironwood_anchor`) moved to
  `wallet/trees.rs`, beside the `WalletCommitmentTrees` impl they wrap.
- `store_name_note` moved to `wallet/write.rs` as the ZNS ingestion lane —
  a write, sibling of `put_blocks`.
- No signature, visibility, or behavior changes.

## 2026-09-17 — `put_blocks_marked`: Name Notes stay witnessable (issue #55)

- `WalletWrite::put_blocks` is now a delegate; the body lives in
  `put_blocks_marked(from_state, blocks, marks)`. `marks` upgrades
  matched commitments to `Checkpoint { Marked }` at append — the same
  retention the scanner assigns to notes it decrypts.
- Without marks, Name Note commitments enter Ephemeral (the scanner
  cannot decrypt ZNS-domain outputs), prune with the checkpoints, and
  a dormant name's update FATALs on a missing witness. Only accepted
  candidates are marked — foreign ZNS outputs stay Ephemeral, so tree
  retention stays bounded.

## 2026-09-22 — The wallet owns two chain positions

### Fixed

- `rewind_to_chain_state` floors on the trees' own retention — the
  oldest retained checkpoint, read from one store. All three trees
  retain identical checkpoint sets by the commit discipline that
  mutates them together (`ensure_block_checkpoint` checkpoints all
  three at the same height; every truncation runs through the
  all-three-or-nothing helpers), so the floor is one read, not three
  probes plus an alignment assertion — `CheckpointMisalignment` is
  gone. This replaces `zebra_tip − window` arithmetic, which — whenever
  the known chain ran ahead of the applied position, every catch-up's
  normal state — landed the floor above the wallet's own height and
  returned `Ok` having rewound nothing. Upstream rewinds by height
  alone (its scenarios pass zero-hash chain states); hash validation
  stays in `truncate_to_chain_state`, the tool that receives real
  frontiers.
- Truncation below the trees' retention window refuses loudly
  (`TruncationTargetUnavailable`): the checkpoint at the target is
  pruned and the request cannot be honored in memory. Flooring the
  request instead would keep the orphaned blocks between target and
  floor applied. For an always-on wallet with no persistence, restart
  is the recovery — boot rescans from the birthday.
- `get_wallet_summary` falls back to the applied position when no tip
  has been supplied — a scan-only wallet still reports balances. When a
  tip IS supplied, confirmations count against it: upstream's
  conformance suite pins that contract, and this service never pushes
  the node's tip, so in production knowledge tracks the applied
  position.
- `Wallet::tip()` — the wallet's applied position:
  `blocks.last_key_value().unwrap_or(seed)`, always defined. Lock
  liveness, lock listing, spend targets, balance expiry, and now
  balance summaries read it; their `None`-tip fallback arms and the
  lock readers' mutual disagreement die with it.
- Chain knowledge (`zebra_tip`) moves only through `update_chain_tip`,
  the one writer: scanning advances it to the applied tip, adopting a
  chain state sets it to the adopted height. Truncation no longer clamps
  it, scanning no longer ratchets it behind the writer's back, and rewind
  never touches it — `chain_height` survives rewinds per the upstream
  scan-queue contract. A far-ahead tip no longer defeats rewind.
- `max_applied_height` is gone. The wallet holds one position — `tip`,
  the fully applied block in full — and upstream's Option-shaped answers
  are composed at the trait boundary from it and the applied prefix. A
  second, height-only view of the same concept invited the wallet to
  reason about itself from partial facts.
- `Wallet::sync_status(network_tip)` and
  `Wallet::expired_unmined_at(txid, network_tip)` — the sync comparison
  and the expiry judgment, offered to callers that hold both tips. The
  node's tip is an argument on each: compared and dropped, never
  stored; decisions still read `tip()` alone. Metrics are the intended
  consumer of the former, expiry reconciliation of the latter.
- The wallet never self-assesses sync. The summary's scan progress is
  always complete relative to its own position (scanning is one linear
  prefix; the tip is its end — a theorem, not a tracked state), and
  `suggest_scan_ranges` never suggests a range: naming a gap would
  require holding the network tip, which the wallet declines to do.
  Whether the wallet trails the network is a comparison only the run
  loop makes — it holds both tips.
