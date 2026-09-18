# Wallet changelog

## 2026-09-18 — Final corpus inventory: five connected, two blocked (issue #69)

- Connected the last five connectable upstream scenarios as thin wrappers:
  `birthday_in_anchor_shard`, `checkpoint_gaps`, `rewind_to_chain_state_deep`
  (`wallet/write.rs`), and `propose_v5_payment_to_orchard_receiver_is_rejected` plus
  `proposal_records_and_serializes_proposed_version` (`wallet/input.rs`, both `cfg(orchard)`
  and enabled in our build).
- Observed results: `checkpoint_gaps` and the two proposal scenarios stop at the shared
  missing-summary gate. `birthday_in_anchor_shard` stops at upstream's scan helper
  (`testing.rs:997`): its `with_initial_chain_state` preload (subtree roots and a seeded
  frontier written before account creation) is discarded by the factory account hook's
  documented whole-wallet replacement, and the first scan fails the continuity contract
  loudly — the pre-documented injection limitation, now visible in red.
  `rewind_to_chain_state_deep` fails at its own first assertion, like its shallow sibling.
- `stabilized_note_spendable_after_deep_rewind` and
  `newly_discovered_notes_become_stabilized` are recorded as BLOCKED, not connected. Both
  preload a ~131k-leaf tree via `with_initial_chain_state`; the injection replacement
  discards it, and the scenarios then run unboundedly (verified: no completion in 150s
  against an otherwise 1.8s suite). Connecting them would hang the suite rather than
  document anything, so they stay out, consistent with the handoff's rule to record such
  scenarios as blocked pending factory extension.
- The upstream inventory is now complete. Counts: 52 connected / 3 passing /
  39 failing at the shared missing-summary gate / 4 failing at target assertions
  (the truncation/rewind findings) / 1 adapter gap (`reorg_to_checkpoint`) /
  3 failing at the retention fixture boundary / 1 failing at the injection-replacement
  boundary / 1 failing at its own rewind assertion; plus 2 blocked and the documented
  exclusions (ordinary-Orchard funding family, transparent/TEX, ZIP-320 multi-step,
  out-of-order scans, account lifecycle, pczt-gated, proptest model, upstream dead code).
  Library run: 54 passed, 50 failed, 0 ignored. No pre-existing test regressed.

## 2026-09-18 — Anchor-retention scenarios connected at the retention boundary (issue #69)

- Connected the two NU6.3-network Ironwood tree scenarios as thin wrappers, with the
  interval arguments mirroring upstream's own SQLite wrappers exactly:
  `anchor_checkpoints_retained_across_deep_scan` with both `ZIP_318` and
  `custom(12)`, and `empty_boundary_blocks_are_checkpointed_and_retained` with
  `custom(7)`.
- All three stop at the factory's explicit
  `"custom retention is not supported"` assertion (`wallet.rs` in the testing
  module): the wallet's tree retention is fixed at `MAX_CHECKPOINTS = 100`, and the
  factory was designed to reject non-default retention loudly rather than ignore it.
  No extension was added: the durable-checkpoint seam itself already exists in the
  scan path (`Marking::Marked` retention flowing through `append_block_commitments`,
  used in production for name-note witnesses, and the `anchor_retention_interval()`
  trait default of ZIP_318), so what these scenarios require is a consumer for a
  configured interval — a wallet capability decision that stays out of this branch.
  The failure is therefore an honest fixture boundary, not a missing seam.
- These are the corpus's direct Ironwood-tree assertions (`with_ironwood_tree_mut`):
  `empty_boundary_blocks_are_checkpointed_and_retained` pins exactly the per-height
  all-three-trees checkpointing property this wallet implements (blocks with no
  commitments in any pool must still be checkpointed), and is the first candidate to
  revisit if configurable anchor retention is ever adopted.
- Counts: 47 connected / 3 passing / 41 failing before target assertions /
  4 failing at target assertions / 1 adapter gap / 3 failing at the documented
  retention fixture boundary. Library run: 54 passed, 45 failed, 0 ignored
  (44 upstream at the shared gate or their own assertions, 3 at the retention
  boundary, and the local `get_locked_outputs` diagnostic, counted separately).
  No pre-existing test regressed.

## 2026-09-18 — Large-batch connect: truncation/rewind and send/spend corpus (issue #69)

- Connected 29 more unchanged upstream Sapling scenarios as thin wrappers (16 in
  `wallet/write.rs`, 13 in `wallet/input.rs`), bringing the corpus to 44 connected.
  Applicability was checked per body before wiring: the two `cfg(not(orchard))`
  send-max scenarios do not exist in our build (orchard is enabled), the
  `pczt`-gated pair is excluded, and the multi-step spend-everything trio requires
  `.with_gap_limits` (which the factory rejects) plus ZIP-320 ephemeral transparent
  addresses — excluded by design. (An earlier note here claimed the crossing corpus
  has no Ironwood-lane scenarios; that was inaccurate — see the corrected Ironwood
  inventory below: the corpus's Ironwood scenarios exist but are premised on
  ordinary-Orchard ownership or configurable anchor retention.)
- Results: 3 passing, 38 failing at the shared missing-summary gate, 4 failing at
  real upstream assertions, 1 failing at a documented adapter gap.
- Findings and applicability notes:
  - Ironwood coverage in the corpus (corrected from an earlier claim): the corpus DOES
    contain Ironwood conformance scenarios. `empty_boundary_blocks_are_checkpointed_and_retained`
    and `anchor_checkpoints_retained_across_deep_scan` run on NU6.3-active test networks and
    assert Ironwood tree checkpoint retention directly; `orchard_to_ironwood_*`, the five
    `canonical_crossing_*` scenarios, and `self_migration_keeps_spending_orchard` exercise
    Ironwood-routed payments, ZIP 318 crossings, and migration. None connect today: the tree-
    checkpoint pair requires `.with_anchor_retention_interval` (the factory rejects it; wallet
    retention is fixed at `MAX_CHECKPOINTS = 100`) plus the funding gate; the crossing family
    funds ordinary-Orchard notes, which this wallet deliberately does not own; the `pczt`
    pair is feature-gated. The empty-boundary scenario pins exactly this wallet's per-height
    all-three-trees checkpointing property, and is the first candidate if configurable anchor
    retention ever becomes supported.
  - `truncate_to_chain_state_below_birthday`: our wallet rejects truncation to the
    birthday−1 prior chain state with `TruncationTargetUnavailable`. Upstream's own
    comment names this exact rejection as the buggy behavior they fixed. Our root
    cause is two-fold: no applied block exists at birthday−1, and after
    `MAX_CHECKPOINTS` (100) further blocks the origin checkpoint is evicted, so
    `common_truncation_height`'s boot-floor fallback is gone. Mint context: `main.rs`
    deliberately panics on forks crossing the mint birthday, so the refusal is mint
    policy — but it is a divergence from the upstream wallet contract and is recorded
    as such.
  - `truncate_to_chain_state_above_scanned`: after `truncate_to_chain_state` to a
    higher target, upstream expects `chain_height()` to equal the target (their
    reference backends trim their scan queue, re-anchoring the tip). Ours keeps the
    externally-supplied `zebra_tip` untouched — truncation is pure state rewind and
    the caller owns the tip, by design. Same two-truths divergence as the funding
    gate, surfacing at the truncation seam.
  - `truncate_to_chain_state` and `rewind_to_chain_state_shallow`: both assert
    `chain_height()` is set after scan-only operation (no `update_chain_tip`). Same
    root cause as the funding gate; these scenarios simply reach it without funding.
  - `reorg_to_checkpoint`: requires `WalletTest::get_checkpoint_history`, which the
    adapter deliberately `unimplemented!()`s. An adapter gap to close by deriving the
    history from the real commitment-tree checkpoints — not a wallet finding.
- Library run: 54 passed, 42 failed, 0 ignored. The 42 are: 38 upstream at the shared
  gate, 4 upstream at the findings above, and the local `get_locked_outputs`
  diagnostic (expected red, counted separately). Upstream counts: 44 connected /
  3 passing / 38 failing before target assertions / 4 failing at target assertions /
  1 adapter gap. No pre-existing test regressed.

## 2026-09-18 — valid_chain_states connected and passing (issue #69)

- Connect upstream's `valid_chain_states` as a thin wrapper in `wallet/write.rs`.
- Third upstream scenario to pass, and the first passing body that exercises
  scanning: it explicitly asserts `chain_height() == Ok(None)` on a wallet not
  yet notified of a tip (our design, asserted as correct by upstream), then
  scans two contiguous blocks through the real `put_blocks` continuity path
  with no balance lookups. The strict sequential contract holds unchanged.
- Surveyed the rest of the `pool.rs` corpus for other scenarios that avoid the
  funding helper: none are currently runnable. `data_db_truncation` opens by
  asserting the summary is `None` but then requires post-scan balances;
  `send_max_fee_overflow_is_an_error`, `receive_two_notes_with_same_value`,
  `scan_full_block_detects_outputs`, and the truncation/rewind family all
  fund via `add_a_single_note_checking_balance` or assert balances after
  scanning, so they are gated at the shared missing-summary precondition.
- `invalid_chain_cache_disconnected` is excluded: upstream marks it
  `#[allow(dead_code)]` with "FIXME: This requires fixes to the test
  framework."
- Counts: 16 connected / 3 passing / 13 failing before target assertions /
  0 at target assertions (plus the local `get_locked_outputs` diagnostic,
  counted separately). Library run: 54 passed, 14 failed, 0 ignored.

## 2026-09-18 — Divergence observed: get_locked_outputs lists lapsed locks (issue #69)

- Promoted the source-predicted `get_locked_outputs` divergence from inferred to
  observed with a local diagnostic (`get_locked_outputs_drops_expired_locks` in
  `wallet/write.rs`), deliberately separate from the upstream corpus: it funds
  through the raw generate+scan path, calls the production
  `WalletWrite::update_chain_tip` exactly as the mint's run loop does, and then
  reads the two consumers of the lock map at the same target height.
- Observed behavior: a lock whose expiry equals the current tip (lapsed, since
  balance evaluates locks against `target_height = tip + 1`) is simultaneously
  — excluded from balance: the note counts as fully spendable and
    `locked_value` is zero (assertions passed), and
  — present in `get_locked_outputs`, because that method reads the raw lock
    map without an expiry filter.
  Upstream's `note_locking_height_boundary` and `lock_expiry_restores_spendability`
  pin the opposite listing contract: a passed lock must be absent. The
  diagnostic pins that contract too and stays red until the divergence is fixed.
- This is the first target-assertion-level finding of the conformance effort, and
  it was reachable without any tip fixture because the diagnostic supplies the
  application-style tip notification itself. No production code was changed; the
  fix (filter lapsed locks in `get_locked_outputs`, matching the liveness rule
  already used by `lock_admits` and `add_note_to_balance`) belongs on a separate
  branch, where this diagnostic and the upstream lock scenarios become its
  regression harness.
- Library run: 53 passed, 14 failed (13 upstream scenarios at the shared
  missing-summary precondition, plus this diagnostic at its target assertion),
  0 ignored. Upstream counts unchanged: 15 connected / 2 passing / 13 failing
  before target assertions / 0 at target assertions; the diagnostic is not an
  upstream scenario and is counted separately.

## 2026-09-18 — Proposal-lock lifecycle batch connected (issue #69)

- Connect three more unchanged upstream Sapling scenarios as thin wrappers:
  `proposal_level_note_locking` (`wallet/write.rs`), and
  `locked_proposal_proto_roundtrip` plus
  `single_note_selection_honors_lock_tier_preference` (`wallet/input.rs`).
- What they target, per the bodies read from the resolved 0.24.0 source:
  - `proposal_level_note_locking`: proposal-acquired locks (`LockRequest`),
    execution releasing spent-input locks, `LockFailure` on unknown outputs,
    and the deliberately pinned permissiveness of locking an already-spent
    note (upstream documents it as a visible contract choice).
  - `locked_proposal_proto_roundtrip`: serialized-proposal decode must
    re-fetch its inputs through `InputSource::get_spendable_note` without
    filtering the proposal's own locked inputs — the seam is
    `zcash_client_backend` proto decode at `proto.rs:927`.
  - `single_note_selection_honors_lock_tier_preference`:
    `PreferUnlocked`/`PreferLocked`/`Exclude` tier ordering in selection; on
    our wallet it runs through the trait's default `select_single_spendable_note`
    over our real `select_spendable_notes`, so no adapter work was required.
- All three fail at the shared funding gate (`data_api/testing.rs:1560`,
  `with_account_balance` unwrapping a `None` summary — the scenarios never
  call `update_chain_tip`). Verified individually: same panic location as the
  other ten. No adapter gaps were hit: none of the three bodies reach the
  `unimplemented!()` `WalletTest` methods, and upstream's
  `TestState::create_proposed_transactions` is a thin wrapper over the
  production function with mock provers, so execution-time inspection is not
  required.
- Library run: 53 passed, 13 failed, 0 ignored. Counts: 15 connected /
  2 passing / 13 failing before target assertions / 0 at target assertions.
  Out-of-order scan scenarios, transparent locking, and the proptest-based
  `check_note_locking_model` remain excluded/unwired, unchanged.

## 2026-09-18 — Locking batch connected without a tip fixture (issue #69)

- Connect four more unchanged upstream Sapling scenarios as thin wrappers:
  `lock_conflict_and_batch_atomicity`, `lock_expiry_restores_spendability`, and
  `unlock_proposal_inputs_releases_locks` in `wallet/write.rs`'s tests module, and
  `spend_policy_locked_input_policy_reaches_selection` in `wallet/input.rs`'s tests
  module. Upstream names preserved; no test bodies copied; corpus is the resolved
  `zcash_client_backend` 0.24.0.
- Twelve upstream scenarios are now connected. Two pass (unknown-key, no-blocks); the
  other ten — the six from the initial batch plus these four — fail at upstream's first
  balance lookup (`data_api/testing.rs:1560` in 0.24.0, `with_account_balance` unwrapping
  a `None` wallet summary) before reaching any of their intended assertions. The four new
  failures were verified to panic at that same location: the scenarios generate and scan
  blocks without ever calling `update_chain_tip`, while `get_wallet_summary` returns
  `Ok(None)` until a tip is supplied through `WalletWrite::update_chain_tip` — which is
  both the documented trait contract and the sequence the mint's run loop performs
  (`main.rs` updates the tip from Zebra before applying blocks). The reference SQLite
  backend instead derives its tip from scan bookkeeping, which is why the corpus passes
  unchanged there.
- No tip fixture was introduced: no production edit, no adapter-side summary
  fabrication, no cache↔wallet state coupling, and no `should_panic` relabeling. The
  precondition is documented rather than adapted around. All ten failures are one shared
  precondition, not ten wallet bugs; none of the lock behaviors the new four target
  (batch preflight atomicity, inclusive expiry at `target_height`, owner-scoped
  acquire/release, `LockedInputPolicy` reaching note selection) have been reached, and
  these tests must not be reported as lock coverage.
- Full library run: 53 passed, 10 failed, 0 ignored. No pre-existing test regressed.
- Counts: 12 connected / 2 passing / 10 failing before target assertions / 0 failing at
  target assertions. Out-of-order scan scenarios and transparent spending remain
  excluded from the effort as a whole, unchanged from the initial batch.

## 2026-09-18 — Initial upstream conformance scenarios (issue #69)

- Enable `zcash_client_backend/test-dependencies` only through the dev dependency.
  The local resolver selects 0.24.0; the manifest's 0.24.0-rc.7 requirement is
  not an exact pin. Both existing patched cryptography tags support the feature.
- Add an inline `wallet::testing` factory, compact-block cache and minimal
  `WalletTest` adapter. Upstream account creation is supported only on wallets
  explicitly created by this test factory: inject one Treasury viewing key and
  initialize the normal wallet from the fixture's prior chain state. Other
  wallets retain their fixed-account behavior, including in unit tests.
- Add eight unchanged upstream Sapling scenarios in the existing `input.rs`
  and `write.rs` test modules. Do not change production birthdays, balances,
  scanning, input selection, locks or transaction persistence. Inspection
  methods outside this batch fail explicitly instead of inventing results.
- Run with `cargo test --lib wallet::`. Initial result: the two existing reserve
  regressions and the upstream unknown-key/no-blocks scenarios pass. The six
  new scanning/locking/spending scenarios fail in upstream's first balance
  lookup (`testing.rs:1560` in 0.24.0): they do not call `update_chain_tip`,
  while our `get_wallet_summary` returns `None` until that explicit update.
  This is an integration-contract mismatch, not six independently verified
  wallet bugs. The later expiry and transaction-building assertions have not
  been reached. No tests are ignored or marked `should_panic` to hide this.
- Full library run: 53 passed, 6 failed (all six described above). The normal
  dependency feature graph contains only `orchard` and `transparent-inputs`
  for `zcash_client_backend`, without `test-dependencies`.
- Excluded from this batch: out-of-order scan scenarios (including upstream's
  oldest-note-selection scenario), because the mint accepts sequential scans
  only. Detailed sent-output/history scenarios still need adapter review;
  ordinary Orchard and transparent-input spending are unsupported by design.

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
