# Wallet Refactor — Subagent Plan

This document breaks the wallet refactor (described in `wallet.md`) into 5
subagents. Each subagent has a defined scope, file ownership, context
requirements, and dependency edges. **No code is written yet — this is
planning and context management only.**

## Module Layout (target)

```
src/wallet.rs              ← module root: Wallet struct, pub mod, re-exports
src/wallet/
├── selection.rs           ← existing: note selection (best-fit waterfall)
├── trees.rs               ← NEW: ShardTrees (Orchard + Sapling ShardTree)
├── record.rs              ← NEW: TransactionRecord, ReceivedNote, SpentNote, ReceivedUtxo
├── index.rs               ← NEW: unspent_notes + nullifier_index derived indexes
├── scan.rs                ← NEW: ScannedBlock → wallet state mutations
├── spend.rs               ← NEW: witness + anchor construction from ShardTree
└── reorg.rs               ← NEW: truncate tree + remove txs + rebuild indexes

src/scanner/
├── scan.rs                ← REWRITE: decrypt_block + scan_block orchestration
└── reorg.rs               ← REWRITE: reorg detection + coordination

src/key.rs                 ← UPDATE: expose IVKs/OVKs/NKs for ScanningKeys
```

## Dependency Graph

```
                    ┌──────────┐
                    │ SA-1     │
                    │ Trees    │
                    └────┬─────┘
                         │
              ┌──────────┴──────────┐
              │                     │
     ┌────────▼────────┐   ┌────────▼────────┐
     │ SA-2             │   │ SA-3            │
     │ Data Model       │   │ Scan Processing │
     │ (record + index) │   │ (ScannedBlock)  │
     └────────┬────────┘   └────────┬────────┘
              │                     │
              └──────────┬──────────┘
                         │
                ┌────────▼────────┐
                │ SA-4            │
                │ Wallet Core     │
                │ (struct + spend  │
                │  + reorg)        │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │ SA-5            │
                │ Scanner Rewrite │
                │ (scan + reorg + │
                │  key exposure)  │
                └─────────────────┘
```

SA-1 and SA-2 are **leaf nodes** — no dependencies on other subagents.
SA-3 depends on SA-1 and SA-2 (it consumes trees + records/indexes).
SA-4 depends on SA-1, SA-2, SA-3 (it ties everything together).
SA-5 depends on SA-4 (it calls into the wallet from the scanner module).

---

## SA-1: ShardTrees

### Scope
Build the tree layer: two `ShardTree<MemoryShardStore, _, _>` instances
(Orchard + Sapling), wrapped in a `ShardTrees` struct with a clean API for
the rest of the wallet.

### Files
- `src/wallet/trees.rs` (new)

### What it produces
A `ShardTrees` struct and API:
- `ShardTrees::new()` — construct with `MemoryShardStore::empty()`, max 100 checkpoints
- `seed_from_birthday(frontier, height)` — `insert_frontier` with `Retention::Checkpoint`
- `append_commitment(cmx, retention)` — per-output append during scanning
- `witness(position, checkpoint_height)` — `witness_at_checkpoint_id_caching`
- `anchor(checkpoint_height)` — `root_at_checkpoint_id_caching`
- `truncate(checkpoint_height)` — `truncate_to_checkpoint` for reorg
- `frontier()` — for birthday seeding / state inspection
- Type aliases: `OrchardShardStore`, `SaplingShardStore`

### Context needed

**Must read:**
- `shardtree` crate source: `src/lib.rs` (API), `src/store.rs` (ShardStore trait, Checkpoint), `src/store/memory.rs` (MemoryShardStore)
- `wallet.md` section "The Tree — ShardTree with MemoryShardStore" and "Two ShardTrees"
- `wallet.md` section "ShardTree API (6 calls)"
- `wallet.md` "Upstream References" → ShardTree API list

**Must understand:**
- `ShardTree<S, DEPTH, SHARD_HEIGHT>` const generics: `DEPTH=32`, `SHARD_HEIGHT=16` for both Orchard and Sapling
- `Retention<BlockHeight>` variants: `Marked`, `Ephemeral`, `Checkpoint { id, marking }`
- `Marking`: `Marked`, `None`, `Reference`
- `MemoryShardStore<H, C: Ord>` — `Error = Infallible`, so all tree ops are infallible (can `.expect()` or `unwrap()`)
- `Position` type from `incrementalmerkletree`
- `MerkleHashOrchard` (from `orchard::tree`) and `sapling::Node` (from `sapling`) as the `H` type params
- `BlockHeight` as the `CheckpointId` type (aliased from `zcash_protocol::consensus::BlockHeight`)

**Reference implementation:**
- zingolib `pepper-sync/src/wallet.rs:1232-1273` — `ShardTrees` struct, `ShardTrees::new()`
- zingolib `pepper-sync/src/witness.rs:22` — `SHARD_HEIGHT = 16`
- zingolib `pepper-sync/src/sync.rs:52` — `MAX_REORG_ALLOWANCE = 100`
- librustzcash `data_api.rs:159,166` — `SAPLING_SHARD_HEIGHT`, `ORCHARD_SHARD_HEIGHT`
- librustzcash `data_api.rs:3517-3592` — `WalletCommitmentTrees` trait (shows the expected interface)
- librustzcash `data_api/ll/wallet.rs` — `update_tree()` function (shows `insert_frontier` + `insert_tree` usage)

### Dependencies
None. This is a leaf node — it wraps the shardtree crate directly.

### Key decisions for this subagent
1. Should `ShardTrees` hold the trees as direct fields or behind the `WalletCommitmentTrees` trait? (Recommendation: direct fields — zns-mint is in-memory, no need for the trait abstraction)
2. Should `append_commitment` take `Retention` directly or compute it from `(is_ours, is_checkpoint)`? (Recommendation: take `Retention` — the scanner already computes it via `find_received`)
3. Error handling: `MemoryShardStore::Error = Infallible`, so all results are `Result<_, Infallible>`. Should we unwrap or propagate? (Recommendation: unwrap/expect — in-memory store cannot fail)

---

## SA-2: Data Model (Records + Indexes)

### Scope
Define the wallet's data structures: `TransactionRecord`, `ReceivedNote`,
`SpentNote`, `ReceivedUtxo`, and the two derived indexes (`unspent_notes`,
`nullifier_index`). Includes the add/remove/rebuild logic for indexes.

### Files
- `src/wallet/record.rs` (new)
- `src/wallet/index.rs` (new)

### What it produces

**`record.rs`:**
- `TransactionRecord` struct: txid, block_height, tx_index, fee, raw_bytes, received_orchard, received_sapling, received_transparent, spent_orchard, spent_sapling, outgoing_orchard
- `ReceivedNote` struct: action_index, note, memo, account_id, scope, position
- `SpentNote` struct: action_index, nullifier, account_id
- `ReceivedUtxo` struct: outpoint, value, account_id

**`index.rs`:**
- `UnspentNotes` type: `HashMap<AccountId, HashMap<[u8; 32], ReceivedNote>>` (account → rho → note)
- `NullifierIndex` type: `HashMap<[u8; 32], (AccountId, [u8; 32])>` (nullifier → (account, rho))
- `add_transaction(&mut indexes, record)` — insert received notes, remove spent notes
- `remove_transaction(&mut indexes, record)` — reverse: remove received, restore spent (for reorg)
- `rebuild_from_transactions(&mut indexes, &transactions)` — full rebuild from remaining cache

### Context needed

**Must read:**
- `wallet.md` section "The Wallet Holds Three Things" → "Transactions (the cache)" and "Derived Indexes"
- Current `src/wallet.rs` — `SpendableNote` struct (what we're replacing/superseding), `nf_index` and `notes` fields (what we're upgrading)

**Must understand (from librustzcash):**
- `WalletTx<AccountId>` — `zcash_client_backend/src/wallet.rs:122` — the shape of scanned transaction data. Our `TransactionRecord` is a superset (adds raw_bytes, fee).
- `WalletOutput<Note, Nullifier, AccountId>` — `zcash_client_backend/src/wallet.rs:449` — fields: index, ephemeral_key, note, is_change, note_commitment_tree_position, nf, account_id, recipient_key_scope. Our `ReceivedNote` extracts from this.
- `WalletSpend<Nf, AccountId>` — `zcash_client_backend/src/wallet.rs:409` — fields: index, nf, account_id. Our `SpentNote` mirrors this.
- `WalletTransparentOutput<AccountId>` — `zcash_client_backend/src/wallet.rs` — fields: outpoint, txout, mined_height, recipient_account, etc. Our `ReceivedUtxo` extracts from this.
- `zip32::Scope` — External or Internal, used in `ReceivedNote.scope`
- `TxId` — from `zcash_primitives::transaction` (or `zcash_protocol`)
- `TxIndex(u16)` — from `zcash_protocol::consensus`
- `Position` — from `incrementalmerkletree`
- `AccountId` — `zip32::AccountId` (the type already used in the codebase)

**Key difference from current code:**
- Current `SpendableNote` has no memo, no scope, no txid. `ReceivedNote` adds all three.
- Current wallet deletes spent notes. `TransactionRecord` keeps them as `SpentNote` entries for history + reorg restoration.
- Current wallet has no transaction-level storage. `TransactionRecord` keyed by `TxId` is new.

### Dependencies
None. This is a leaf node — pure data structure definitions and index logic.

### Key decisions for this subagent
1. Should `ReceivedNote` store the full `orchard::note::Note` or a type-erased `Note` enum? (Recommendation: full typed note — zns-mint is Orchard-centric but Treasury receives Sapling too, so may need a pool-aware enum or separate per-pool structs. The `wallet.md` design shows separate `received_orchard` and `received_sapling` vectors in `TransactionRecord`, which suggests per-pool types.)
2. Should memo be `[u8; 512]` or `MemoBytes`? (Recommendation: `[u8; 512]` — matches wallet.md design, and the scanner needs to parse it for Name Notes)
3. Should `raw_bytes` be `Vec<u8>` or a boxed slice? (Recommendation: `Vec<u8>` — rescan insurance, not hot-path)
4. Should indexes be separate structs or methods on `Wallet`? (Recommendation: separate structs in `index.rs` — testable in isolation, clear ownership)

---

## SA-3: Scan Processing

### Scope
Process a `ScannedBlock<AccountId>` (produced by librustzcash's
`scan_block`) into wallet mutations: append commitments to ShardTrees,
build `TransactionRecord`s, update derived indexes.

### Files
- `src/wallet/scan.rs` (new)

### What it produces
A function (or impl block) that takes a `ScannedBlock` and mutates the wallet:
- `process_scanned_block(trees, transactions, indexes, scanned_block)`
  1. For each commitment in `scanned_block.orchard().commitments()`: `trees.orchard.append_commitment(cmx, retention)`
  2. For each commitment in `scanned_block.sapling().commitments()`: `trees.sapling.append_commitment(node, retention)`
  3. For each `WalletTx` in `scanned_block.transactions()`:
     - Build a `TransactionRecord` from the WalletTx's spends/outputs/transparent
     - If non-empty (has any received/spent/transparent/outgoing): insert into `transactions` cache
     - Call `index::add_transaction(indexes, record)` to update derived indexes
  4. If empty: discard (commitments already appended to tree)

### Context needed

**Must read:**
- `wallet.md` section "Scanning Pipeline"
- `wallet.md` section "What a Full Block Gives Us" → "Relevant — Extract and Store" table
- librustzcash `scanning/full.rs` — `scan_block` function signature and return type
- librustzcash `data_api.rs:2425-2514` — `ScannedBlock<AccountId>` struct, `transactions()`, `sapling()`, `orchard()`, `into_commitments()`, `to_block_metadata()`
- librustzcash `data_api.rs:2369-2412` — `ScannedBundles` (commitments with `Retention<BlockHeight>`, nullifier_map, final_tree_size)
- librustzcash `wallet.rs:122-210` — `WalletTx<AccountId>` (txid, block_index, orchard_spends, orchard_outputs, sapling_spends, sapling_outputs, transparent_outputs)
- librustzcash `wallet.rs:449-510` — `WalletOutput` (index, note, is_change, position, nf, account_id, scope)
- librustzcash `wallet.rs:409-440` — `WalletSpend` (index, nf, account_id)
- librustzcash `wallet.rs` — `WalletTransparentOutput` (outpoint, txout, value, recipient_account)
- Current `src/scanner/scan.rs` — the hand-rolled scanner being replaced. Note: it currently does Name Note memo parsing (decode_name_note → registry.set_tip). This logic needs to be preserved — it happens after note decryption, before/after wallet insertion.

**Must understand:**
- `ScannedBlock` already contains commitments with `Retention<BlockHeight>` pre-computed by `find_received`. The retention logic is:
  ```
  (is_marked, true)  → Checkpoint { id: block_height, marking: Marked/None }
  (true, false)      → Marked
  (false, false)     → Ephemeral
  ```
  SA-3 does NOT recompute retention — it just passes through what `ScannedBlock` provides.
- `ScannedBlock.transactions()` only includes `WalletTx`s that are relevant (have spends/outputs/transparent). Irrelevant txs are already filtered by `scan_block`.
- `WalletOutput.nf()` is `Option<Nullifier>` — `None` if only IVK was used (no FVK), `Some` if FVK was used. This matters for nullifier index construction.
- `WalletOutput.is_change()` — true if the account also spent in the same tx. This maps to Internal scope.
- `WalletOutput.recipient_key_scope()` — `Option<Scope>` (External or Internal). This is the scope to store in `ReceivedNote`.

**Name Note parsing:**
- Current scanner parses Registry notes' memos via `crate::mint::decode_name_note(&memo)` and calls `registry.set_tip(name, tip)`.
- This logic must be preserved but it lives in the scanner module (SA-5), not in the wallet's scan processing. The wallet's `process_scanned_block` inserts notes with memos; the scanner reads them back for registry updates. OR: the scanner passes a callback/filter. This boundary needs to be decided.

### Dependencies
- SA-1 (Trees) — calls `trees.append_commitment(cmx, retention)`
- SA-2 (Data Model) — builds `TransactionRecord`s, calls `index::add_transaction`

### Key decisions for this subagent
1. Should `process_scanned_block` be a free function or a method on `Wallet`? (Recommendation: free function taking `&mut` references — matches the scanner's "pure pipeline" design from `08-chain-sync.md`)
2. How to handle the Name Note memo parsing? Options:
   - (a) Wallet stores the memo, scanner reads it back after processing (decoupled)
   - (b) Scanner passes a callback to `process_scanned_block` (coupled)
   - (c) Scanner does a second pass over the wallet's transactions after processing
   - Recommendation: (a) — wallet stores memo in `ReceivedNote`, scanner does a post-pass over newly-inserted Registry notes to parse memos. Clean separation.
3. `raw_bytes` — `ScannedBlock` doesn't contain raw transaction bytes. They come from the original `Block`. SA-3 needs the raw bytes passed in separately, or SA-5 stores them. (Recommendation: SA-5 passes `(ScannedBlock, Vec<(TxId, Vec<u8>)>)` — raw bytes keyed by txid. Or: `ScannedBlock` is consumed alongside the original block.)

---

## SA-4: Wallet Core (Struct + Spend + Reorg)

### Scope
Define the `Wallet` struct that ties together trees, transaction cache, and
indexes. Implement the spending path (witness + anchor from ShardTree) and
reorg coordination (truncate + remove + rebuild).

### Files
- `src/wallet.rs` (rewrite — module root + Wallet struct)
- `src/wallet/spend.rs` (new)
- `src/wallet/reorg.rs` (new)

### What it produces

**`wallet.rs` (module root):**
```rust
pub mod selection;    // existing
pub mod trees;        // SA-1
pub mod record;       // SA-2
pub mod index;        // SA-2
pub mod scan;         // SA-3
pub mod spend;        // SA-4 (this subagent)
pub mod reorg;        // SA-4 (this subagent)

pub struct Wallet {
    ufvk_map: HashMap<AccountId, UnifiedFullViewingKey>,
    trees: ShardTrees,                              // SA-1
    transactions: HashMap<TxId, TransactionRecord>,  // SA-2
    unspent_notes: UnspentNotes,                     // SA-2
    nullifier_index: NullifierIndex,                 // SA-2
}
```
- `Wallet::new(ufvks)` — construct empty
- `Wallet::ufvk_for(account)` — existing, keep
- `Wallet::balance(account)` — existing, keep but rework to use `unspent_notes`
- `Wallet::notes_for(account)` — existing, keep but rework
- `Wallet::process_scanned_block(...)` — delegates to `scan::process_scanned_block`

**`spend.rs`:**
- `spend_witness(trees, note) -> MerklePath` — `witness_at_checkpoint_id_caching(position, &confirmed_height)`
- `spend_anchor(trees, confirmed_height) -> Anchor` — `root_at_checkpoint_id_caching(&confirmed_height)`
- The `registry::build_transaction` path calls these instead of `todo!()`

**`reorg.rs`:**
- `handle_reorg(wallet, common_ancestor_height)`:
  1. `trees.orchard.truncate(common_ancestor_height)`
  2. `trees.sapling.truncate(common_ancestor_height)`
  3. Remove all `TransactionRecord`s where `block_height > common_ancestor`
  4. `index::rebuild_from_transactions(&mut unspent_notes, &mut nullifier_index, &transactions)`
- This replaces the current `ReorgBuffer` stub in `scanner/reorg.rs`

### Context needed

**Must read:**
- `wallet.md` section "The Wallet Holds Three Things"
- `wallet.md` section "Spending Path"
- `wallet.md` section "Reorg"
- `wallet.md` section "Implementation Plan" → Steps 3, 5, 7, 8
- Current `src/wallet.rs` — the struct being replaced, methods to preserve (`new`, `ufvk_for`, `notes_for`, `balance`, `insert_note`, `spend_note`, `append_commitment`)
- Current `src/wallet/selection.rs` — `select_funds` takes `&Wallet`, accesses `notes_for()`. The `Wallet` API must remain compatible.
- Current `src/registry.rs` — the spending path caller (has `todo!()` for witness construction)
- Current `src/scanner/reorg.rs` — the `ReorgBuffer` stub being replaced

**Must understand (from librustzcash):**
- `ShardTree::witness_at_checkpoint_id_caching(position, checkpoint_id)` → `Result<Option<MerklePath<H, DEPTH>>, ShardTreeError>` — the Merkle path for spending
- `ShardTree::root_at_checkpoint_id_caching(checkpoint_id)` → `Result<Option<H>, ShardTreeError>` — the anchor (tree root at checkpoint)
- `MerklePath<H, DEPTH>` from `incrementalmerkletree` — contains the authentication path + position
- Orchard anchor type: `orchard::tree::Anchor` (or `MerkleHashOrchard` wrapped)
- `ShardTree::truncate_to_checkpoint(checkpoint_id)` → `Result<bool, ShardTreeError>` — reorg rewind
- `PRUNING_DEPTH = 100` — max reorg depth (from `data_api/ll/wallet.rs`)

**Spending path detail:**
- `select_funds` returns `Vec<&SpendableNote>` (or `&ReceivedNote` in new model)
- For each selected note: need its `position` and `confirmed_height` (the block height where it was mined = the checkpoint ID)
- `witness_at_checkpoint_id_caching(note.position, &note.confirmed_height)` → MerklePath
- `root_at_checkpoint_id_caching(&note.confirmed_height)` → Anchor
- These go into the Orchard bundle builder

### Dependencies
- SA-1 (Trees) — `ShardTrees` is a field of `Wallet`
- SA-2 (Data Model) — `TransactionRecord`, `UnspentNotes`, `NullifierIndex` are fields
- SA-3 (Scan) — `process_scanned_block` is called via `Wallet`

### Key decisions for this subagent
1. Should `SpendableNote` (current) be replaced by `ReceivedNote` (SA-2) or kept as a view type? (Recommendation: replace — `ReceivedNote` is a superset. `selection.rs` needs to be updated to work with `ReceivedNote` instead of `SpendableNote`. The `notes_for()` API returns `ReceivedNote` now.)
2. Should `confirmed_height` be stored on `ReceivedNote` or derived from the `TransactionRecord`? (Recommendation: store on `ReceivedNote` — it's the checkpoint ID for witness/anchor lookups, and it's per-note, not per-tx. Actually, `TransactionRecord` has `block_height` and all notes in a tx share it. But `ReceivedNote` is cloned out of the record for the index, so it needs its own copy.)
3. How does `reorg.rs` interact with the scanner's reorg detection? The scanner detects `prev_hash` mismatch, finds common ancestor, then calls `wallet::reorg::handle_reorg`. (Recommendation: scanner owns detection, wallet owns state mutation. Clean separation.)
4. `selection.rs` compatibility: currently returns `&SpendableNote`. With `ReceivedNote`, the references change. Should `select_funds` return owned `ReceivedNote` clones or references? (Recommendation: references into `unspent_notes` — same pattern, just different type.)

---

## SA-5: Scanner Rewrite

### Scope
Rewrite the scanner module to use librustzcash's `decrypt_block` +
`scan_block` instead of the hand-rolled `scan_verified_block`. Update key
exposure in `key.rs` for `ScanningKeys::from_account_ufvks`. Rewrite reorg
detection to use `BlockMetadata` and coordinate with the wallet's reorg
handler.

### Files
- `src/scanner/scan.rs` (rewrite)
- `src/scanner/reorg.rs` (rewrite)
- `src/key.rs` (update — expose IVKs/OVKs/NKs for scanning)

### What it produces

**`scanner/scan.rs` (rewrite):**
- `scan_block(wallet, registry, block, height, prior_metadata)`:
  1. Build `ScanningKeys` from wallet's UFVKs via `ScanningKeys::from_account_ufvks`
  2. Build `Nullifiers` from wallet's `nullifier_index` (or maintain incrementally)
  3. Call `decrypt_block(params, block, &scanning_keys)` → `(BlockHeader, Vec<BatchResult>)`
  4. Call `scan_block(params, height, &header, vtx, &scanning_keys, &nullifiers, prior_metadata, find_account_for_address)` → `ScannedBlock`
  5. Call `wallet.process_scanned_block(scanned_block, raw_tx_bytes)` (SA-3)
  6. Post-pass: for each new Registry note, parse memo via `decode_name_note`, update `registry.set_tip`

**`scanner/reorg.rs` (rewrite):**
- Replace `ReorgBuffer` with `BlockMetadata` tracking (using librustzcash's `BlockMetadata`)
- `detect_reorg(header, prior_metadata) -> bool` — `header.prev_block != prior_metadata.block_hash()`
- `find_common_ancestor(zebra, current_height) -> BlockHeight` — walk back through Zebra
- `handle_reorg(wallet, common_ancestor)` — delegates to `wallet::reorg::handle_reorg` (SA-4)
- Re-scan from `common_ancestor + 1` to new tip

**`key.rs` (update):**
- `AccountKeys` already has `fvk()` which returns `UnifiedFullViewingKey`
- `ScanningKeys::from_account_ufvks` takes `(AccountId, UnifiedFullViewingKey)` pairs
- The wallet's `ufvk_map` already stores these. SA-5 just needs to ensure the UFVKs are accessible in the format `ScanningKeys::from_account_ufvks` expects.
- May need to expose OVKs explicitly if SA-3/SA-4 need them for outgoing note detection. `UnifiedFullViewingKey::orchard()` gives the FVK, from which OVK is derivable.

### Context needed

**Must read:**
- `wallet.md` section "Scanning Pipeline"
- `wallet.md` section "Reorg"
- `wallet.md` section "Implementation Plan" → Steps 2, 4, 6, 7
- `wallet.md` section "Why OVK is needed" and "Why Internal scope is needed"
- librustzcash `scanning.rs` — `ScanningKeys`, `ScanningKeys::from_account_ufvks`, `Nullifiers`, `Nullifiers::update_with`
- librustzcash `scanning/full.rs` — `decrypt_block`, `scan_block` signatures, `BatchRunners`, `BatchResult`, `ScanBlockError`
- librustzcash `data_api.rs:2315-2350` — `BlockMetadata` struct
- librustzcash `data_api/ll/wallet.rs` — `put_blocks` as reference for how ScannedBlock is consumed (SA-3 follows this pattern)
- Current `src/scanner/scan.rs` — the hand-rolled scanner being replaced. Key logic to preserve: Name Note memo parsing (`decode_name_note` → `zns_psi_rcm` → `registry.set_tip`)
- Current `src/scanner/reorg.rs` — the stub being replaced
- Current `src/key.rs` — already multi-pool, just needs to wire UFVKs into `ScanningKeys`

**Must understand:**
- `scan_block` (full) signature:
  ```rust
  fn scan_block<P, AccountId, IvkTag, E>(
      params: &P,
      height: BlockHeight,
      header: &BlockHeader,
      vtx: Vec<BatchResult<IvkTag>>,
      scanning_keys: &ScanningKeys<AccountId, IvkTag>,
      nullifiers: &Nullifiers<AccountId>,
      prior_block_metadata: Option<&BlockMetadata>,
      find_account_for_address: impl Fn(&TransparentAddress) -> Result<Option<(AccountId, Option<TransparentKeyScope>)>, E>,
  ) -> Result<ScannedBlock<AccountId>, ScanBlockError<E>>
  ```
- `AccountId` bounds: `Default + Debug + Ord + Hash + ConditionallySelectable + Send + Sync + 'static`
- `zip32::AccountId` — does it implement all these? Need to check. If not, may need a newtype wrapper.
- `IvkTag = (AccountId, Scope)` — the tag type used by `ScanningKeys::from_account_ufvks`
- `find_account_for_address` — needed for transparent UTXO detection. For zns-mint, this checks if a transparent address belongs to the Treasury account.
- `Nullifiers` can be built from the wallet's `nullifier_index` or maintained incrementally via `Nullifiers::update_with(&ScannedBlock)`. For in-memory, incremental is natural.
- `decrypt_block` spins up internal `BatchRunners` and discards them. For high-throughput scanning, you might want persistent `BatchRunners` (the `sync-decryptor` feature). For now, `decrypt_block` is simpler.

**Constants:**
- `DEFAULT_BATCH_SIZE_THRESHOLD = 200` (from `scanning/full.rs`)
- `PRUNING_DEPTH = 100` (from `data_api/ll/wallet.rs`)
- Network params: `MAIN_NETWORK` (already used in `key.rs`)

### Dependencies
- SA-4 (Wallet Core) — calls `wallet.process_scanned_block`, `wallet::reorg::handle_reorg`
- SA-3 (Scan) — the `process_scanned_block` function being called
- SA-1 (Trees) — indirectly (wallet uses trees)
- SA-2 (Data Model) — indirectly (wallet uses records/indexes)

### Key decisions for this subagent
1. `zip32::AccountId` trait bounds: does it implement `ConditionallySelectable`? If not, need a newtype. (This is a **blocker** — must be resolved early.)
2. `Nullifiers` maintenance: incremental (`update_with`) or rebuilt from `nullifier_index` each block? (Recommendation: incremental — matches the scanning pipeline design. But the wallet's `nullifier_index` is the source of truth, so there's a sync question.)
3. `find_account_for_address`: how to implement for zns-mint? The Treasury has transparent addresses. Need to derive them from the UFVK and match. (Check: does `zcash_keys` provide transparent address derivation from UFVK?)
4. Name Note parsing: post-pass over newly inserted Registry notes. How to identify "newly inserted" notes? (Recommendation: `process_scanned_block` returns the list of new txids, or the scanner tracks the block's transactions.)
5. Raw transaction bytes: `ScannedBlock` doesn't include them. The original `Block` has them. SA-5 needs to extract raw bytes from the block before passing to `scan_block` (which consumes the `BatchResult`s that wrap the `Transaction`s). (Recommendation: extract `tx.txid() → tx.encode().to_vec()` mapping before calling `decrypt_block`.)

---

## Execution Order

```
Phase 1 (parallel):  SA-1 (Trees)    SA-2 (Data Model)
Phase 2:             SA-3 (Scan Processing)  — needs SA-1 + SA-2
Phase 3:             SA-4 (Wallet Core)      — needs SA-1 + SA-2 + SA-3
Phase 4:             SA-5 (Scanner Rewrite)  — needs SA-4
```

SA-1 and SA-2 can be done in parallel. SA-3 starts after both complete.
SA-4 starts after SA-3. SA-5 starts after SA-4.

## Open Questions (must resolve before coding)

1. **`zip32::AccountId` trait bounds** — Does it implement `ConditionallySelectable + Default + Ord + Hash + Send + Sync + 'static`? If not, SA-5 needs a newtype wrapper, which ripples into SA-2, SA-3, SA-4. **This is the #1 blocker.**
2. **Raw transaction bytes** — `ScannedBlock` doesn't carry them. Where do they come from? SA-5 extracts from `Block` before `decrypt_block` consumes it? Or `BatchResult` retains them?
3. **Name Note parsing boundary** — Wallet stores memos, scanner does post-pass for registry updates. Exact API?
4. **`SpendableNote` → `ReceivedNote` migration** — `selection.rs` must be updated. Is this SA-4's job or a separate small task?
5. **Birthday checkpoint** — Where does the birthday frontier come from? `src/checkpoints/` directory exists. Need to load and parse it to seed ShardTrees.
6. **OVK for outgoing detection** — `scan_block` via `ScanningKeys` handles incoming (IVK) + nullifier (NK). Does it also handle OVK outgoing? Check: `find_received` only does IVK trial decryption. OVK is separate. The `wallet.md` design says OVK is needed for Treasury OTP relay memos. Need to confirm librustzcash `scan_block` supports OVK or if it's a separate pass.