# Wallet Design

This document defines the in-memory wallet that `zns-mint` uses to cache
blockchain state personal to the mint's keys and maintain always-spendability.

It is the design source for the wallet layer. When source code implements or
changes behavior described here, update this document in the same change.

## Problem Statement

The current `src/wallet.rs` is a **note tracker**, not a wallet. It holds:
- Unspent notes (only)
- A nullifier index
- A `CommitmentTree` (frontier)

It throws away everything else: memos, transaction records, spent notes,
block context. A spent note is deleted, not logged. There is no transaction
history, no reorg data, and the tree type (`CommitmentTree` frontier) cannot
construct retroactive witnesses — so always-spendability is broken.

A wallet is a **cache of the blockchain personal to the mint's keys**: every
transaction where the mint received a note, spent a note, received a
transparent UTXO, or sent an outgoing note. Plus chain state (the Merkle
tree) for witness construction.

## What a Full Block Gives Us

We poll a Zebra node via gRPC for full block bytes and parse them with
`zcash_primitives::block::Block::read`. A full block contains:

```
Block
├── header: { prev_hash, time, bits, nonce, solution, ... }
└── vtx: [Transaction]
      └── each Transaction may have:
          ├── orchard_bundle: { actions: [Action { nullifier, cmx, enc_ciphertext, out_ciphertext }] }
          ├── sapling_bundle: { shielded_outputs, shielded_spends }
          ├── transparent_bundle: { vin, vout }
          └── sprout_bundle (deprecated)
```

### Relevant — Extract and Store

| Data | How we detect it | What we store |
|---|---|---|
| Orchard commitments (all) | Every action in every bundle | Appended to ShardTree (chain state) |
| Orchard nullifiers (all) | Every action in every bundle | Check against ours; store matches as SpentNote |
| Our Orchard notes | IVK trial decryption (External + Internal) | ReceivedNote: note, memo, position, account, scope |
| Our Orchard outgoing notes | OVK decryption | Same shape as ReceivedNote |
| Sapling commitments (all) | Every output in every bundle | Appended to Sapling ShardTree |
| Our Sapling notes | IVK trial decryption (External + Internal) | ReceivedNote |
| Our transparent UTXOs | Match output script to our addresses | ReceivedUtxo: outpoint, value, account |
| Transaction txid | From parsed transaction | TransactionRecord key |
| Transaction fee | From value balance | Part of TransactionRecord |
| Full transaction bytes | From parsed transaction | Part of TransactionRecord (rescan insurance) |
| Block header prev_hash | From block header | Check at scan time for reorg (don't store) |

### Dead — Never Look At

- **Sprout bundles** — deprecated, no modern wallet uses it
- **Block header time** — mint is height-ordered, not time-ordered
- **Block header bits** — PoW difficulty target, block explorer data only

## Two Sides of the Mint

- **Registry (sends):** single-pool — creates Name Notes in Orchard only.
  Registry UFVK is Orchard-only.
- **Treasury (receives):** multi-pool — accepts Orchard, Sapling, and
  Transparent from users. Treasury UFVK has all three components.

## The Tree — ShardTree with MemoryShardStore

### Why Not CommitmentTree (Frontier)

`CommitmentTree<MerkleHashOrchard, 32>` is a frontier. It stores only the
incomplete edges of the tree. It can append commitments and compute the
root, but **cannot retroactively construct a witness for an old position**.
`IncrementalWitness` can only be created for the most recently appended leaf
(`IncrementalWitness::from_tree`), and must be maintained every block after.

This means always-spendability is broken with the current tree type: notes
received in the past cannot be spent because no witness can be constructed.

### ShardTree

`ShardTree` splits the Merkle tree into shards (subtrees of a fixed height).
It stores enough of the tree to construct witnesses for any position at any
time — retroactively, on demand. It has built-in checkpoint/truncate for
reorg. `MemoryShardStore` is the in-memory implementation.

The full type:
```rust
ShardTree<
    MemoryShardStore<MerkleHashOrchard, BlockHeight>,
    32,   // orchard::NOTE_COMMITMENT_TREE_DEPTH
    16,   // ORCHARD_SHARD_HEIGHT = 32 / 2
>
```

Confirmed by zingolib (a production Zcash wallet) which creates ShardTree
locally with `MemoryShardStore`, same constants:
- `SHARD_HEIGHT = 16` (`pepper-sync/src/witness.rs:22`)
- `MAX_REORG_ALLOWANCE = 100` (`pepper-sync/src/sync.rs:52`)
- `COMMITMENT_TREE_LEVELS = 32` (`zingolib/src/wallet/legacy.rs:993`)

### ShardTree API (6 calls)

```rust
// Construct
let tree = ShardTree::new(MemoryShardStore::empty(), 100);

// Seed from birthday checkpoint
tree.insert_frontier(frontier, Retention::Checkpoint {
    id: birthday_height, marking: Marking::Reference,
})?;

// Append a commitment — scanner does this per action
tree.append(cmx, Retention::Marked)?;       // ours
tree.append(cmx, Retention::Ephemeral)?;    // not ours
tree.append(cmx, Retention::Checkpoint {    // last in block → creates checkpoint
    id: block_height, marking: Marking::Marked,
})?;

// Get a witness at sign time
let path = tree.witness_at_checkpoint_id_caching(position, &block_height)?;

// Get the anchor (root) at sign time
let anchor = tree.root_at_checkpoint_id_caching(&block_height)?;

// Reorg rewind
tree.truncate_to_checkpoint(&block_height)?;
```

Retention is set during scanning (librustzcash `find_received`):
```rust
let retention = match (decrypted_note.is_some(), is_checkpoint) {
    (is_marked, true) => Retention::Checkpoint {
        id: block_height,
        marking: if is_marked { Marking::Marked } else { Marking::None },
    },
    (true, false) => Retention::Marked,
    (false, false) => Retention::Ephemeral,
};
```

### Two ShardTrees

The wallet holds two: one for Orchard, one for Sapling.
```rust
type OrchardShardStore = MemoryShardStore<MerkleHashOrchard, BlockHeight>;
type SaplingShardStore = MemoryShardStore<sapling::Node, BlockHeight>;
```

## The Wallet Holds Three Things

```
Wallet {
    viewing_keys: ...,          // config — what we decrypt with
    trees: ShardTrees,          // chain state — for witnesses
    transactions: ...,          // cache — what happened to us
}
```

### Viewing Keys (config, set once at boot)

One UFVK per account (Treasury, Registry). From each UFVK we derive:
- IVKs (External + Internal) for incoming note detection
- OVKs for outgoing note detection
- NKs (nullifier deriving keys) for nullifier computation

### Trees (chain state)

```rust
struct ShardTrees {
    orchard: ShardTree<OrchardShardStore, 32, 16>,
    sapling: ShardTree<SaplingShardStore, 32, 16>,
}
```

Seeded from birthday checkpoint on boot. Appended to every block. Provides
retroactive witnesses on demand. Truncates on reorg.

### Transactions (the cache — one table)

```rust
HashMap<TxId, TransactionRecord>
```

A transaction is relevant if ANY of:
- An Orchard output decrypts with our IVK → we received a note
- An Orchard nullifier matches ours → we spent a note
- A Sapling output decrypts with our IVK → we received a Sapling note
- A transparent output goes to our address → we received a UTXO
- An Orchard output decrypts with our OVK → we sent a note (outgoing)

If none are true, the transaction is discarded (commitments already appended
to the tree).

```rust
struct TransactionRecord {
    txid: TxId,
    block_height: BlockHeight,
    tx_index: TxIndex,              // position in the block
    fee: u64,
    raw_bytes: Vec<u8>,
    received_orchard: Vec<ReceivedNote>,
    received_sapling: Vec<ReceivedNote>,
    received_transparent: Vec<ReceivedUtxo>,
    spent_orchard: Vec<SpentNote>,
    spent_sapling: Vec<SpentNote>,
    outgoing_orchard: Vec<ReceivedNote>,  // via OVK
}

struct ReceivedNote {
    action_index: usize,            // which action in the bundle
    note: ...,                      // value, rho, rseed, recipient
    memo: [u8; 512],
    account_id: AccountId,
    scope: Scope,                   // External or Internal
    position: Position,             // where in the tree
}

struct SpentNote {
    action_index: usize,
    nullifier: ...,
    account_id: AccountId,
}

struct ReceivedUtxo {
    outpoint: OutPoint,
    value: u64,
    account_id: AccountId,
}
```

### Derived Indexes

Two indexes derived from the transactions table, maintained incrementally:

```
unspent_notes: HashMap<AccountId, HashMap<[u8; 32], ReceivedNote>>
    // account → rho → note, only notes not yet spent

nullifier_index: HashMap<[u8; 32], (AccountId, [u8; 32])>
    // nullifier → (account, rho), for spend detection
```

When a transaction is added:
- Each `ReceivedNote` → inserted into `unspent_notes`, nullifier computed
  and added to `nullifier_index`
- Each `SpentNote` → matching note removed from `unspent_notes`, nullifier
  removed from `nullifier_index`

When a transaction is removed (reorg):
- Each `ReceivedNote` → removed from `unspent_notes`, nullifier removed
- Each `SpentNote` → note restored to `unspent_notes`, nullifier restored

## Scanning Pipeline

```
For each block from Zebra:
    1. Check prev_hash == cursor.hash (reorg detection)
    2. Use zcash_client_backend::scanning::full::scan_block
       (replaces hand-rolled scan_verified_block)
       - Trial-decrypts with IVKs (External + Internal) for all pools
       - Checks nullifiers against ours
       - Trial-decrypts with OVKs for outgoing detection
       - Matches transparent outputs to our addresses
       - Tracks commitment positions
       - Returns ScannedBlock<AccountId>
    3. Process ScannedBlock:
       - Append commitments to ShardTree with retention
       - For each WalletTx in ScannedBlock:
         - Build TransactionRecord
         - Add to transaction cache
         - Update derived indexes
    4. Update cursor (height, hash)
```

The key change: use `zcash_client_backend::scanning::full::scan_block`
instead of the hand-rolled `bundle.decrypt_outputs_with_keys`. This gives
correct trial decryption (both scopes), nullifier matching, OVK decryption,
transparent detection, and position tracking for free.

`ScanningKeys::from_account_ufvks` derives all IVKs (External + Internal),
NKs, and account mappings from the UFVKs in one call.

## Spending Path

```
1. Select notes from unspent_notes (via selection::select_funds)
2. For each selected note:
   a. tree.witness_at_checkpoint_id_caching(note.position, &note.block_height)
      → MerklePath
   b. tree.root_at_checkpoint_id_caching(&note.block_height)
      → Anchor
3. Build the Orchard bundle with notes + witnesses + anchor
4. Prove + sign with the spending key
5. Broadcast via Zebra
```

No per-note witness maintenance. Witnesses constructed on demand from
ShardTree. Always spendable as long as the tree is in sync.

## Reorg

```
Scanner detects: block.prev_hash != cursor.hash

1. Find common ancestor height (walk back through Zebra)
2. tree.truncate_to_checkpoint(&common_ancestor_height)
3. Remove all TransactionRecords where block_height > common_ancestor
4. Rebuild derived indexes from remaining transactions
5. Re-scan from common_ancestor + 1 to new tip
```

ShardTree handles tree rewind. Transaction cache handles data rewind.
Derived indexes are rebuilt from remaining cache.

Max reorg depth: 100 blocks (PRUNING_DEPTH in librustzcash,
MAX_REORG_ALLOWANCE in zingolib).

## Implementation Plan — 8 Steps

### Step 1 — Add tree dependency

Add `shardtree` as a direct dep in `Cargo.toml`. Already transitive via
`zcash_client_backend`, so no new compiled code. May not need to be in
Cargo.toml if we only use it through `zcash_client_backend` re-exports.

### Step 2 — Redesign `key.rs` for multi-pool

Treasury UFVK gets Orchard + Sapling + Transparent components (user-facing,
accepts all pools). Registry UFVK stays Orchard-only (Name Notes are
Orchard). Expose all derived keys: IVKs (External + Internal) and OVKs for
each pool.

Current `key.rs` derives Orchard-only keys:
```rust
zcash_keys = { ..., features = ["orchard"] }
UnifiedSpendingKey::from_seed(&MAIN_NETWORK, seed, AccountId::const_from_u32(0))
```

Need to add `sapling` feature to `zcash_keys` and configure
`UnifiedSpendingKey::from_seed` to derive multiple pool components.

### Step 3 — Redesign `wallet.rs`

Replace the current struct with:
- `viewing_keys`: UFVKs per account
- `orchard_tree`: `ShardTree<MemoryShardStore<MerkleHashOrchard, BlockHeight>, 32, 16>`
- `sapling_tree`: `ShardTree<MemoryShardStore<sapling::Node, BlockHeight>, 32, 16>`
- `transactions`: `HashMap<TxId, TransactionRecord>`
- `unspent_notes`: derived index
- `nullifier_index`: derived index

Define `TransactionRecord`, `ReceivedNote`, `SpentNote`, `ReceivedUtxo`.
Reuse librustzcash's `WalletTx`, `WalletOutput`, `WalletSpend` shapes where
they fit.

### Step 4 — Replace hand-rolled scanner with librustzcash's

Replace `scan_verified_block` with
`zcash_client_backend::scanning::full::scan_block`. Use
`ScanningKeys::from_account_ufvks` for all key derivation. Use `Nullifiers`
for spend detection. Process the returned `ScannedBlock` to update wallet
state.

### Step 5 — ShardTree integration

- Seed from birthday checkpoint frontier on boot
- Append commitments from each `ScannedBlock` with retention
- `witness_at_checkpoint_id_caching` at sign time
- `root_at_checkpoint_id_caching` for the anchor
- `truncate_to_checkpoint` on reorg

### Step 6 — Transaction cache

Process each `WalletTx` from the `ScannedBlock`. If it has any received
notes, spent notes, transparent outputs, or outgoing notes → build a
`TransactionRecord`, store it, update derived indexes. If empty → discard.

### Step 7 — Reorg handling

Scanner checks `prev_hash` (librustzcash's `scan_block` already does this
via `prior_block_metadata`). On mismatch: truncate ShardTree, remove
transactions above fork, rebuild derived indexes, re-scan from common
ancestor.

### Step 8 — Spending path

`registry::build_transaction` calls
`tree.witness_at_checkpoint_id_caching` +
`tree.root_at_checkpoint_id_caching` to get the Merkle path and anchor,
then builds/proves/signs the bundle. Replaces the current `todo!()`.

## Upstream References

### librustzcash types

- `ShardTree` — `shardtree` crate, `shardtree::ShardTree`
- `MemoryShardStore` — `shardtree::store::memory::MemoryShardStore`
- `Retention`, `Marking` — `incrementalmerkletree`
- `ScannedBlock<AccountId>` — `zcash_client_backend::data_api::ScannedBlock`
  - File: `zcash_client_backend/src/data_api.rs:2337`
  - Contains: `block_height`, `block_hash`, `block_time`, `transactions: Vec<WalletTx>`, `orchard: ScannedBundles`, `sapling: ScannedBundles`
- `WalletTx<AccountId>` — `zcash_client_backend::wallet::WalletTx`
  - File: `zcash_client_backend/src/wallet.rs:122`
  - Contains: `txid`, `block_index: TxIndex`, `orchard_spends`, `orchard_outputs`, `sapling_spends`, `sapling_outputs`, `transparent_outputs`
- `WalletOutput<Note, Nullifier, AccountId>` — `zcash_client_backend/src/wallet.rs:449`
  - Contains: `index`, `note`, `is_change`, `note_commitment_tree_position`, `nf`, `account_id`, `recipient_key_scope`
- `WalletSpend<Nf, AccountId>` — `zcash_client_backend/src/wallet.rs:409`
  - Contains: `index`, `nf`, `account_id`
- `ScanningKeys` — `zcash_client_backend::scanning::ScanningKeys`
  - `ScanningKeys::from_account_ufvks(ufvks)` derives all IVKs (External + Internal), NKs, and account mappings
  - File: `zcash_client_backend/src/scanning.rs`
- `Nullifiers<AccountId>` — `zcash_client_backend::scanning::Nullifiers`
  - `Nullifiers::unspent(db)` or maintained incrementally via `update_with(&ScannedBlock)`
- `scan_block` (full blocks) — `zcash_client_backend::scanning::full::scan_block`
  - File: `zcash_client_backend/src/scanning/full.rs`
  - Signature: `fn scan_block(params, height, header, vtx, scanning_keys, nullifiers, prior_block_metadata, find_account_for_address) -> Result<ScannedBlock, ScanBlockError>`
- `decrypt_block` — `zcash_client_backend::scanning::full::decrypt_block`
  - File: `zcash_client_backend/src/scanning/full.rs`
  - First half of scanning (batch trial decryption)
- `WalletCommitmentTrees` trait — `zcash_client_backend::data_api::WalletCommitmentTrees`
  - File: `zcash_client_backend/src/data_api.rs:3395`
  - Provides `with_orchard_tree_mut` / `with_sapling_tree_mut` callbacks
  - `ORCHARD_SHARD_HEIGHT = 16` — `zcash_client_backend/src/data_api.rs:165`
  - `SAPLING_SHARD_HEIGHT = 16` — `zcash_client_backend/src/data_api.rs:158`
- `PRUNING_DEPTH = 100` — `zcash_client_backend/src/data_api/ll/wallet.rs`
- `TxIndex(u16)` — `zcash_protocol/src/consensus.rs:135`
- `put_blocks` — `zcash_client_backend/src/data_api/ll/wallet.rs:214`
  - Reference implementation for how scanned blocks are persisted to the tree + wallet

### ShardTree API

- `ShardTree::new(store, max_checkpoints)` — `shardtree/src/lib.rs:84`
- `ShardTree::append(value, retention)` — `shardtree/src/lib.rs:224`
- `ShardTree::insert_frontier(frontier, leaf_retention)` — `shardtree/src/lib.rs:283`
- `ShardTree::checkpoint(checkpoint_id)` — `shardtree/src/lib.rs:412`
- `ShardTree::truncate_to_checkpoint(checkpoint_id)` — `shardtree/src/lib.rs:635`
- `ShardTree::root()` — `shardtree/src/lib.rs:713`
- `ShardTree::root_at_checkpoint_id(checkpoint_id)` — `shardtree/src/lib.rs:1057`
- `ShardTree::root_at_checkpoint_id_caching(checkpoint_id)` — `shardtree/src/lib.rs:1077`
- `ShardTree::witness_at_checkpoint_id(position, checkpoint_id)` — `shardtree/src/lib.rs:1268`
- `ShardTree::witness_at_checkpoint_id_caching(position, checkpoint_id)` — `shardtree/src/lib.rs:1299`
- `MemoryShardStore::empty()` — `shardtree/src/store/memory.rs:21`

### zingolib confirmation

- `ShardTrees` struct — `pepper-sync/src/wallet.rs:1239`
- `ShardTree::new(MemoryShardStore::empty(), MAX_REORG_ALLOWANCE)` — `pepper-sync/src/wallet.rs:1258`
- `SHARD_HEIGHT = 16` — `pepper-sync/src/witness.rs:22`
- `MAX_REORG_ALLOWANCE = 100` — `pepper-sync/src/sync.rs:52`
- `WalletCommitmentTrees` impl — `zingolib/src/wallet/zcb_traits.rs:548`

### Current zns-mint code

- `src/wallet.rs` — current wallet (note tracker, CommitmentTree frontier)
- `src/wallet/selection.rs` — note selection (best-fit waterfall)
- `src/key.rs` — current key derivation (Orchard-only)
- `src/scanner/scan.rs` — current scanner (hand-rolled, `decrypt_outputs_with_keys`)
- `src/scanner/reorg.rs` — current reorg buffer (stub)
- `src/registry.rs` — name chain state (peer of wallet)
- `src/mint.rs` — ZNS payload, Name Note encode/decode, psi/rcm derivation
- `src/zcash/chain.rs` — Zebra block fetcher
- `src/zcash/zebra.rs` — Zebra gRPC + JSON-RPC client, birthday checkpoint

### Orchard key hierarchy

```
SpendingKey (sk)
├── SpendAuthorizingKey (ask)     — signs spend authorization
├── NullifierDerivingKey (nk)     — derives nullifiers
├── OutgoingViewingKey (ovk)      — decrypts notes YOU sent
└── IncomingViewingKey (ivk)      — decrypts notes sent TO you
      └── External scope — payments from others
      └── Internal scope — change notes
```

- IVK trial decryption: try to decrypt `enc_ciphertext` with IVK → note is
  sent to you
- OVK trial decryption: try to decrypt `out_ciphertext` with OVK → note was
  sent by you
- Nullifiers are public — no viewing key needed to SEE them, only to know
  which ones are YOURS (via NK)

### Why OVK is needed

The Treasury sends OTP relay memos to external addresses (the current name
controller). Those are shielded notes sent to third parties. After a
restart, the mint rebuilds from birthday by re-scanning. Without OVK, it
cannot see the OTP relay notes it sent in the past. With OVK, it can recover
them for auditing/verification.

Change notes sent to the mint's own address are caught by IVK (Internal
scope), not OVK.

### Why Internal scope is needed

When the mint spends a note and creates a change note back to itself, the
change note goes to the Internal scope address. The current scanner only
derives External scope IVKs, so it misses change notes. Both scopes must be
checked.