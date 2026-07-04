# 14 - Wallet Design

This document defines the in-memory wallet that `zns-mint` uses to track
Treasury and Registry account state, drive ZNS lifecycle transitions, and feed
transaction assembly.

It is the design source for the wallet layer. When source code implements or
changes behavior described here, update this document in the same change.

## Scope

The wallet is the in-memory cache of chain-derived facts about the two
ZIP-32 accounts the mint derives from one seed:

- **Treasury** (account `0`): the user-facing account. Users send name payments
  to it and send request memos to it. It is the shielded origin of OTP relay
  memos. It funds its own OTP relay transactions and Treasury policy
  transactions (auto-sweep to a configured transparent address, funding the
  Registry account so the Registry can self-fund Name Note fees). It never
  authorizes Name Notes. The Treasury *account* sends OTP relay memos; the
  Treasury *module* does not sign OTP relay transactions (see F10).
- **Registry** (account `1`): name-notes-only. The sole signer for Name Note
  lifecycle transitions. Owns the live Name Note for each name. Funds its own
  Name Note transactions (claim, update, release) from value sent to it by
  the Treasury's Registry-funding policy. Does not receive user request
  memos, does not collect name payments, does not relay OTPs.

The wallet is **not** the source of truth. The Zcash best chain is the source
of truth. The wallet is a cache and recovery log that lets the mint act on
chain-derived observations without recomputing from genesis each block.

The wallet is **in-memory only**. On restart it is rebuilt by replaying from
the static birthday checkpoint. There is no durable wallet state; the wallet
is a pure cache over chain data and is rebuilt from the birthday checkpoint on
every boot.

## Constraints Inherited

The hard constraints from `AGENTS.md`, `02-accounts-and-keys.md`, and
`08-chain-sync.md` apply unchanged:

- No environment variables, CLI flags, or config files. Config is the TEE
  injection story, not wallet config.
- No seed material, spending keys, or decrypted key material stored in wallet
  state. Wallet state is view-only and rebuildable from chain.
- No `Debug`/`Display`/serde for key material. `SpendableNote` does not print
  note plaintext, recipient, or memo contents.
- Best-chain finality: the current Zcash best chain is truth. Reorgs rewind
  and replay, they do not wait for a confirmation depth.
- Use full blocks, not compact blocks. Fail loudly on malformed chain data.

## Features

The wallet provides these capabilities. Each is a narrow, testable feature;
none should be speculatively expanded.

### F1 - Per-Account Note Tracking

The wallet tracks Orchard notes per account. Each account owns its own
`HashMap<[u8; 32], SpendableNote>` keyed by nullifier. There is no shared
note pool; a note belongs to exactly one account because it was decryptable by
exactly one account's IVK.

- Treasury note map: name payments received, plus any other Orchard value the
  Treasury happens to hold. Used to fund OTP relay transactions.
- Registry note map: value-`0` Name Notes with ZNS memos, plus any other Orchard
  notes received by the Registry. The Registry's value notes are what fund Name
  Note transaction fees (Registry self-funds).

`SpendableNote` carries the decrypted `Note`, the `[u8; 512]` memo, the
account id, and the height it was confirmed. It does not carry a witness;
witnesses are tracked separately (F4).

### F2 - Nullifier Tracking

A single shared `Nullifiers<AccountId>` structure records every Orchard
nullifier the wallet has seen on the best chain. The scanner uses it to detect
when a tracked note is spent.

When a nullifier the wallet owns appears in a block, the matching note moves
from the account's unspent map to that account's spent log. Spent notes are
retained in the undo buffer for reorg rewind (F5) and pruned after the undo
window expires.

### F3 - Per-Account Spend Authority Separation

The wallet does not hold spending keys. It holds only viewing-key-derived
observations. Spend authority stays in `key.rs` / `Keys` and is reached only
by the transaction-assembly signing path, never by the wallet, the treasury
module, or the registry module.

The wallet exposes spend *capability* queries:

- `treasury.select_funds(target) -> Vec<&SpendableNote>`: returns Treasury
  notes sufficient to fund a Treasury-origin transaction (OTP relay fee or
  Treasury policy action), without touching keys.
- `registry.select_funds(target) -> Vec<&SpendableNote>`: returns Registry
  value notes sufficient to fund a Registry Name Note transaction, without
  touching keys.
- `registry.current_name_note(name) -> Option<&RegistryNameNote>`: returns
  the live Name Note for a name, ready for the transaction-assembly path to
  spend.

The Treasury spending key is consumed only by the transaction-assembly path
when signing Treasury-origin transactions (OTP relay, auto-sweep, Registry
funding). The Registry spending key is consumed only by the
transaction-assembly path when signing Name Note transactions. The wallet
never sees either key. The treasury module and registry module never see
either key either — they own wallet state and policy, not signing.

### F4 - Witness Tracking For Registry Name Notes

Update and release spend a prior Registry Name Note. Spending requires an
Orchard Merkle witness for the note's commitment, not just the note itself.

The wallet maintains, per live Registry Name Note:

- the decrypted note data the transaction-assembly path needs (`note`, `rho`,
  `rseed`, memo);
- the position of the note's commitment in the Orchard tree;
- an incremental `IncrementalWitness<MerkleHashOrchard, 32>` updated as new
  commitments append.

The wallet maintains the Orchard `CommitmentTree<MerkleHashOrchard, 32>` as
blocks advance. Every output commitment appends to it; every appended
commitment also updates outstanding witnesses.

Only Registry Name Notes that may be spent by the mint need witnesses.
Treasury notes and Registry value notes need witnesses only when they are
selected for a spend; the witness can be reconstructed at spend-select time
from the current tree plus the note's position, or maintained incrementally
like Registry notes. The decision is deferred to the funding-implementation
slice.

### F5 - Reorg Rewind

The wallet keeps a bounded `VecDeque<UndoState>` (currently capped at 100
blocks). Each entry records what a block changed:

- nullifiers added to the shared nullifier set;
- notes added to either account's unspent map;
- notes removed from either account's unspent map (because their nullifier
  appeared);
- witness appends to outstanding Registry Name Note witnesses;
- prior `CommitmentTree` snapshot;
- prior `BlockMetadata` (height, hash, sapling/orchard tree sizes).

A reorg rewinds the wallet to a common ancestor height by popping undo
entries back to that height and replaying. Rewind also reverts confirmed
Name Note state (owned by the registry layer, see F7) and submission state.

Reorg application is not wired yet; the data shape is intentionally present
so the rewind path is mechanical when wired.

### F6 - Birthday Checkpoint Restore

On boot, the wallet is initialized from the static birthday checkpoint
(`src/checkpoints/birthday.json`, currently block `2_999_999`):

- `CommitmentTree` is seeded with the stored Orchard final state.
- `Nullifiers` is empty (the scanner will repopulate it from `3_000_000`).
- Both account note maps are empty.
- `prior_block_metadata` is set from the checkpoint.

The wallet then scans `3_000_000..=tip` to rebuild in-memory state. No
durable wallet state is read or written. Restart cost is bounded by chain
length since the birthday, not by wallet activity.

### F7 - ZNS-Specific Registry Logic

The Registry account is special: its value-`0` notes with ZNS memos are Name
Notes, and the wallet layer exposes a typed view over them. Its value notes
(non-zero, no ZNS memo) are funding notes, tracked by F1.

A `RegistryNameNote` is a `SpendableNote` plus parsed ZNS payload fields:

- `action` (`claim` / `update` / `release`);
- `name` (canonical lowercase DNS label);
- `ua` (Unified Address string, empty only for committed release notes);
- `prev_rcm` (32-byte previous chain value);
- `rcm` (this note's trapdoor; becomes the next link's `prev_rcm`).

The wallet does not parse the memo grammar itself; it asks the protocol
kernel (`payload.rs`) to parse the 512-byte memo into the typed fields. The
wallet stores the typed result so the registry layer can ask
`registry.name_chain(name)` and get the ordered chain of Name Notes for a
name.

The wallet enforces the per-name chain rule: only one live Name Note per
name. When a new Name Note for an existing name appears, the prior note's
nullifier must have appeared in the same block or an earlier block on the
best chain. A Name Note whose nullifier appears is marked spent and removed
from the live map; it stays in the undo buffer and the name's history.

### F8 - Treasury-Specific Request Surface

The Treasury account is the user-facing surface. Its wallet view is implemented
by the `treasury.rs` module; see `15-treasury-module.md` for the full design.
The wallet exposes:

- `treasury.unspent_notes() -> &HashMap<...>`: funds available for OTP relay
  funding and Treasury policy actions.
- `treasury.select_funds(target) -> Vec<&SpendableNote>`: select notes to
  fund an OTP relay transaction or a Treasury policy transaction
  (auto-sweep, Registry funding).
- `treasury.requests_in_block(height) -> &[RequestMemo]`: raw 512-byte
  Treasury-received memos classified by the treasury module as
  claim/update/release requests.

The Treasury does not have a Name Note view. The Registry does not have a
request surface.

### F9 - Observation Surface For Higher Layers

The wallet exposes a narrow observation interface consumed by the run loop,
the treasury module, and the registry module — not by `main.rs`:

- `wallet.treasury().unspent_notes() -> &HashMap<...>`
- `wallet.treasury().select_funds(target) -> Vec<&SpendableNote>`
- `wallet.treasury().requests_in_block(height) -> &[RequestMemo]`
- `wallet.registry().name_chain(name) -> Option<&[RegistryNameNote]>`
- `wallet.registry().current_name_note(name) -> Option<&RegistryNameNote>`
- `wallet.registry().witness_for(name) -> Option<&IncrementalWitness<...>>`
- `wallet.registry().select_funds(target) -> Vec<&SpendableNote>`

`main.rs` never reaches into the wallet directly. It drives `scan_to_tip`
or the future live loop and lets the treasury/registry modules pull from the
wallet.

### F10 - Treasury Policy vs OTP Relay vs Auth — Separation

Three distinct concerns touch the Treasury account. They must not collapse
into one module:

- **`auth.rs`** owns OTP *credential policy*: issuance, verification, expiry,
  one-time consumption, and OTP relay memo byte construction. It is the sole
  OTP authority. It does not sign or broadcast anything.
- **`treasury.rs`** owns Treasury *wallet state and Treasury policy*: the
  Treasury note map, balance, `select_funds` for Treasury-origin transactions,
  auto-sweep to a configured transparent address, and funding the Registry
  account. It does not sign OTP relay transactions. It does not own OTP
  credentials. See `15-treasury-module.md` for the full design.
- **transaction-assembly (future)** owns *signing and broadcast*: it takes
  funds selected by the treasury module, an OTP memo produced by `auth`, and
  the Treasury spending key, and builds/funds/signs/broadcasts the OTP relay
  transaction. It is the only consumer of the Treasury spending key for OTP
  relay. It also signs Treasury policy transactions (auto-sweep, Registry
  funding) and Registry Name Note transactions (using the Registry spending
  key).

The Treasury account is the shielded origin of OTP relay memos; the Treasury
module is not the signer of OTP relay transactions.

## Data Structures

The wallet is two `Account` instances plus shared chain state:

```text
struct Wallet {
    treasury: TreasuryAccount,
    registry: RegistryAccount,
    tree: CommitmentTree<MerkleHashOrchard, 32>,
    nullifiers: Nullifiers<AccountId>,
    undo_buffer: VecDeque<UndoState>,
    prior_block_metadata: Option<BlockMetadata>,
}

struct Account {
    account_id: AccountId,            // 0 for treasury, 1 for registry
    unspent: HashMap<[u8; 32], SpendableNote>,
}

struct TreasuryAccount {
    inner: Account,                  // account_id = 0
    requests: VecDeque<(BlockHeight, RequestMemo)>,
}

struct RegistryAccount {
    inner: Account,                  // account_id = 1
    names: HashMap<NameKey, NameChain>,
}

struct NameChain {
    live: Option<RegistryNameNote>,   // spent live note is None
    history: Vec<RegistryNameNote>,  // ordered, pruned past undo window
}

struct SpendableNote {
    account_id: AccountId,
    note: Note,
    memo: [u8; 512],
    confirmed_height: BlockHeight,
}

struct RegistryNameNote {
    note: SpendableNote,
    action: Action,                   // Claim | Update | Release
    name: NameKey,
    ua: String,
    prev_rcm: [u8; 32],
    rcm: [u8; 32],
    witness: IncrementalWitness<MerkleHashOrchard, 32>,
}

struct UndoState {
    height: BlockHeight,
    added_nullifiers: Vec<[u8; 32]>,
    spent_notes_treasury: Vec<SpendableNote>,
    spent_name_notes_registry: Vec<RegistryNameNote>,
    witness_appends: Vec<(NameKey, MerkleHashOrchard)>,
    prior_tree: CommitmentTree<MerkleHashOrchard, 32>,
    prior_block_metadata: Option<BlockMetadata>,
}
```

`NameKey` is a newtype over the canonical lowercase DNS label, not a raw
`String`, so two different casings cannot both index the same name.

## Syncing

Sync is the process of bringing the wallet from its current scan cursor to
the current best-chain tip. The scanner (future module; `sync.rs` was
deleted) is the scanner;
the wallet is its sink.

### Sync Flow

1. **Birthday restore** (F6): if `prior_block_metadata` is `None`, sync
   asks `zcash::zebra::JsonRpc` to load or create the birthday checkpoint
   for block `SCAN_START_HEIGHT - 1` and seeds the wallet's tree and
   `prior_block_metadata`.
2. **Catch-up**: sync fetches full blocks from `zcash::chain::Reader` for
   every height from `SCAN_START_HEIGHT` to tip, in order, and hands each
   verified block to `Wallet::scan_verified_block`.
3. **Live**: the future run loop (Slice 7) replaces the one-shot catch-up
   with a `ChainTipChange` subscription. Each new best-chain block is fed
   to the same `scan_verified_block` path; reorgs rewind via the undo
   buffer before replaying.

### One Pass, Both Accounts

`scan_verified_block` runs `decrypt_block` + `scan_block` once per block
with both accounts' UFVKs in `ScanningKeys`. There is one scan pass per
block, not one per account. This is required by the librustzcash scanner
API (a single `ScanningKeys` set) and is also cheaper.

The wallet then fans the scan output out to the two `Account` instances by
`account_id` on each scanned output. The scanner is account-role
agnostic; the wallet decides which account owns each output and routes
Treasury-received memos to the treasury request queue and Registry-received
ZNS memos to the name chain.

### Per-Block Update Order

Inside `scan_verified_block`, the update order is load-bearing:

1. Decrypt memos for Orchard-bearing transactions (separate
   `decrypt_transaction` pass, as today). Memos decryptable by the Treasury
   UFVK are Treasury-received request memos; memos decryptable by the
   Registry UFVK that match the ZNS Name Note grammar are Name Note memos.
2. `decrypt_block` + `scan_block` produce the scanned block.
3. Apply spends first: for each nullifier the wallet owns, move the note
   from unspent to the undo buffer. If the spent note is a live Registry
   Name Note, mark the name's `live` as `None` and append to `history`.
4. Apply outputs: for each scanned output, insert into the owning account's
   unspent map. If the output is a Registry Name Note, parse the memo via
   `payload.rs`, insert into the name chain, and start a witness. If the
   output is a Treasury-received memo, route the memo to the treasury
   request queue.
5. Append every Orchard commitment in the block to `tree` and to every
   outstanding Registry witness.
6. Update `nullifiers`, `prior_block_metadata`, and push `UndoState`.

Applying spends before outputs matters: in a single transaction, the same
action can spend the prior live Name Note and create the new one. Spending
first keeps the per-name chain rule (`only one live note per name`)
trivially satisfiable within a block.

### Reorg Rewind Path

When the run loop detects that the best chain's parent hash disagrees with
the wallet's `prior_block_metadata` hash, it:

1. Computes the common ancestor height with Zebra.
2. Pops `UndoState` entries from the back of `undo_buffer` until the
   wallet cursor is at the common ancestor, reverting each entry in
   reverse order: restore spent notes, remove added nullifiers, restore
   the prior tree, restore prior `prior_block_metadata`, un-spend
   Name Notes, drop appended witness entries, drop treasury requests
   from that height.
3. Replays fresh blocks from Zebra through `scan_verified_block`.

This rewind path is not wired yet. The `UndoState` shape is intentionally
complete so wiring is mechanical.

## Integration With zns-mint

### Module Boundaries

- `src/wallet.rs` (new): the `Wallet`, `Account`, `TreasuryAccount`,
  `RegistryAccount`, `SpendableNote`, `RegistryNameNote`, `NameChain`,
  `UndoState` types and their mutation methods. No chain I/O, no key
  derivation, no ZNS memo parsing beyond asking `payload.rs` to parse.
  **Note:** the current implementation holds note/tree/nullifier state only;
  the `TreasuryAccount`/`RegistryAccount`/`NameChain`/`UndoState` shapes
  below are the target design. Name-chain state lives in `src/registry.rs`
  as a peer `Registry` newtype, not as a field of `Wallet` — see
  `src/registry.rs`.
- `src/treasury.rs` (new stub): the Treasury-specific layer over the
  wallet. Owns Treasury wallet state view, Treasury policy (auto-sweep to a
  transparent address, funding the Registry account), Treasury
  `select_funds`, request memo classification, and claim payment detection.
  Does NOT sign OTP relay transactions. Does NOT own OTP credentials.
  No spending keys. See `15-treasury-module.md`.
- `src/auth.rs` (existing, currently unwired): the sole OTP credential
  authority. Owns issuance, verification, expiry, one-time consumption, and
  OTP relay memo byte construction. Does NOT sign or broadcast. No spending
  keys.
- scanner (future, no module yet — `sync.rs` was deleted): the scanner.
  Owns `scan_verified_block` and `scan_to_tip`. Becomes a pure pipeline from
  `zcash::chain::Reader` blocks into `wallet::Wallet::insert_note` /
  `remove_note`.
- `src/payload.rs` (not in current tree, and the user has explicitly rejected
  reintroducing it): parses 512-byte memos into typed ZNS fields. Memo
  parsing now lives inline in the module that needs it (treasury parses
  request memos, auth encodes OTP memos, registry parses Name Note memos).
- transaction-assembly (future, no module yet): the only consumer of both
  spending keys. Builds, funds, signs, and broadcasts Treasury-origin
  transactions (OTP relay, auto-sweep, Registry funding) and Registry Name
  Note transactions (claim, update, release).
- `src/registry.rs`: owns the name-chain state as a peer `Registry` newtype
  over `HashMap<Name, Tip>`, not as a field of `Wallet`. Consumes the name
  chain to apply confirmed Name Notes and authorize transitions. Calls
  `auth` for OTP verification. The scanner takes `&mut Registry` and
  `&mut Wallet` by reference per block; nothing owns both as nested state.
- `main.rs`: orchestrates. Does not touch wallet internals, does not sign,
  does not own OTP credentials.

### What Moved Out Of sync.rs (Now Deleted)

`sync.rs` was deleted after its wallet state moved to `wallet.rs`. The
former `sync.rs::Wallet` mixed scanner state, note maps, undo buffer, and
tree in one struct; that is now split:

- note maps, undo buffer, tree, nullifiers move to `wallet.rs` as the
  `Wallet` struct (done).
- `scan_verified_block` and `scan_to_tip` will be reintroduced in a future
  scanner module as free functions taking `&mut wallet::Wallet` plus the
  block.
- birthday-checkpoint seeding will be reintroduced with the scanner (it is
  chain I/O and scanner bootstrap, not wallet state).

### No Durable Wallet State

This design is in-memory only. The wallet is a pure cache over chain data,
rebuilt from the birthday checkpoint on every boot. There is no `store.rs`
layer, no on-disk snapshot, and no cross-restart wallet state. Restart cost
is bounded by chain length since the birthday, not by wallet activity.

## Open Questions

- **Witness strategy for funding notes**: maintain incrementally like
  Registry Name Notes, or reconstruct at spend-select time from the current
  tree and the note's position? Deferred to the funding-implementation
  slice. Applies to both Treasury OTP relay funding and Registry Name Note
  fee funding.
- **History pruning**: how long does a spent Name Note stay in `history`
  after its nullifier appears? The undo window is a floor; an upper bound
  is open.
- **Witness reconstruction on reorg**: when a reorg drops the block that
  appended a commitment, the witness must rewind too. The undo buffer
  records `prior_tree`, but reverting an `IncrementalWitness` may require
  rebuilding it from the note's position on the prior tree. Needs
  validation against `incrementalmerkletree` API.
- **Cross-account authorization handoff**: a claim requires both a Treasury
  payment check and a Registry Name Note issuance. The handoff between the
  treasury layer (which sees the payment) and the registry layer (which
  mints the note) needs an explicit in-mint interface so the Registry does
  not mint a Name Note for an unpaid claim. Not yet specified.
- **Two-wallet vs one-wallet-with-two-accounts**: this design picks one
  `Wallet` owning two typed account instances, because they share one
  `CommitmentTree`, one `Nullifiers`, and one undo buffer. The user raised
  "two wallets"; the shared tree/nullifier state makes a single struct with
  two typed account views the cleaner split. Revisit if the Treasury path
  turns out to need independent reorg windows.

## Related Files

- `docs/protocol/02-accounts-and-keys.md` - account and key model.
- `docs/protocol/03-name-note.md` - Name Note artifact.
- `docs/protocol/04-memo-grammar.md` - Treasury request and OTP relay memo
  formats.
- `docs/protocol/06-authorization.md` - claim/update/release flow including
  the Treasury OTP-relay path.
- `docs/protocol/08-chain-sync.md` - sync, checkpoint, reorg expectations.
- `docs/protocol/09-transaction-assembly.md` - Registry self-funds Name Note
  fees; Treasury funds OTP relay fees.
- `docs/protocol/12-programming-model.md` - the three-layer model this
  wallet lives in.
- `docs/protocol/13-implementation-slices.md` - slices 2, 3, and 4 are
  the wallet, sync-output, and witness-tracking slices this design
  implements.
- `src/wallet.rs` and `src/wallet.rs.context.md` — the wallet state (done).
- `src/treasury.rs` and `src/treasury.rs.context.md` — Treasury wallet state
  and policy layer stub.
- `src/auth.rs` and `src/auth.rs.context.md` - OTP credential policy; sole
  OTP authority; does not sign or broadcast.
- `src/key.rs` and `src/key.rs.context.md` - the only place spending keys
  live; the wallet, treasury, and registry modules never see them; only the
  transaction-assembly path consumes them.