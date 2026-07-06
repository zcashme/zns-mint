# 08 - Chain Sync

## Chain Source

The current implementation uses Zebra's indexer gRPC API:

- `ChainTipChange` for tip/liveness;
- `GetBlock` for full block bytes.

The mint parses full blocks locally and verifies that the recomputed header hash
matches the server-reported hash and requested height. Full consensus remains
Zebra's job.

## Birthday Checkpoint

Scanning from an arbitrary post-Sapling height requires prior tree state. The
current code uses a ZNS-owned JSON birthday checkpoint for block `2_999_999`
and scans from `3_000_000`.

If the birthday checkpoint is missing, the mint can create it from trusted Zebra
JSON-RPC `z_gettreestate`. After boot, wallet state lives in memory and is
rebuilt by replaying from the birthday checkpoint on restart. There is no
durable wallet state across restarts.

## Scanner Boundary

The sync module is a **pure library**: `Block` + UFVKs in, `BlockOutput` out.
It touches no wallet state, decodes no ZNS payload, owns no loop, detects no
reorg. The orchestrator (`main.rs`) owns catch-up, reorg detection, and the
fan-out to `wallet` / `registry` / `treasury`.

The scanner does not know whether a UFVK belongs to Treasury or Registry.
Account roles belong to the caller. It does not know that a memo is a Name
Note payload or a request memo — it surfaces raw decrypted memos, and the
registry / treasury layers classify them.

## Block Output

Scanning one block produces a `BlockOutput` carrying two distinct concerns:

- **`transactions: Vec<TxOutput>`** — the *decrypted subset*: only txs where
  at least one output decrypted to one of our accounts or one of our
  nullifiers was spent. Each `TxOutput` groups received notes (with memo +
  tree position) and spent nullifiers (without original note — the wallet
  resolves NF → original note via its own nullifier index during `apply`).
  Most blocks yield an empty vec.
- **`orchard_commitments` / `sapling_commitments`** — the *full ordered
  commitment stream* for the block: every action's `cmx` and every output's
  `cmu`, wallet-relevant or not. The wallet's `ShardTree` must append all of
  them to stay in sync with the chain's tree; skipping non-wallet actions
  would break every Merkle witness we compute.

## Memo Capture

Upstream `decrypt_block` / `scan_block` drop the memo in their output types
(`WalletOutput` has no memo field), and `BatchResult` that carries the memo
is opaque. The public memo path is `zcash_client_backend::decrypt_transaction`
(`decrypt.rs:123`): takes UFVKs directly, returns `DecryptedTransaction` with
`DecryptedOutput`s carrying `MemoBytes` in-band. Sync calls
`decrypt_transaction` per tx for notes + memos + accounts, and `scan_block`
(upstream) for positions, spends, and the full commitment stream. UFVK →
memo in one upstream call; no fork-specific decryption API, no
`ScanningKeys`-vs-raw-IVK contortions.

Memos are wrapped in the `Memo` newtype (`mint.rs`) at the sync extraction
boundary. `Memo` is a newtype around upstream `MemoBytes` with `Debug`
redacted — ZNS memo contents are shielded user data and must not leak to
logs (AGENTS.md "treat key material as radioactive").

## Memo Detection

Treasury-received Orchard memos are shielded user request data. Sync surfaces
raw decrypted memos to the caller; it must not log them (the `Memo` newtype's
`Debug` is redacted for this reason).

Registry-received Orchard memos that match the Name Note grammar are Name
Note payloads. Sync surfaces them to the caller; the registry layer
classifies them. Registry-received memos that do not match the Name Note
grammar are ignored by the registry path.

## Witness Tracking

Update and release require spending prior Registry Name Notes. Production sync
must track enough Orchard note and Merkle witness state to spend the current
tip Name Note for each live name.

The current dry-run code accepts update/release after OTP but stops at
`NeedsWitness`. That is an explicit missing piece, not protocol policy.

## Reorg Handling

Reorg handling must rewind:

- wallet scan state;
- nullifier state;
- note witnesses;
- confirmed Name Note state;
- submission state for transactions that became unconfirmed.

After rewind, the mint replays the new best chain from the common ancestor.

Confirmed name state must always match the selected best chain.

ZNS uses immediate best-chain finality: the current Zcash best chain is the
truth. Reorgs are handled by rewinding and replaying, not by waiting for a
protocol-level confirmation depth.
