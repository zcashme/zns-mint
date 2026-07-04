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

The scanner should turn verified full blocks into account observations. It
should not know whether a UFVK belongs to Treasury or Registry. Account roles
belong to the caller.

## Memo Detection

Treasury-received Orchard memos are shielded user request data. Sync may
surface raw 512-byte Treasury memos to the treasury layer, but it must not log
them.

Registry-received Orchard memos that match the Name Note grammar are Name
Note payloads. Sync may surface them to the registry layer, but it must not
log them. Registry-received memos that do not match the Name Note grammar are
ignored by the registry path.

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
