# 14a - Wallet Storage Rationale

This document records *why* the wallet is in-memory only with no durable
state, so the decision is not re-litigated without new information.

It pairs with `14-wallet-design.md`, which defines *what* the wallet is.
This document explains *why* that is the right design.

## The Question

Should `zns-mint` persist wallet state (notes, nullifiers, witnesses, scan
height) to disk using an embedded database (SQLite, RocksDB, etc.), or
operate with an in-memory hash map that is rebuilt from the birthday
checkpoint on every boot?

## Answer

In-memory only. No database. No durable wallet state beyond the encrypted
seed and the static birthday checkpoint.

## Reasoning

### The blockchain is the source of truth

The wallet is a cache, not a ledger. Every note, nullifier, witness, and
balance entry is derivable from the chain by trial-decrypting shielded
outputs with the account viewing keys. Nothing the wallet holds is
irreplaceable — if the hash map is wiped, scanning from the birthday
checkpoint rebuilds it identically.

The only irreplaceable datum is the seed phrase, which is injected by the
TEE and persisted outside the wallet entirely.

### The mint is an always-on daemon next to a full node

`zns-mint` runs as a daemon on a VPS alongside a Zebra full node. It is not
a mobile app that the OS kills. It is not a desktop app the user closes.
It is not a CLI the user invokes and exits. It starts once and runs
indefinitely, scanning every new block as it arrives.

This means:

- The hash map is **always warm** during normal operation.
- Crashes are rare (VPS uptime, no user interaction, no OS lifecycle kills).
- When a crash does occur, Zebra is already running with the full chain
  locally — no network fetch, just CPU-bound trial decryption.

### Restart cost is bounded and acceptable

On restart, the wallet scans from the birthday checkpoint (currently block
`2_999_999`) to the chain tip. The cost is:

- O(blocks since birthday) trial decryptions.
- Bounded by chain length, not by wallet activity.
- Automated, no user action required.

For a mint that started recently, this is seconds. For a long-running mint,
it is minutes. In either case, it happens rarely (only on crash or planned
restart) and the wallet comes back online on its own.

### A database would add complexity for no benefit in this context

An embedded database (SQLite, RocksDB) would let the wallet persist its
scan results and resume from a checkpoint instead of the birthday. But:

- It adds a dependency, a schema, serialization logic, and migration
  concerns.
- It adds disk I/O on every block scan (write notes, nullifiers,
  witnesses, checkpoint).
- It introduces a second source of truth that must be kept consistent with
  the chain (cache/database inconsistency bugs).
- Its sole benefit — faster restart — matters only on the rare crash, and
  the restart is already automated and bounded.

For a mobile wallet that starts and stops constantly, a database is
essential. For an always-on daemon next to a full node, it is insurance
against a rare event that is already cheap to recover from.

### Persisting scan height alone is not useful

A natural thought: "persist just the scan height (one integer) so restart
resumes from the checkpoint instead of the birthday." This does not work
without also persisting the notes and nullifiers discovered up to that
height. If the hash map is gone on crash, scanning from the checkpoint
yields only notes from that point forward — all older notes are missing
and the balance is wrong.

Either you persist everything (a database) or nothing (rescan from
birthday). Half-persisting is a bug.

## What Is Persisted

| Data | Persisted? | Where | Why |
|------|-----------|-------|-----|
| Seed phrase / spending keys | Yes (TEE-injected) | TEE / key injection | Irreplaceable — without it, funds are gone forever |
| Birthday checkpoint | Yes (static) | `src/checkpoints/birthday.json` | Bounded rescan start point; changes only on wallet creation |
| Notes, nullifiers, witnesses | **No** | In-memory hash map | Reconstructable from chain via trial decryption |
| Scan height | **No** | In-memory | Reconstructable — rescan starts from birthday |
| Transaction history | **No** | In-memory hash map | Reconstructable from chain |
| Name chain state | **No** | In-memory hash map | Reconstructable from chain |
| Balances | **No** | Computed from notes | Derived, never stored |

## When This Decision Should Be Revisited

This architecture assumes:

1. The mint runs as an always-on daemon.
2. A Zebra full node is available locally with the full chain.
3. Restarts are rare and acceptable.
4. The wallet birthday is recent enough that rescans are bounded.

If any assumption changes — for example, the mint needs to support cold
start on a remote/light node, or the birthday drifts far enough back that
rescans take hours — then reconsider durable wallet state. Until then,
in-memory is simpler, has fewer failure modes, and is sufficient.

## Related Files

- `docs/design/14-wallet-design.md` — the wallet design this rationale
  supports.
- `docs/design/08-chain-sync.md` — sync, checkpoint, and reorg
  expectations.
- `docs/protocol.md (§2–3)` — key model; seed injection via
  TEE.