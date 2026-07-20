# 12 - Programming Model

This document explains how to program `zns-mint` as software.

The best working term is **attested issuer**:

`zns-mint` is the attested issuer for ZNS Name Notes. The Zcash best chain is
the source of truth. The Registry spending key is the write authority. The mint
is the runtime that holds that authority inside the TEE, watches chain state,
applies ZNS policy, and issues new zero-value Name Notes.

It is useful to think in three layers:

- chain I/O: Zebra blocks, tips, and transaction submission;
- wallet state: Treasury and Registry scanning, notes, nullifiers, witnesses;
- ZNS state: names, requests, OTPs, in-flight transactions.

The Treasury is the user-facing account: it receives name payments and request
memos, and sends OTP relay memos. The Registry is name-notes-only and
self-funds its Name Note transaction fees.

## System Shape

```mermaid
flowchart LR
    UserWallet[User wallet] -->|shielded request memo| Zcash[(Zcash best chain)]

    Zebra[Zebra gRPC/indexer] -->|tip stream + full blocks| Mint[zns-mint\nattested issuer]
    Zcash --> Zebra

    Mint -->|scan checkpoints\nwallet state\nname index\nin-flight txs| RAM[(In-memory state)]
    RAM --> Mint

    Mint -->|Registry signed\nName Note txs| Zebra
    Mint -->|OTP relay txs| Zebra
    Zebra -->|broadcast / submit path| Zcash

    Resolver[Resolver] -->|Registry UFVK + chain data| Zebra
    Resolver -->|name -> UA| Client[Client]
```

Notes:

- The resolver is not privileged. Anyone with the Registry UFVK and chain data
  can scan Name Notes and compute `name -> ua`.
- The mint holds no durable state. All mint state is in-memory, rebuilt from
  the birthday checkpoint by replaying the best chain on every boot.
- Zebra is the chain interface. The current code uses Zebra gRPC for tips and
  full blocks. Transaction submission should also be wired through the approved
  Zebra surface available to the deployment.

## Main Components

```mermaid
flowchart TB
    Main[main.rs\nphase orchestrator]
    Boot[boot.rs\nchain liveness + key derivation]
    Sync[sync.rs\nblock scanner]
    Wallet[wallet store\nnotes/nullifiers/witnesses]
    Treasury[treasury.rs\nTreasury wallet + policy]
    Registry[registry.rs\nZNS state machine]
    Payload[payload.rs\nprotocol kernel]
    Auth[auth.rs\nOTP credential policy]
    Tx[tx assembly\nfees + sighash + submit]
    Metrics[metrics.rs\nPrometheus]
    RAM[(in-memory state)]
    Zebra[Zebra]

    Main --> Boot
    Main --> Sync
    Main --> Treasury
    Main --> Registry
    Main --> Metrics

    Boot --> Zebra
    Boot -->|Accounts| Main

    Sync --> Zebra
    Sync --> Wallet
    Wallet <--> RAM

    Treasury --> Wallet
    Treasury --> Tx
    Registry --> Payload
    Registry --> Auth
    Registry --> Tx
    Registry --> RAM

    Tx --> Zebra
```

`main.rs` should stay boring. It should wire phases together and keep logs
redacted. The protocol decisions belong in `payload`, `registry`, `auth`,
`treasury`, and the future transaction-assembly module.

## In-Memory State Held By The Mint

The mint holds operational state in memory, not secrets. Nothing below is
durable; all of it is rebuilt from the birthday checkpoint by replaying the
best chain on every boot.

```mermaid
erDiagram
    CHAIN_CHECKPOINT {
        int height
        bytes block_hash
        int sapling_tree_size
        int orchard_tree_size
    }

    WALLET_NOTE {
        text account_role
        bytes txid
        int action_index
        int height
        bytes nullifier
        bool spent
    }

    NOTE_WITNESS {
        bytes note_id
        int height
        bytes merkle_path
    }

    NAME_STATE {
        text name
        text ua
        text action
        bytes tip_rcm
        bytes txid
        int height
    }

    IN_FLIGHT_TX {
        bytes txid
        text kind
        text status
        int first_submit_height
        int retry_count
    }

    CHAIN_CHECKPOINT ||--o{ WALLET_NOTE : anchors
    WALLET_NOTE ||--o| NOTE_WITNESS : has
    WALLET_NOTE ||--o| NAME_STATE : may_update
    NAME_STATE ||--o{ IN_FLIGHT_TX : causes
```

Things not held:

- plaintext seed;
- Registry spending key;
- Treasury spending key;
- decrypted key material;
- plaintext OTPs after expiration.

Pending OTPs live in memory because they expire after 30 minutes and the
service is expected to run continuously with metrics and logs.

## Block Processing Pipeline

```mermaid
sequenceDiagram
    participant Zebra
    participant Mint
    participant RAM
    participant Registry
    participant TxBuilder

    Zebra->>Mint: next best-chain block
    Mint->>Mint: parse and verify block shape
    Mint->>RAM: load previous scan state
    Mint->>Mint: scan Treasury and Registry keys (one pass)
    Mint->>RAM: save notes, nullifiers, witnesses
    Mint->>Registry: detected Registry Name Note memos
    Mint->>Treasury: detected Treasury request memos
    Registry->>Registry: apply confirmed Name Notes first
    Treasury->>Treasury: classify request memos (claim/update/release)
    Treasury->>Registry: authorize against name state
    Registry->>TxBuilder: ready claim / update / release work
    Treasury->>TxBuilder: ready OTP relay work
    TxBuilder->>RAM: record in-flight tx
    TxBuilder->>Zebra: submit transaction
    Mint->>RAM: advance checkpoint
```

The ordering matters. Confirmed Name Notes update name state before Treasury
request memos in the same processing pass are allowed to depend on that state.

## Request Handling

```mermaid
flowchart TD
    Memo[Treasury request memo] --> Classify{classify memo}

    Classify -->|Name Note at Registry| Apply[apply confirmed Name Note\nto name state]
    Classify -->|claim request| Claim{is name free or released?}
    Classify -->|update request| Update{has OTP?}
    Classify -->|release request| Release{has OTP?}
    Classify -->|not ZNS| Ignore[ignore]

    Claim -->|yes| BuildClaim[build zero-value claim Name Note tx\nfunded by Registry]
    Claim -->|no| RejectClaim[reject]

    Update -->|no| IssueUpdateOtp[Treasury sends OTP to current UA]
    Update -->|yes| VerifyUpdateOtp[verify 30 minute OTP]
    VerifyUpdateOtp --> BuildUpdate[build update Name Note tx\nfunded by Registry]

    Release -->|no| IssueReleaseOtp[Treasury sends OTP to current UA]
    Release -->|yes| VerifyReleaseOtp[verify 30 minute OTP]
    VerifyReleaseOtp --> BuildRelease[build release Name Note tx\nfunded by Registry]
```

Update and release OTPs are sent from the Treasury to the current UA. That is
the ownership check: the party that can receive the shielded memo at the current
binding can complete the transition.

## Coding Order

The detailed breakdown lives in
[13-implementation-slices.md](13-implementation-slices.md).

At a high level:

1. restore a green compile/test baseline;
2. define the in-memory wallet data model;
3. scan blocks into wallet observations;
4. track Registry Name Note witnesses;
5. assemble real transactions, with Registry self-funding Name Note fees and
   Treasury funding OTP relay fees;
6. submit transactions through Zebra;
7. replace one-shot scans with a live best-chain loop;
8. add Prometheus metrics once state transitions are explicit;
9. replace the dev zero seed with TEE-bound seed blob intake.

Each step should leave `main.rs` as a phase orchestrator. If a step makes
`main.rs` understand protocol details, that logic belongs in a module.
