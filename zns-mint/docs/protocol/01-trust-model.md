# 01 - Trust Model

## Parties

### Human

The human chooses a name and a Unified Address. The human is outside the
protocol boundary. ZNS cannot prove that the human chose wisely, protected their
wallet, or inspected attestation correctly.

### User Wallet

The user's wallet controls the Unified Address being bound. It creates shielded
request memos to the Treasury and receives OTP relay memos from the Treasury.
Compromise of a user wallet can affect that user's requests, but must not
affect the namespace globally.

### Registry

The Registry is account 1 derived from the mint seed. It is the only account
authorized to create and spend Name Notes. It runs inside the TEE and owns the
Registry spending key. It is name-notes-only: it does not receive user request
memos, does not collect name payments, and does not relay OTPs. It funds its own
transaction fees from value it holds.

Compromise of the Registry spending key is total namespace compromise. The
entire design exists to keep that key out of operator-readable channels.

### Treasury

The Treasury is account 0 derived from the same seed. It is the user-facing
account: users send name payments to it and send request memos to it. It is
also the account that sends OTP relay memos back to the current binding UA. It
does not authorize name lifecycle transitions.

Treasury compromise costs user-facing funds and the request/OTP-relay channel.
Registry compromise costs the namespace. They share a seed but remain separate
ZIP-32 accounts with separate capabilities, so one account's compromise does
not automatically grant the other's capability.

### Chain Source

The mint currently talks to Zebra's indexer gRPC service. The chain source is
trusted for consensus validation only to the extent Zebra is trusted. The mint
still performs local structural and integrity checks on blocks it consumes.

### Zcash Consensus

Consensus finalizes or rejects transactions. A built and signed Name Note bundle
is only a proposal until included in a block and accepted by the best chain.

### Resolver

A resolver reads chain data and computes `name -> ua`. It should not require
Registry secrets or privileged operator state. Anyone with the Registry UFVK and
chain data can run a resolver.

### Independent Verifier

`zns-verify` is the independent implementation of the ZNS kernel. It recomputes
payload derivations and verifies Name Notes without trusting the mint's local
code path.

## Load-Bearing Boundaries

The critical boundary is operator to Registry key. Operators may deploy,
observe, restart, and inspect logs, but must not be able to read or influence
the Registry spending key through environment variables, command-line flags, or
plaintext config.

The second critical boundary is wallet to Registry. A request memo sent to the
Treasury must not give arbitrary users the ability to update or release someone
else's live name; the OTP relay path through the Treasury is the authorization
gate.

The third boundary is Registry to resolver. Resolvers must be able to verify
the Name Note chain from public chain data instead of trusting the Registry's
database.
