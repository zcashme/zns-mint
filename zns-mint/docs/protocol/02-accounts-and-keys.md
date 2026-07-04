# 02 - Accounts And Keys

## Seed

The mint derives its accounts from one seed. In production, the seed must arrive
as an encrypted blob bound to the TEE measurement. It must never be supplied as
an environment variable, CLI argument, plaintext file, or operator-readable
configuration.

Plaintext seed material exists only long enough to derive the accounts and must
be zeroized immediately afterward.

## Account Assignment

- Treasury: ZIP-32 account `0`
- Registry: ZIP-32 account `1`

The account mapping is protocol-operational convention, not a cryptographic
necessity. Changing it would require an explicit migration plan because it
changes which keys receive user funds and which keys authorize names.

## Treasury Capability

The Treasury is the user-facing account. It is the address users send funds to
(name payments) and the address users send request memos to. It is also the
account that sends OTP relay memos back to the current binding UA.

Treasury never authorizes Name Notes. Treasury signing belongs in funding and
OTP-relay transaction code, not in the protocol kernel.

Because the Treasury receives user request memos and funds name payments, the
Treasury UFVK is the one a wallet UI shows to users as "the ZNS address".

## Registry Capability

The Registry key creates and spends Name Notes. It is the sole signer for name
lifecycle transitions. It is name-notes-only: it does not receive user request
memos, does not collect name payments, and does not relay OTPs.

The Registry also funds its own transaction fees. There is no Treasury fee
funding path. Name Note transactions are signed and funded entirely from the
Registry account.

The Registry spending key must:

- stay private inside `Keys`;
- be exposed only through narrow crate-private accessors;
- be consumed only by the Registry transaction signing path;
- never implement `Debug` or `Display`;
- never be logged, serialized, cloned for convenience, or passed through generic
  config/state structures.

## Treasury Spending Key

The Treasury key signs Treasury-origin transactions: OTP relay memos (the
Treasury account is the shielded origin of OTP relay) and Treasury policy
transactions (auto-sweep to a configured transparent address, funding the
Registry account). The Treasury module owns Treasury wallet state and policy,
but does **not** sign OTP relay transactions itself — signing is the job of the
transaction-assembly path, which is the only consumer of the Treasury spending
key, exactly analogous to how the Registry signing path is the only consumer of
the Registry spending key.

Both spending keys follow the same handling rules: never `Debug`/`Display`,
never logged, never serialized, crate-private accessors only.

## Viewing Keys

Unified full viewing keys are used for scanning. They reveal wallet-relevant
chain data and should not be logged. They are less dangerous than spending keys
but are still key material.

The scanner should accept a UFVK and remain account-role agnostic. Treasury and
Registry roles are assigned by the caller.

## Compromise Scope

Treasury compromise costs user-facing funds and the request/OTP-relay channel.
Registry compromise costs the namespace. They share a seed but remain separate
ZIP-32 accounts with separate capabilities, so one account's compromise does not
automatically grant the other's capability.