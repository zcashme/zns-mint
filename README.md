# zns-mint

The ZcashName registry minter — the service that turns name requests into
on-chain Name Notes.

A *Name Note* is a self-sent Orchard note whose commitment randomness is not
random: its `(rcm, ψ)` are a deterministic hash of `(action, name, ua,
prev_rcm)`. The chain commits to that hash through the note's `cmx`, so the
`(name → ua)` binding can be recomputed and checked directly against the chain
(see `zns-verify`). This workspace is the service that produces those notes.

## Crates

| crate | role |
|-------|------|
| `core`   | shared types, the registry DB, memo parsing — no cryptographic deps |
| `host`   | the daemon: chain I/O, request intake, the treasury wallet, orchestration |
| `signer` | builds, proves, and signs the Orchard bundles; holds the spend key |
| `auth`   | OTP challenge-response for UPDATE / RELEASE |

The split is the design, not filing. `host` is the large, network-facing
surface. `signer` is small and is the only thing that touches the spend key.
`host` *proposes* — "mint this name, spending this treasury note." `signer`
*decides*: it re-derives the binding itself, constructs every output to the
registry's own address or to one fixed cold address, checks the fee and a
per-window rate limit, and signs. There is no input from `host` that makes
`signer` send value anywhere it didn't already choose.

## Treasury

Minting pays a fee, so the registry spends. It self-funds from a small hot
float and moves the excess to a cold address; the cold address and the limits
live in the `signer`, not in anything `host` can rewrite. The spend key is held
only in memory and re-derived per signature. The float it guards is small by
construction, and the rate limit bounds how fast anything can move.

## Stack

orchard 0.14 (the `zns-orchard` fork) · zcash_primitives 0.28 ·
zcash_client_backend 0.23 / zcash_client_sqlite 0.21 (treasury note-state).

## Status

Research code — **not deployed.** In place and tested: the lightwalletd
transport and the policy-gated signer (request intake, the funded-mint and
sweep builders, the spend gate). Not yet built: the treasury note-state wiring,
the daemon supervision loop, in-enclave key sealing + attestation, and an
external audit.

## Running against regtest

`zebrad` serves JSON-RPC; the minter speaks the lightwalletd gRPC, so run a
`lightwalletd` in front of it:

```sh
zebrad --config zebra-regtest/zebrad.toml start
lightwalletd --no-tls-very-insecure --grpc-bind-addr 127.0.0.1:9067 \
  --zcash-conf-path zebra-regtest/lwd/zcash.conf \
  --data-dir zebra-regtest/lwd/data

# exercise the transport against the live chain
cargo test -p zns-host scanner::regtest -- --ignored --nocapture
```
