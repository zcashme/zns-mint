# lib.changelog.md

## 2026-09-24

- New harness library for the boot-completion scenario, replacing
  `regtest-harness` (which built the mint without `fake-tee`, treated a
  two-second-surviving process as booted, and activated NU6.x at the wrong
  height). The crate links the mint in-process (`regtest,fake-tee`) and
  drives real Zebra + Zallet from the pinned `zns-integration-tests`
  f28fabf, whose Zebra config already matches boot's transports
  (JSON-RPC 8232, Indexer gRPC 8230) and activation schedule (NU6 at 1,
  NU6.1/6.2/6.3 at 4).
- Vendored the ceremony assembly from `zns-integration-tests`
  `ceremony.rs`/`tx.rs` at f28fabf rather than inventing a third
  transaction serializer, with two deliberate divergences: no
  coinbase-maturity filter on the Treasury input (the funding payment is
  a regular UTXO, not coinbase) and no ceremony-tx cache (the funding
  txid is random, so reproducibility across runs is impossible).
- Wallet-side waits encode probe-verified zallet zebra-backend semantics:
  `z_getbalances`'s `transparent.coinbase.spendable` is the only
  scan-completeness signal (status sync trails the balance scan), the
  spendable shielded balance lives under `ironwood` once NU6.3 is active
  (never `orchard`), and memos are refused to transparent recipients.
