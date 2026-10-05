# lib.changelog.md

## 2026-10-05

- `User::fund_attached` and `User::pay_ua` join the harness: a second
  wallet funded by shielded transfer (no zebrad restart — safe after
  the mint is live), and shielded payments to an arbitrary address.
- `verify::block_txids` and `verify::find_verified_name_note` are
  exported; the slot regression test (`tests/slot_regression.rs`)
  drives K underpaid claims plus one full-price claim through a single
  block, asserts block membership with a dust claim decoded before the
  buyer, and asserts the full-price claim wins the name's slot.

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

## 2026-10-01

- New `happy_path` test (closes #267): the mint's black-box happy path —
  claim → update → release — now lives in this repo. The user is a real
  Zallet wallet; update and release walk the full OTP dance (mint relays
  the challenge on chain to the controller UA, the wallet reads it via
  `z_viewtransaction`, the echo payment answers it); every successor note
  is verified with `zns-verify` and chained by `rcm` (`prev` must equal
  the predecessor's own derived `rcm`, recomputed here from the memo
  fields through `zns_psi_rcm`).
- The `zns-integration-tests` dep is harness-only by rule now:
  `Zebrad`, `Mint`, and `ceremony::{publish, treasury_ua, miner_address,
  FIXTURE_HEIGHT}`. The test phases, the payer (`user.rs`), the verify
  stack, and the bring-up (`stack.rs`) are owned here, so sibling
  harness changes can only break this test mechanically, never
  semantically. `User`'s funding plan is sized for this test's five
  2.0-ZEC payments, not the sibling's four.
- The update's term slot is `none` (carried forward): a forever record
  rejects a term-carrying update (`allows_challenge`), and the happy
  path does not test transfer/rebind — a different-UA update stays a
  separate, adversarial scenario.
- `zallet_bin` became `pub(crate)` so `Stack::start` can skip gracefully
  when zallet is missing locally, mirroring the zebrad skip.
- The OTP read waits for the challenge txid in a mined block and for
  Zallet to scan that height before calling `z_viewtransaction`; both
  update and release use this path.
