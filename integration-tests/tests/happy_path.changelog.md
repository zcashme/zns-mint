# happy_path.changelog.md

## 2026-10-31

- Bootstrap one coinbase-funded wallet, then fund the user through a
  shielded transfer with the existing `User::fund_attached` helper.
  Switch miners only on the empty chain, before any rewards exist.
  This removes the funded-chain restart and the dependency on Zebra's
  periodic non-finalized backup, replacing the extra-1,000-block
  workaround. Assert the funder has the user and Treasury budgets
  before sending either payment.

## 2026-10-12

- Merged `boot_completion.rs` + `happy_path.rs` into one boot-to-release
  e2e; retired `slot_regression.rs` and the fixture-ceremony lane
  (`Stack::start`, cached `publish`, ceremony tx cache). CI folds the two
  integration jobs into one `e2e` job (`needs: ci`).
- Wallet ordering is load-bearing: a zallet whose retrieval queue holds
  txs mined after the first shielded tx never retrieves them. Funder
  mines first, the user's shield is the first shielded tx, the funder's
  daemon starts last; no restart after the user's coins exist.
- Funder is reaped before `Boot::start()`; the user wallet stays alive
  across boot.
