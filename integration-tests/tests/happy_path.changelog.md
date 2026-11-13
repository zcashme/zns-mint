# happy_path.changelog.md

## 2026-11-13 — No `boot.birthday` assertion (#489)

- `Boot` carries no birthday, so `assert_eq!(boot.birthday, tip_height)`
  is gone. Boot still refuses an anchor not mined at the manifest
  birthday, and the test still asserts the full ceremony pool.

## 2026-11-10

- The fixture is `zns_integration_tests::fixture`: the mint's e2e crate
  and the harness are one crate in this workspace's `integration-tests/`.
  The test body is unchanged.

## 2026-11-07

- The happy path claims, updates and releases `alice` with no access
  code. `alice` has no `zn_names` row, so the claim is open (#360). The
  access-code helper is gone.

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
