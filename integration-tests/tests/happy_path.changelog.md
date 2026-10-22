# happy_path.changelog.md

## 2026-10-20

- After the release, the same name runs a second claim → update →
  release under a Sapling-only controller (#365): both challenges go out
  as Sapling notes. The user mines 14 coinbases to cover both lifecycles.
- The first lifecycle pays the Treasury's index-0 Orchard address, which
  is no longer the identity UA's Orchard receiver for the dev seed: a
  payment to the pre-#365 address is still read.

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
