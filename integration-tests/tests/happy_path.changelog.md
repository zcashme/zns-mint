# happy_path.changelog.md

## 2026-10-31

- Mine past Zebra 7.0.0's 1,000-block non-finalized window before
  switching miners. The previous 106-block setup was entirely lost on
  restart, leaving the funder with no rewards and a five-minute wallet
  balance timeout. Check the node's mature funder balance after the
  restart so lost funding reports its cause immediately.

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
