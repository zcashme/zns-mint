# happy_path.changelog.md

## 2026-10-22

- The happy path claims `alice` with a code-free memo, as before #341:
  `alice` holds no `zn_names` row, so open registration (#360) lets it
  through. Update and release follow on `alice`; the access-code helper
  is gone.

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
