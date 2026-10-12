# happy_path.changelog.md

## 2026-10-12

- One test, whole lifecycle: the merged e2e chains real boot (the former
  `boot_completion.rs`) into the user verbs (the former `happy_path.rs`).
  The funder wallet mines and shields coinbase and pays the Treasury, the
  Treasury's own keys author the 40-anchor ceremony, the funder is
  reaped, `Boot::start()` completes in-process with all its evidence
  assertions (birthday, wallet tip, anchor pool, adoption closed, oracle
  price, dev identity document), and the mint binary then launches
  against the real ceremony facts for claim → update → release.
- `slot_regression.rs` is retired along with the fixture-ceremony lane
  (`Stack::start`, the cached `publish`, `FIXTURE_HEIGHT`): the only
  integration test is now the real one.
- Wallet ordering is load-bearing: a zallet whose retrieval queue holds
  txs mined after the chain's first shielded (Ironwood) tx never
  retrieves them, so its transparent balance stays zero forever. The
  funder therefore mines its coinbase before any shielded tx exists; the
  user wallet's bring-up follows (its restart drops only the funder's
  unfinalized tail) and its own shield is the first shielded tx; the
  funder's daemon starts last — after the shield, but with a queue
  holding only the finalized pre-shield coinbase. No zebrad restart
  happens after the user wallet's coins exist.
- Wallet precision: boot is proven independent of the funder wallet —
  reaped before `Boot::start()`. The unrelated user wallet stays alive
  across boot (the keys/ contract references no wallet, and the harness
  exposes no way to pause a zallet daemon).
- CI folds the `integration` and `happy-path` jobs into one `e2e` job
  (`needs: ci`, 45-minute timeout). The ceremony tx cache is retired:
  the funding txid is random, so a signed ceremony was never
  byte-reproducible — every run now re-proves the real ceremony.
