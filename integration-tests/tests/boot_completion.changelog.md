# boot_completion.changelog.md

## 2026-09-24

- Replaces the stale `boot_and_sync.rs` (boot at height 4, no capsule, no
  anchors, no Treasury funding, 2-second survival as success) with a
  scenario that proves the current `Boot::start()` contract: real regtest
  Zebra (JSON-RPC 8232 + Indexer gRPC 8230), chain facts built through the
  real ownership flow, and boot completion asserted from the returned
  `Boot` value plus a fresh identity-bound attestation — bounded by a
  harness deadline instead of elapsed sleep.
- The fixture lane is a real Zallet wallet (pinned
  `zns-integration-tests` f28fabf): mines coinbase, waits for its scan to
  reach the node's mature-coinbase truth (inclusive `h + 100 <= tip + 1`),
  shields once, then pays the Treasury's transparent address under
  `AllowRevealedRecipients`. The wallet holds no mint authority and is
  reaped before `Boot::start()`.
- The ceremony is authored by the Treasury's own keys derived from the
  all-zero seed — 40 zero-value Registry Ironwood anchors plus Treasury
  Ironwood funding, one ZIP-317-fee'd 42-action UNPADDED bundle,
  transparent signature + Ironwood proof + freeze in the vendored
  assembler (from `zns-integration-tests` `src/tx.rs` at f28fabf).
- Boot is called directly (not a daemon subprocess) because the returned
  `Boot` is the evidence; the test binary owns the process CWD that boot
  reads `keys/zns_seed.capsule` from and writes `zns_mint_attestation.bin`
  to. Assertions: birthday 100, cursor at the confirmed fixture tip, 40
  anchors with adoption closed, live initial price, and attestation bytes
  equal to an independently recomputed FakeTee report
  (`BLAKE2b-512(treasury shielded default address || "||" || registry
  UFVK)`).
- `claim_e2e.rs` is deleted with this change (superseded by the sibling
  repository's claim coverage); Zallet, shielding, and claim settlement
  appear here only as fixture funding, never as post-boot coverage.
