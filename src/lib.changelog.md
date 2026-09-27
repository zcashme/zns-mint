# Library root changelog

Tracks design-relevant changes to `src/lib.rs`.

## 2026-09-27 — Reject the testnet+regtest feature combo (PR #212)

- `--features testnet,regtest` previously compiled, silently resolving
  to regtest by gate precedence. It is now a `compile_error!`, matching
  the loud-over-silent posture of the release guards above it.
- CI replaces `--all-features` clippy/doc jobs with explicit supported
  combinations, since `--all-features` enables both exclusive features.

## 2026-07-30 — Release exclusion for regtest boot

- `regtest` is rejected whenever debug assertions are disabled. A
  production artifact cannot contain the regtest boot constructor or local
  consensus parameters.
