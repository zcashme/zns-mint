# Library root changelog

Tracks design-relevant changes to `src/lib.rs`.

## 2026-07-30 — Release exclusion for regtest boot

- `regtest` is rejected whenever debug assertions are disabled. A
  production artifact cannot contain the regtest boot constructor or local
  consensus parameters.
