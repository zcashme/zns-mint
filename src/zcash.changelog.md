# Zcash I/O changelog

## 2026-07-23 — Read-only canonical replay capability

- Added `CanonicalBlockSource`, a narrow facade exposing only chain-info and
  full-block reads. Canonical catch-up can no longer reach raw-transaction or
  submission methods through its RPC argument.
- Classified retryable read failures explicitly. Malformed/invalid node data,
  checkpoint failures, request construction, serde, and RPC-semantic errors
  remain fatal; only transport availability failures may retry.
