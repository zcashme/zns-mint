# TEE module changelog

Tracks design-relevant changes to the enclave seam. The implementation
now lives in `zns-canon`.

## 2026-09-29 — TEE seam moved to zns-canon

- `Tee`, `RealSnpTee`, and `FakeTee` are `zns_canon::sealing`. The mint
  no longer keeps a copy.

## 2026-09-29 — TEE is a boot submodule (#231)

- Moved the enclave seam under `boot::tee`, alongside capsule intake and
  boot attestation. The existing root module path remains a re-export.
- Production SNP operations, FakeTee behavior, and feature gates are unchanged.

## 2026-09-15 — Initial TEE seam (`Tee` trait, `RealSnpTee`, `FakeTee`)

- `Tee`: `derive_sealing_key(context)` + `get_attestation(report_data)`. SNP types
  (`Firmware`, `DerivedKey`, `AttestationReport`, …) stay inside `RealSnpTee`.
- `Attestation` = crate newtype `{ bytes, report_data }`: opaque wire bytes plus the
  64-byte identity binding, kept so callers don't re-parse the report.
- `RealSnpTee` (Linux): `firmware.get_derived_key` (VCEK, guest_policy + measurement)
  and `firmware.get_report`. Non-Linux returns `TeeError::Unavailable`.
- `FakeTee` (feature `fake-tee`, deterministic):
    - sealing key = `SHA256(SEALING_DOMAIN || LP(context))`,
    - body = `ATTEST_DOMAIN || FAKE_MEASUREMENT || report_data`,
    - "signature" = `SHA256(FAKE_SIGNING_KEY || body)` over a public constant —
      cosmetic shape only; any real verifier rejects it.
