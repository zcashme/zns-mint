# TEE module changelog

Tracks design-relevant changes to `src/tee.rs`.

## 2026-09-22 — Production KDF now binds `context`

- `RealSnpTee::derive_sealing_key` used to ignore `context`, so
  `CAPSULE_KEY_CONTEXT` and `ACCESS_CODE_KEY_CONTEXT` shared one
  SNP-derived key. `FakeTee` domain-separated; production didn't.
- Two-step KDF: SNP root → `bind_context(root, context) =
  HMAC-SHA256(root, SEALING_DOMAIN || LE32(len) || context)`. Domain
  distinct from `FakeTee`'s.
- `bind_context` is pure and cross-platform tested: determinism,
  distinct-contexts-disjoint-keys, prefix-collision safety, and
  pinned vectors for both live contexts against a zero root.

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
