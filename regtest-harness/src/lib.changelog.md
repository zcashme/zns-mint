# Regtest harness library changelog

Tracks design-relevant changes to `regtest-harness/src/lib.rs`.

## 2026-09-23 — Every NU6.x activates at genesis (#155)

- `zebrad_toml` configures NU6.1/6.2/6.3 at height 1 (was 4): NU6.3 is
  always active, even on regtest. The e2e flows mine to a working tip
  and to mature coinbase; activation is no longer a milestone the
  harness stages.

## 2026-07-30 — Boot-proven regtest consensus parameters

- The harness builds the mint only with the development-only regtest boot
  feature. That boot constructor pins the same activation schedule as the
  Zebra TOML generated here; it does not accept activation heights at runtime.
- The harness must mine through the pinned NU6.3 activation height before it
  launches the mint. A successful test therefore proves that the real mint
  loop sees regtest consensus parameters, rather than weakening Ironwood's
  boot invariant.
