# Boot-and-sync regtest changelog

Tracks design-relevant changes to `regtest-harness/tests/boot_and_sync.rs`.

## 2026-07-30 — Activate Ironwood before mint boot

- The integration sequence mines the harness's configured NU6.3 activation
  block before launching the mint. Regtest boot retains the requirement that
  Ironwood is active; the test does not bypass it.
