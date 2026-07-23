# Registry authorization changelog

Tracks design-relevant changes to `src/registry/authorize.rs`.

## 2026-07-23 — Test fixtures follow opaque production tips

- Authorization continues to consume only the public action and predecessor
  commitment view of a Registry tip.
- Unit fixtures now use the test-only Registry insertion boundary rather than
  constructing production tips from free scalar fields. Production tips remain
  constructible only from scanner-validated Name Notes.

