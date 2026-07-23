# Registry liquidity changelog

Tracks design-relevant changes to `src/registry/liquidity.rs`.

## 2026-07-23 — Ordinary notes cannot become Name Notes by memo syntax

- Removed the `Name` classification from the ordinary Ironwood wallet lane.
  A commitment-valid Name Note is represented only by the scanner's opaque
  validated type and never enters Registry fee-note storage.
- Ordinary positive-value Registry notes are fee liquidity regardless of memo
  contents. Ordinary zero-value notes remain unusable `Other` notes.
- This prevents an attacker-controlled memo from changing note capabilities or
  excluding legitimate Registry funding from the fee pool.

