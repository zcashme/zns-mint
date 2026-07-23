# Treasury design record

Tracks design-relevant changes to `src/treasury.rs`.

## 2026-07-24 — No per-block request queue

- Treasury policy reads canonical Wallet state; it does not own or expose a
  height-indexed request queue.
- Request memo parsing remains a pure classifier over canonical Wallet memo
  evidence. Future Live work will reconcile Wallet and Registry state without
  this deletion deciding which observations are pending.
- The empty `requests_in_block` placeholder is removed without adding a
  replacement API.
