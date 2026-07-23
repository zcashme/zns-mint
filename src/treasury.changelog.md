# Treasury design record

Tracks design-relevant changes to `src/treasury.rs`.

## 2026-07-24 — Payment matching is not fee policy

- Deleted the one-function `treasury::fee` module. It computed no fee and had
  only one caller.
- Inlined its unchanged claim-only, Treasury-account, minimum-value, and exact
  memo predicate into `Treasury::match_payment`.
- Registry now funds the complete atomic claim fee. Treasury payment matching
  compares only against the caller-supplied price.

## 2026-07-24 — Standalone claim refund removed

- Removed the `treasury::assemble` module and its public refund constructor.
  A refund without the corresponding Name Note was the wrong settlement
  boundary and must not remain available for future runtime wiring.
- Preserved payment matching as canonical evidence selection. It does not
  decide refund, aggregate-fee, or settlement policy.
- Preserved the crate-private mixed Orchard/Ironwood V6 signer in
  `registry::signing`; the future atomic claim constructor will be its caller.

## 2026-07-24 — No per-block request queue

- Treasury policy reads canonical Wallet state; it does not own or expose a
  height-indexed request queue.
- Request memo parsing remains a pure classifier over canonical Wallet memo
  evidence. Future Live work will reconcile Wallet and Registry state without
  this deletion deciding which observations are pending.
- The empty `requests_in_block` placeholder is removed without adding a
  replacement API.
