# Treasury design record

Tracks design-relevant changes to `src/treasury.rs`.

## 2026-07-24 — No exclusion-free sweep or funding selection

- Deleted the unwired `treasury::sweep` and `treasury::note` request modules.
  Both selected Treasury notes behind internally empty exclusion sets and had
  no production caller.
- Deleted `Treasury::auto_sweep`, `Treasury::registry_funding`, their request
  types, and the unused last-sweep state. Added no replacement API.
- Preserved `RegistryFeeLiquidity` as pure Registry policy and preserved the
  lower-level Wallet selectors that require explicit caller-owned exclusions.
  Future Live work must derive any sweep/funding intent from one cursor-bound
  reservation view.

## 2026-07-24 — No exclusion-free Treasury selection wrapper

- Deleted the unused `Treasury::select_funds` convenience method. It always
  supplied an empty exclusion set and therefore made Live-owned reservations
  optional at its boundary.
- Preserved `wallet::selection::select_funds`, whose caller must supply an
  explicit exclusion set.
- Added no replacement. The audit also found embedded empty exclusions in the
  unwired sweep and Registry-funding policies; the follow-on entry above
  records their deletion in this combined Phase 0 closure.

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
