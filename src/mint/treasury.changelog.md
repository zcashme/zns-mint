# Treasury design record

## OTP relay construction moves to upstream wallet assembly (mint-level)

- The `relay` module is deleted. OTPs are a mint concern, not a Treasury
  one: issuance lives in `mint::otp::issue_relay`, which builds the
  challenge as an ordinary upstream Treasury payment (`propose_transfer` +
  `create_proposed_transactions`) to the current controller's Unified
  Address with the relay memo and one fee unit of compensation. After
  NU6.3, upstream routes the controller UA's Orchard receiver to the
  Ironwood pool; the spend policy, change strategy, and the
  Sapling-disabled prover keep the transaction Ironwood-only.
- The forced request-note spend and `required_relay_value` exact-value
  rule are gone: they were implementation policy, not protocol. A user may
  purchase as many challenges as they like; the queue burns the echoed one
  and prunes the rest at expiry. Upstream's sent-transaction recording
  marks the selected notes unavailable before broadcast, closing the
  manual path's window where built-but-unstored transactions left inputs
  re-selectable.
- `key.rs` gains the sanctioned `usk_clone()` for upstream's owned
  `SpendingKeys`; signing safety that the type boundary no longer provides
  is carried by policy constraints plus the disabled Sapling prover.

## 2026-09-02 — Treasury is a keyless policy layer over the wallet

- The `Treasury` view struct and its two methods (`unspent_notes`,
  `balance`) are deleted: zero callers remained after the vault and
  replenish rewrites, both of which read balances and notes through the
  upstream wallet traits directly. No exclusion-free wrapper survives to
  re-grow (the 2026-07-24 rule).
- Module docs now state the five responsibilities and the keyless boundary:
  Treasury holds no keys and no notes — not even viewing keys; every fact
  flows through a wallet projection, every signing capability arrives as a
  borrowed argument. Spending authority flows through `AccountKeys`
  (key.rs), viewing facts through the wallet.

## 2026-08-16 — Treasury carries live pricing

- `Treasury` gains `refresh_price(tip)` / `price(name, tip)` / `rate(tip)`
  delegating to the embedded `pricing::RateOracle`. The run loop refreshes
  once per block before evaluating requests; every claim in a cycle prices
  against one rate. Pricing is evaluation-time only — see
  `treasury/pricing.changelog.md` — so `Treasury` carries no historical
  pricing state and rebuilds cold on boot.

## 2026-08-15 — Treasury view projects Ironwood notes

- `Treasury::unspent_notes` returns the Treasury account's Ironwood notes.
  Treasury notes are Ironwood notes; the Orchard spend lane is deleted.

## 2026-07-28 — Stale claim-payment exclusion

- Claim matching receives the canonical Registry view and rejects an unspent
  payment confirmed at or before the current tip for that name. A payment
  cannot be reused after a release/reclaim boundary.

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
