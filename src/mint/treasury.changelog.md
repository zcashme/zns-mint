# Treasury design record

## The sweep is a midnight event with a minimum payment (#82)

- `sweep_to_vault` takes this tip's day and the day MTP named before
  catch-up. A same-day tip returns `None` on one integer compare, no
  wallet. A catch-up that crosses midnight is the one chance to sweep;
  a dry crossing waits until the next.
- The 2 ZEC spendable `SWEEP_THRESHOLD` and its wallet-summary
  pre-check are gone; the gate is now a floor on what moves:
  `sweep_payment` returns the vault payment only when at least
  `SWEEP_MINIMUM` (1 ZEC) reaches the vault, with `SWEEP_RESERVE`
  still behind as change. Below-minimum and empty-notes idle log at
  debug so a dry rollover does not warn.

## 2026-09-18 — Sweep payment leaves slack for propose's change action

- `propose_transfer` first prices ZIP-317 with the payment and spends
  but **no change** (often the 10_000-zat grace fee). Only then does it
  add the Ironwood change note, which can raise the fee. An exact leftover
  from the finished-tx fee does not close. Payment subtracts one extra
  `MARGINAL_FEE`. A failed proposal logs `fee_zats`, `payment_zats`, and
  `ironwood_n`.

## 2026-09-18 — Sweep payment is ZIP-317 over the pinned input set (#63)

- `sweep_to_vault` guessed a ZIP-321 amount from `note_count + 3` times
  `MARGINAL_FEE`. `unspent_*_notes` and `select_spendable_notes` did not
  agree on the input set, so `propose_transfer` saw `InsufficientFunds`
  with `available > required`, which made CI fail. Dummy Orchard actions
  from `SpendPolicy::default()` could change the fee again.
- The drain set is now `select_spendable_notes(AllFunds, [Sapling,
  Ironwood])`. ZIP-317 prices that shape (1 P2PKH vault, Ironwood change,
  DEFAULT padding, no Orchard). `payment = total − fee − SWEEP_RESERVE`.
  Spend policy is Sapling+Ironwood only. Not `propose_send_max`: that
  would sweep the 0.01 float.

## 2026-09-18 — Sweep None paths log why

- `sweep_to_vault` returned `None` with no log on missing
  anchor/summary, below-threshold idle, zero payment, and ZIP-321
  construction failure. Proposal failure was debug-only. Two CI
  timeouts looked identical: mint never called submit, and the log
  could not tell skip from silent None.
- Each None path now logs the reason. Unexpected skips and proposal
  failure are WARN. Below-threshold idle is DEBUG so a dry Treasury
  does not spam every tip.


## 2026-09-17 — update term gains forever — the upgrade spelling (#65)

- `parse_request` accepts `ZNS:update:forever:<name>:<ua>`: a
  fixed-term registration may buy the forever tier through the
  ordinary request → relay → respond flow. `none` and `<N>y`
  unchanged; `claim:none` stays invalid.
## 2026-09-17 — Request grammar is term-first; echo is the relay memo

- `parse_request` reads `ZNS:claim:<term>:<name>:<ua>` (`forever` or
  `<N>y`), `ZNS:update:<term>:<name>:<ua>` (`none` or `<N>y`),
  `ZNS:release:<name>:<ua>`. UA is terminal. No OTP on a request.
- An echo is `ZNS:otp:…`, routed by `Challenge::decode` at intake; digits
  ride the request queue, the bound term stays on the issued challenge.

## 2026-09-15 — Loop keeps parse_request and challenge()

- User memos stay on `parse_request` (WP slots, canonical seconds, OTP
  Respond). The orchestrator loop classifies from `ParsedRequest.otp`.
- Outbound controller relays are `treasury::challenge` with
  `required_relay_value`. Relay memos are not decoded as echoes.
- `registry.authorize` consumes the internal `Request`. Names
  `authorize_claim` / `authorize_update` in older entries below are
  historical.

## Request memos carry access codes in a trailing slot

- Update and release Responds append a six-digit OTP. Field count is the
  discriminator: an update Request is `ZNS:update:<name>:<ua>[:<term>]`;
  an update Respond is `ZNS:update:<name>:<ua>:<term>:<otp>` (`none` in
  the term slot when the Request carried none). A release Request stays
  `ZNS:release:<name>:<ua>`; a release Respond is
  `ZNS:release:<name>:<ua>:<otp>`. Claim never takes an OTP.
- `ParsedRequest.otp` is `Some` only on a Respond. Intake settles that
  note and issues a relay only when the slot is empty. Relay memos
  (`ZNS:otp:…`) are still not Requests or Responds.
- A six-digit update field without a following OTP remains a term
  (`123456` is 123456 seconds, not an access code). Leading-zero OTP
  spellings (`004206`) are not terms, so they cannot occupy the term slot.

## Request memos accept a registration term

- `parse_request` returns [`ParsedRequest`] with an optional `term`.
  `ZNS:claim:<name>:<ua>` and `ZNS:update:<name>:<ua>` still mean no
  fixed expiration / no extension. Those verbs may append a canonical
  second-duration or the exact field `none`. `release` still rejects any
  extra field. Leading-zero spellings (including a 6-digit OTP) are not
  terms.
- The intake loop forwards `term` into claim settlement and OTP issuance
  so `authorize_claim` / `authorize_update` can compute `expires_at`.

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
