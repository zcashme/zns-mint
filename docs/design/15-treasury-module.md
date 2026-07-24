# 15 - Treasury Module

This document defines the `treasury.rs` module: its features, data, public
surface, and boundaries. It is the design source for the Treasury module.
When source code implements or changes behavior described here, update this
document in the same change.

## Scope

`treasury.rs` is the Treasury account's **wallet view and Treasury policy**
layer. It is a stateless policy layer over borrowed wallet state — it owns no
note map of its own and holds no key material. It reads canonical Treasury
evidence from the shared `Wallet` and matches claim payments.

The Treasury account (ZIP-32 account `0`) is the user-facing account: users
send name payments to it and send ZNS request memos to it; it is the shielded
origin of OTP relay memos. See `02-accounts-and-keys.md` and
`14-wallet-design.md` for the account model.

## What This Module Does NOT Do

These are load-bearing exclusions. The Treasury account and the Treasury
module are different things:

- **Does not sign transactions.** The Treasury spending key is consumed only
  by the transaction-assembly path, never by this module. This module returns
  canonical evidence references and pure policy answers; it produces neither
  selected-fund requests nor signed transactions.
- **Does not own OTP credentials.** OTP issuance, verification, expiry, and
  one-time consumption belong to `auth.rs`. `treasury.rs` does not generate,
  store, or verify OTPs. The Treasury *account* is the shielded origin of the
  OTP relay memo; the Treasury *module* does not sign the relay.
- **Does not mint or spend Name Notes.** That is the Registry's sole
  capability.
- **Does not decide name pricing.** Pricing strategy is protocol policy and
  lives elsewhere (a future `policy.rs` or in `payload.rs`). The Treasury
  module answers "was this paid" given a caller-supplied price; it does not
  decide the price.
- **Does not select sweep or Registry-funding inputs.** The prior unwired
  request modules hid empty reservation exclusions and were deleted. Any
  future policy must be derived by a Live owner from one cursor-bound
  exclusion/reservation view.
- **Does not parse Name Note memos or maintain name chains.** That belongs to
  the registry path.
- **Does not hold spending keys, seed material, or operator-readable config.**
- **Does not read env vars, CLI flags, or config files.** Policy inputs arrive
  through typed callers or canonical wallet state.

## Features

### T1 — Treasury Wallet View

Read access to the Treasury account's unspent Orchard notes and balance,
borrowed from the shared `Wallet` through
`wallet.orchard_notes_for(TREASURY_ACCOUNT)` and
`wallet.balance(TREASURY_ACCOUNT)`.

The Treasury note map holds name payments received and any other Orchard value
the Treasury happens to hold. It does not hold Name Notes (those are Registry
account notes).

### T6 — Claim Payment Detection

`match_payment(wallet: &Wallet, request: &RequestMemo, price: u64)
-> Option<&ReceivedOrchardNote>`: given a claim request and a caller-supplied
price, return the Treasury Orchard note that pays for this claim, if any.

Detection rules:

- The note was received at the Treasury account.
- The note value is `>= price`.
- The note's memo matches the claim. Matching is by memo reference: the
  payment memo must carry the same `name` as the claim, so a payment can be
  attributed to a specific claim. The exact memo grammar for payments is an
  Open Question (see below) — the request memo grammar in
  `04-memo-grammar.md` does not yet define a payment memo format.
- The note has not already been matched to a prior claim (a payment is
  consumed by exactly one claim).

Pricing is supplied by the caller (the request-processing layer, which gets
it from protocol policy). The Treasury module does not decide the price; it
only confirms a payment of that size arrived and points to the note.

This is the cross-account handoff: the Registry layer will not mint a claim
Name Note until `treasury.match_payment(...)` returns `Some`.

## Data

The Treasury module owns no durable request state. Its methods borrow the
shared `Wallet`. Wallet note and transaction state retains canonical memo
evidence; `RequestMemo::parse`
classifies a memo when Live reconciliation needs it. This design does not yet
define which observations constitute pending work.

No Treasury request or selected-note type is retained as canonical state.

## Public Surface

The Treasury module exposes a stateless `Treasury` policy type. Each query
borrows the shared wallet explicitly:

```text
impl Treasury {
    fn new() -> Self;

    // T1
    fn unspent_notes<'w>(
        &self,
        wallet: &'w Wallet,
    ) -> impl Iterator<Item = &'w ReceivedOrchardNote>;
    fn balance(&self, wallet: &Wallet) -> u64;

    // T6
    fn match_payment<'w>(
        &self,
        wallet: &'w Wallet,
        request: &RequestMemo,
        price: u64,
    ) -> Option<&'w ReceivedOrchardNote>;
}
```

`main.rs` does not call this directly. Future Live reconciliation reads
canonical Treasury evidence from Wallet, classifies memos, compares Wallet and
Registry state, and only then invokes the relevant policy methods. There is no
height-indexed request queue, no exclusion-free Treasury selection wrapper,
and no replacement pending-work query. Exact note selection belongs to a
future Live owner that supplies its reservation exclusions explicitly.

## Live Reconciliation Order

After rebuild reaches and verifies an exact Zebra tip:

1. Classify relevant canonical Treasury memo evidence with
   `RequestMemo::parse`.
2. **T6** — for each claim `RequestMemo`, ask `match_payment` (caller supplies
   price). Claims without a matching payment are rejected; claims with a
   matching payment are handed to the Registry layer to mint.
3. Update/release `RequestMemo`s go to the request-processing layer, which
   calls `auth` to issue or verify OTPs. This is not Treasury module work.

No request slice is produced or retained per block. Sweep and Registry-funding
selection are absent; future Live requirements must force their correct
reservation-aware shape back into existence.

## Boundaries

- Do not import `crate::boot` or accept `boot::Accounts`.
- Do not derive or touch spending keys here. View-only wallet state only.
- Do not parse Name Note memos or maintain name chains. That belongs in the
  registry path.
- Do not mint or spend Name Notes. That is the Registry's sole capability.
- Do not generate, store, verify, or otherwise handle OTP credentials. That
  is `auth.rs`'s sole authority.
- Do not decide name pricing. Pricing is protocol policy supplied by the
  caller.
- Do not sign or broadcast transactions. Return evidence references and pure
  policy answers only.
- Do not add env vars, CLI flags, or config files.
- Do not add durable storage unless explicitly requested.
- Do not expand this module until the user explicitly says so.

## Open Questions

- **Payment memo grammar.** `04-memo-grammar.md` defines the request memo and
  OTP relay memo formats but not a *payment* memo format. T6 needs a way to
  attribute a payment note to a specific claim (currently sketched as "the
  payment memo carries the same `name`"). The exact grammar needs to be
  added to `04-memo-grammar.md` before T6 can be implemented.
- **Reservation-aware sweep and funding.** The prior selected-note request
  modules were deleted. Future Live design must decide policy, accounting, and
  destination together with one caller-owned reservation/exclusion view; no
  shortcut API exists meanwhile.
- **Reorg handling for T6.** A matched payment can be reorged out. The undo
  buffer reverts the Treasury note map on rewind, but `match_payment` results
  handed to the Registry layer in prior blocks are not automatically
  retracted. The Registry layer must not mint a claim until the payment is
  confirmed past the reorg window, or must handle mint-then-reorg explicitly.
  Needs a joint decision with the registry layer.

## Related Files

- `docs/protocol.md (§2–3)` — Treasury capability and key
  handling constraints.
- `docs/protocol.md (§6)` — request memo grammar; payment memo
  grammar is an open question here.
- `docs/protocol.md (§8)` — claim/update/release flow.
- `docs/design/09-transaction-assembly.md` — future transaction assembly;
  no Treasury sweep/funding request surface currently exists.
- `docs/design/14-wallet-design.md` — wallet design; F8, F9, F10 define the
  Treasury module's place in the wallet boundary.
- `src/treasury.rs` and `src/treasury.rs.context.md` — the source module and
  its context.
- `src/auth.rs` and `src/auth.rs.context.md` — OTP credential authority;
  the Treasury module does not touch it.
- `src/wallet.rs` — the shared `Wallet` each Treasury policy query borrows.
- `src/key.rs` — the only place spending keys live; not reachable from this
  module.

This document must be updated whenever `treasury.rs` changes design-relevant
behavior.
