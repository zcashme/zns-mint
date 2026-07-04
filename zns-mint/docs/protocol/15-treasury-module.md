# 15 - Treasury Module

This document defines the `treasury.rs` module: its features, data, public
surface, and boundaries. It is the design source for the Treasury module.
When source code implements or changes behavior described here, update this
document in the same change.

## Scope

`treasury.rs` is the Treasury account's **wallet view and Treasury policy**
layer. It is a stateless policy layer over borrowed wallet state — it owns no
note map of its own and holds no key material. It reads the Treasury slice of
the shared `Wallet` and produces policy decisions and "please sign this"
requests for the future transaction-assembly path.

The Treasury account (ZIP-32 account `0`) is the user-facing account: users
send name payments to it and send ZNS request memos to it; it is the shielded
origin of OTP relay memos. See `02-accounts-and-keys.md` and
`14-wallet-design.md` for the account model.

## What This Module Does NOT Do

These are load-bearing exclusions. The Treasury account and the Treasury
module are different things:

- **Does not sign transactions.** The Treasury spending key is consumed only
  by the transaction-assembly path, never by this module. This module produces
  *requests* (selected funds + recipient + intent), not signed transactions.
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
- **Does not parse Name Note memos or maintain name chains.** That belongs to
  the registry path.
- **Does not hold spending keys, seed material, or operator-readable config.**
- **Does not read env vars, CLI flags, or config files.** All policy inputs
  are hardcoded constants in this module.

## Features

### T1 — Treasury Wallet View

Read access to the Treasury account's unspent note map and balance, borrowed
from the shared `Wallet` via `wallet.treasury()` / `wallet.treasury_mut()`.

The Treasury note map holds name payments received and any other Orchard value
the Treasury happens to hold. It does not hold Name Notes (those are Registry
account notes).

### T2 — Fund Selection

`select_funds(target) -> Vec<&SpendableNote>`: greedy note selection
sufficient to cover a target value (e.g. an OTP relay fee, an auto-sweep
amount, a Registry funding transfer). No spending keys touched. The selection
is deterministic so the caller can predict what will be spent.

Selection policy: smallest-notes-first (a simple greedy ascending sort by note
value), so small change notes get consolidated and the Treasury doesn't sit on
a long tail of dust. This is a starting policy; it can be revisited without
breaking the boundary.

### T3 — Request Memo Classification

`requests_in_block(height) -> &[RequestMemo]`: raw 512-byte Treasury-received
memos, parsed into a typed `RequestMemo`:

```text
struct RequestMemo {
    height: BlockHeight,
    txid: TxId,
    action: Action,            // Claim | Update | Release
    name: NameKey,
    ua: String,
    otp: Option<OtpCode>,      // None for the no-OTP (request-authorization) form
}
```

This is *parsing* of incoming user request memos (per `04-memo-grammar.md`),
not OTP policy. The parsed requests are handed to the request-processing
layer (future, alongside `auth`), which decides whether to issue an OTP (via
`auth`), verify an OTP (via `auth`), or pass a claim to the Registry layer.

Memos that do not match the ZNS request grammar are dropped silently — they
are not ZNS traffic. Classification failures are not fatal.

### T4 — Auto-Sweep Policy

When Treasury balance exceeds a hardcoded `SWEEP_THRESHOLD`, the Treasury
module produces a `SweepRequest` for transaction-assembly:

```text
struct SweepRequest {
    selected_notes: Vec<[u8; 32]>,   // nullifiers of the notes to spend
    recipient: TransparentAddress,   // hardcoded SWEEP_ADDRESS
    amount: u64,                     // balance - SWEEP_RESERVE
}
```

Policy constants (hardcoded in `treasury.rs`):

- `SWEEP_ADDRESS: TransparentAddress` — the transparent address excess funds
  sweep to. Hardcoded; not env, not config.
- `SWEEP_THRESHOLD: u64` — Treasury balance above which a sweep is triggered.
- `SWEEP_RESERVE: u64` — amount kept in the Treasury for OTP relay fees and
  normal operation; sweep sends `balance - SWEEP_RESERVE`.

Auto-sweep is evaluated once per block, after sync. It produces *at most one*
`SweepRequest` per block. The request is handed to transaction-assembly, which
signs and broadcasts. The Treasury module does not sign.

### T5 — Registry Funding Policy

When the Registry account's spendable balance falls below a hardcoded
`REGISTRY_FUNDING_FLOOR`, the Treasury module produces a `RegistryFundingRequest`
for transaction-assembly:

```text
struct RegistryFundingRequest {
    selected_notes: Vec<[u8; 32]>,   // Treasury notes to spend
    recipient: RegistryOrchardAddress,  // the Registry's external Orchard address
    amount: u64,                     // REGISTRY_FUNDING_TOPUP
}
```

Policy constants:

- `REGISTRY_FUNDING_FLOOR: u64` — Registry balance below which a top-up is
  triggered.
- `REGISTRY_FUNDING_TOPUP: u64` — amount sent from Treasury to Registry per
  top-up.

The Treasury module reads the Registry balance through the shared wallet
(`wallet.registry().balance()`) to decide whether a top-up is needed. It does
not touch the Registry spending key. The recipient is the Registry's external
Orchard address, derived from the Registry UFVK (which the wallet already
holds for scanning).

Registry funding is evaluated once per block, after sync, after auto-sweep.
If both fire in the same block, auto-sweep must account for the outgoing
funding transfer when computing `balance - SWEEP_RESERVE` (see Open Questions).

### T6 — Claim Payment Detection

`match_payment(request: &RequestMemo, price: u64) -> Option<&SpendableNote>`:
given a claim request and a caller-supplied price, return the Treasury note
that pays for this claim, if any.

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

The Treasury module owns no durable state. It borrows the Treasury slice
of the shared `Wallet` and reads hardcoded constants. The only owned data
types are the request structs it produces:

```text
struct RequestMemo { ... }       // T3
struct SweepRequest { ... }      // T4
struct RegistryFundingRequest { ... }  // T5
```

These are produced-per-block, handed to the run loop / transaction-assembly,
and dropped. They are not stored.

## Public Surface

The Treasury module exposes a `Treasury` type that borrows the wallet's
Treasury slice:

```text
impl<'w> Treasury<'w> {
    fn from_wallet(wallet: &'w Wallet) -> Self;

    // T1
    fn unspent_notes(&self) -> &HashMap<[u8; 32], SpendableNote>;
    fn balance(&self) -> u64;

    // T2
    fn select_funds(&self, target: u64) -> Option<Vec<&SpendableNote>>;

    // T3
    fn requests_in_block(&self, height: BlockHeight) -> &[RequestMemo];

    // T4
    fn auto_sweep(&self) -> Option<SweepRequest>;

    // T5
    fn registry_funding(&self, registry_balance: u64) -> Option<RegistryFundingRequest>;

    // T6
    fn match_payment(&self, request: &RequestMemo, price: u64) -> Option<&SpendableNote>;
}
```

`main.rs` does not call this directly. The run loop constructs a `Treasury`
borrow each block (or the request-processing layer does) and drives T3 → T6
→ T4/T5 in that order.

## Per-Block Evaluation Order

Within a block, after `scan_verified_block` has updated the wallet:

1. **T3** — classify Treasury-received memos into `RequestMemo`s.
2. **T6** — for each claim `RequestMemo`, ask `match_payment` (caller supplies
   price). Claims without a matching payment are rejected; claims with a
   matching payment are handed to the Registry layer to mint.
3. Update/release `RequestMemo`s go to the request-processing layer, which
   calls `auth` to issue or verify OTPs. This is not Treasury module work.
4. **T5** — check Registry balance; if below floor, produce a
   `RegistryFundingRequest`.
5. **T4** — check Treasury balance after any outgoing funding; if above
   threshold, produce a `SweepRequest`.

T5 before T4 so auto-sweep sees the post-funding Treasury balance.

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
- Do not sign or broadcast transactions. Produce requests only.
- Do not add env vars, CLI flags, or config files. Policy inputs are
  hardcoded constants.
- Do not add durable storage unless explicitly requested.
- Do not expand this module until the user explicitly says so.

## Open Questions

- **Payment memo grammar.** `04-memo-grammar.md` defines the request memo and
  OTP relay memo formats but not a *payment* memo format. T6 needs a way to
  attribute a payment note to a specific claim (currently sketched as "the
  payment memo carries the same `name`"). The exact grammar needs to be
  added to `04-memo-grammar.md` before T6 can be implemented.
- **Auto-sweep + Registry funding in the same block.** If both fire, the
  sweep amount should be `balance - REGISTRY_FUNDING_TOPUP - SWEEP_RESERVE`,
  not `balance - SWEEP_RESERVE`. The current "T5 before T4" ordering handles
  this only if the sweep policy reads the post-funding balance; the exact
  accounting needs to be made precise when implemented.
- **Fund selection for sweep vs. funding.** `select_funds` is shared between
  OTP relay, auto-sweep, and Registry funding. Whether one selection policy
  fits all three or each needs its own is open. Starting assumption: one
  policy, revisit if sweep or funding shows different dust behavior.
- **Sweep address as a hardcoded constant.** A hardcoded transparent address
  in `treasury.rs` means changing it requires a binary rebuild and
  re-attestation. That is the safest option under the no-config rule, but it
  is operationally rigid. Seed-derivation was rejected because the operator
  can't predict the address without running the derivation. This is the
  agreed tradeoff.
- **Reorg handling for T6.** A matched payment can be reorged out. The undo
  buffer reverts the Treasury note map on rewind, but `match_payment` results
  handed to the Registry layer in prior blocks are not automatically
  retracted. The Registry layer must not mint a claim until the payment is
  confirmed past the reorg window, or must handle mint-then-reorg explicitly.
  Needs a joint decision with the registry layer.

## Related Files

- `docs/protocol/02-accounts-and-keys.md` — Treasury capability and key
  handling constraints.
- `docs/protocol/04-memo-grammar.md` — request memo grammar; payment memo
  grammar is an open question here.
- `docs/protocol/06-authorization.md` — claim/update/release flow.
- `docs/protocol/09-transaction-assembly.md` — transaction-assembly is the
  consumer of `SweepRequest` and `RegistryFundingRequest`.
- `docs/protocol/14-wallet-design.md` — wallet design; F8, F9, F10 define the
  Treasury module's place in the wallet boundary.
- `src/treasury.rs` and `src/treasury.rs.context.md` — the source module and
  its context.
- `src/auth.rs` and `src/auth.rs.context.md` — OTP credential authority;
  the Treasury module does not touch it.
- `src/wallet.rs` (future) — the shared `Wallet` this module borrows the
  Treasury slice from.
- `src/key.rs` — the only place spending keys live; not reachable from this
  module.

This document must be updated whenever `treasury.rs` changes design-relevant
behavior.