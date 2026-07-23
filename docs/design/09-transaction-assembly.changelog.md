# Transaction assembly design changelog

## 2026-07-24 — Registry funds the atomic claim fee

- Recorded the explicit policy that Treasury retains the caller-supplied price
  and refunds only `payment - price`.
- Registry fee notes fund the complete atomic transaction's aggregate ZIP-317
  fee. The deleted fee-derived Treasury surcharge has no replacement.
- Deleted the misleading one-function `treasury::fee` module; exact payment
  matching remains `Treasury::match_payment`.

## 2026-07-24 — Standalone refund path deleted

- Deleted the Treasury-only claim refund constructor instead of adapting its
  two-transaction ownership boundary.
- Claim assembly now has one permissible target: a single V6 transaction that
  settles the exact Treasury payment and creates the valid Name Note.
- Retained the crate-private mixed Orchard/Ironwood V6 signer because it
  already commits both effecting bundles under one shared sighash.
- Left aggregate ZIP-317 fee assignment and semantic recovery as explicit
  prerequisites to the atomic constructor. Fee assignment was subsequently
  resolved in favor of Registry funding.

## 2026-07-23 — Operational reservation ownership

- Replaced the stale claim that Registry fee-note reservations live in Wallet.
  Planning now accepts caller-owned exclusions and returns the same opaque
  exact locator plan.
- Recorded that transaction construction, proving, signing, and submission are
  unwired from passive canonical replay pending the Live boundary.

## 2026-07-23 — Runtime hardening status

- Recorded the typed Treasury/Registry signer split, exact Registry fee-note
  reservations, and separate anchor/target heights.
- Atomic claim settlement and OTP relay output policy remain explicit blocked
  decisions rather than silent implementation guesses.
