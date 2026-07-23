# Transaction assembly design changelog

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
