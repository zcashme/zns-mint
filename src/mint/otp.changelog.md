# `mint/otp.rs` design record

## 2026-09-22 — `awaiting` scopes by `tip_rcm`

- `OtpQueue::awaiting` now binds `tip_rcm`, symmetric with `pending`
  and `accept`. Without it, a six-digit code collision across two
  live challenges for the same name/action/UA at different
  commitments could return one pending while `accept` bound the
  other — the caller then read term/policy off the wrong request.
- Test `awaiting_scopes_by_tip_rcm` seeds a shared-code pair across
  commitments and checks each resolves to its own pending.

## 2026-09-21 — The birth is one constructor (#120)

- `OtpRequest::pending_challenge` births the pair the run loop used to
  hand-write twice — the `Challenge` memo and the pending it arms, one
  code in two bodies, expired at D_OTP. Both lanes call it; the
  hand-copies are gone. Encoding stays with the callers: an
  unencodable challenge is dead at the relay and unreachable in
  liveness — lane policy, not birth.
