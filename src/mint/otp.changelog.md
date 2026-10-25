# `mint/otp.rs` design record

## 2026-10-24 — term is part of the challenge key

- `admit` records one entry per term at a tip. A different term is
  a separate challenge, with a separate code.
- `answer` returns the relayed entry whose code the echo carries.
  If two entries carry that code, it returns no entry. A non-matching
  code counts one attempt against every relayed entry for that name,
  action, address, and tip, and the sixth removes them all.
- `consume` removes the answered term and retains every other term
  at the same tip.

## 2026-10-15 — `OtpQueue::relayed` and `unrelayed` (#342)

- `relayed` names every relayed challenge, awaiting its echo;
  `unrelayed` every challenge still awaiting relay. Both borrow, so the
  metric tells the mint's move from the owner's without cloning a
  challenge or its code.

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
