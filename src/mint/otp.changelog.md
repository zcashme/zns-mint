# `mint/otp.rs` design record

## 2026-10-20 — A challenge is its transition; a stale entry is replaced (#368)

- `OtpQueue` finds an entry by its transition — name, verb, requested
  address — in one place, `OtpChallenge::is_for`. Five hand-written
  comparisons, two of them also matching `term` and `code`, are gone.
- `tip_rcm` leaves the key. It is the record version the challenge was
  issued against: stored, checked by `answer` against the current record
  and by the registry's laws, but not what tells entries apart. A request
  against a newer record replaces the stale entry — new code, new
  deadline, attempts reset — instead of sitting beside it until expiry;
  the stale entry could neither be relayed nor answered. A repeat against
  the same record still receives the existing entry, code, deadline and
  attempts kept.
- `invalidate` and `is_relayed` had no caller; gone, with the request
  txid the entry carried for them. `admit` takes the challenge alone.
- The `(OtpChallenge, ChallengeState, TxId, Attempts)` tuple is an
  `Entry` struct.

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
