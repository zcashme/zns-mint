# `mint/otp.rs` design record

## 2026-10-26 — The right code spends the challenge (#383)

- `answer` removes the challenge it matches and returns it: one code,
  one use, at the block that carried the response. `consume` is gone.
  The run loop rules on the returned challenge there and then; a
  refused response ends the challenge, and a new request starts a
  new one.
- `prune` is `expire`, called per applied block with that block's
  median, before the block's responses are answered.

## 2026-10-22 — A challenge carries its request; one lookup (#368)

- `OtpChallenge` is `{ request, code, expires_at }`. It carries the
  update or release `Request` it answers instead of copies of its name,
  verb, address and term, so the request lane passes the request
  through and no longer unpacks it into a tuple.
- `index_of(name, action, ua)` is the one definition of "the same
  OTP". `admit`, `challenge_issued`, `answer` and `consume` look up
  through it; the five hand-written comparisons, over two different
  field sets, are gone.
- `tip_rcm` is gone. Every record change is a Name Note the run loop
  admits, and each admission drops that name's challenges
  (`drop_challenges`), so no challenge outlives the record it was
  issued against. A reorg or a restart still starts from an empty
  queue. Any new way to change a record must drop the name's
  challenges too.
- `invalidate` and `is_relayed` had no callers; gone, with the request
  txid each entry carried for them.

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
