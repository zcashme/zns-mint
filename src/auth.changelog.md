# OTP authorization changelog

## 2026-07-23 — Typed internal challenge and fixed OTP secret

- `ChallengeKey` is the private-field internal identifier
  `(name, action, requested ua)`; it is not a request-memo field.
- Challenge debug output is redacted.
- Issued OTPs use a fixed 16-byte zeroizing type. Relay encoding writes the
  lowercase hexadecimal representation directly into a 512-byte stack buffer
  instead of creating a secret-bearing heap `String`.

## 2026-07-28 — Tip-bound two-phase relay challenge

- `ChallengeKey` additionally binds the canonical predecessor commitment. An
  OTP cannot authorize a request after the name's live tip changes.
- OTP generation is separate from recording an issued challenge: a failed
  relay assembly cannot leave an undeliverable OTP pending.

## 2026-07-28 — Reorg-scoped OTP invalidation

- A reorg retains OTP state for unrelated names and discards only pending or
  reserved challenges whose bound predecessor commitment no longer matches the
  rebuilt canonical Registry tip.
