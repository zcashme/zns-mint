# OTP authorization changelog

## 2026-07-23 — Typed internal challenge and fixed OTP secret

- `ChallengeKey` is the private-field internal identifier
  `(name, action, requested ua)`; it is not a request-memo field.
- Challenge debug output is redacted.
- Issued OTPs use a fixed 16-byte zeroizing type. Relay encoding writes the
  lowercase hexadecimal representation directly into a 512-byte stack buffer
  instead of creating a secret-bearing heap `String`.
