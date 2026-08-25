# Registry authorization changelog

Tracks design-relevant changes to `src/registry/authorize.rs`.

## 2026-07-30 — OTP challenge machinery merged from `src/auth.rs`

- The top-level `auth` module is deleted; `src/auth.rs` and
  `src/auth.changelog.md` no longer exist. `ChallengeKey`, `OtpSecret`,
  `OtpCode`, `PendingOtps`, and the OTP relay memo encoding now live here,
  beside the transition authorization that consumes them.
- The burn side already lived here (`authorize_update`/`authorize_release`
  verify and burn challenges via `PendingOtps`); the issuance side
  (`treasury/relay.rs`) and the orchestrator (`mint.rs`, `main.rs`) now
  import through `crate::registry::authorize` and its re-exports.
- Nothing was added to `mint.rs`: the orchestrator keeps only the
  `OperationalState.pending_otps` field and its import path changed.

## 2026-07-30 — Boot-proven transition parameters

- Authorized update and release assembly forwards the boot-proven consensus
  parameters into Registry fee selection and signing. OTP authorization itself
  remains independent of network selection.

## 2026-07-23 — Test fixtures follow opaque production tips

- Authorization continues to consume only the public action and predecessor
  commitment view of a Registry tip.
- Unit fixtures now use the test-only Registry insertion boundary rather than
  constructing production tips from free scalar fields. Production tips remain
  constructible only from scanner-validated Name Notes.

## 2026-07-28 — Current-owner release and tip-bound OTPs

- A release request's UA must exactly equal the current controller recorded in
  the validated Name Note; request-controlled UAs cannot solicit a relay.
- Update and release OTP verification includes the exact predecessor
  commitment, invalidating every issued OTP once the name tip changes.

---

Historical entries from the deleted `src/auth.changelog.md`, merged verbatim:

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
