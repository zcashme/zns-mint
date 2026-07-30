# Registry authorization changelog

Tracks design-relevant changes to `src/registry/authorize.rs`.

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
