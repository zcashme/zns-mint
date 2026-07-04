# auth.rs.changelog.md

## 2026-06-28 (in-band OTP authorization)
- Added `OtpStore`: in-memory one-time credentials scoped to `(name, action, ua)`.
- Added the two-pass update/release flow: unauthenticated request issues
  `ZNS:otp:<name>:<verb>:<ua>:<otp>`, authorized request verifies and consumes.
- OTP plaintext is redacted from `Debug`; logs must never include it.
- OTPs are 16-byte lowercase hex (32 chars) so they cannot parse as the 64-char
  `prev_rcm` field of a Name Note.
