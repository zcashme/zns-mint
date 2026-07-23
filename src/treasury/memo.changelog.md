# Treasury request memo changelog

## 2026-07-23 — Fixed five-form request grammar

- Request memos accept exactly claim, update, update-with-OTP, release, and
  release-with-OTP forms.
- No version, network, nonce, or challenge identifier is present on the wire.
  OTP lookup uses the internal `(name, action, ua)` challenge key.
- Parsing requires a 512-byte memo with canonical zero padding and rejects
  hidden nonzero bytes after the first padding byte.
- `RequestMemo` debug output is redacted because names and addresses came from
  shielded memo plaintext.
