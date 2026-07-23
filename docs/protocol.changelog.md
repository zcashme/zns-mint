# Protocol changelog

## 2026-07-23 — Fixed request grammar

- Replaced the deferred/versioned request description with the five explicitly
  approved claim, update, and release forms.
- Request memos contain no version, network, nonce, or challenge identifier.
- Kept the Treasury-to-controller OTP relay policy listed separately as
  unresolved; it is not part of the user request grammar.

## 2026-07-23 — Candidate validity versus Registry authorship

- Corrected the security analysis: anyone can construct a commitment-valid
  zero-value output to the public Registry address.
- Namespace authority comes from a legal transition in a transaction that
  spends Registry authority; update/release additionally spend the exact live
  tip. Structural candidate validation alone has no namespace effect.
- Removed obsolete wording that described the confirmed request grammar as a
  deferred versioned policy. Request memos use the fixed unversioned `ZNS:`
  forms selected by the protocol owner.
