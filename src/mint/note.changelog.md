# `mint/note.rs` design record

## 2026-09-17 — Term is `forever` | `<N>y`; extend refuses forever+years

- `Term` is `Forever | Years(1..=99)`. One year is `LIVENESS_INTERVAL`.
  Seconds never appear on the request wire.
- `Expiry::extend`: `None` keeps the current expiry; years are added to
  the current expiry (not to now). The result must sit ≤ 99 years ahead
  of MTP. `Never` plus a term is `None` — forever has no end date, so
  years cannot be added to it.

## 2026-09-15 — Term is a second-duration; updates call Expiry::extend

- `Term` is a canonical whole-second duration (`Term::parse` / `duration` /
  `claim_expiry`). Years are a subsequent task.
- `Expiry::extend(term)` is the update successor: `Never` stays `Never`,
  `None` keeps the current instant, a term adds to `Expiry::At`.

## Canonical Name Note payload

- The on-chain form is exactly
  `ZNS:<verb>:<name>:<ua>:<prev_rcm_hex>` followed only by zero padding to 512
  bytes. The verb and hexadecimal encoding are lowercase ASCII with no
  normalization or alternate spelling.
- Parsing yields a typed `NameNotePayload` that retains name, action, UA, and
  predecessor commitment. The same value derives `(rcm, psi)` and is retained
  by `ValidatedZnsNote`; consumers do not independently reparse the memo.
- `claim` requires an absent/zero predecessor and a nonempty UA. `update`
  requires a present predecessor and a nonempty UA. `release` requires a
  present predecessor and an empty UA.
- Encoding and decoding are exact inverses over the accepted canonical domain.
  A decoded payload must re-encode byte-for-byte to the input memo, including
  its zero padding.
- This codec defines Name Note artifact grammar, not user request grammar. The
  request forms remain the user-approved `ZNS:claim`, `ZNS:update`, and
  `ZNS:release` forms without a version, nonce, network field, or challenge ID.
  `claim` and `update` may append a canonical second-duration `term` (or `none`);
  `release` does not. An update Respond is `ZNS:update:<name>:<ua>:<term>:<otp>`
  (`none` when the Request carried no term). A release Respond is
  `ZNS:release:<name>:<ua>:<otp>`. The Mint computes `expires_at` from the
  Request term bound at relay issuance.

## Rejected designs

- Returning an unstructured tuple is rejected because it allows an opening to
  be derived from one interpretation and Registry state to apply another.
- Uppercase hex, non-ASCII aliases, extra separators, nonzero trailing bytes,
  and action-inconsistent empty fields are rejected as noncanonical.
- Treating UA strings as normalized by this codec is rejected. Network and UA
  receiver validation belongs at the request-policy boundary.
