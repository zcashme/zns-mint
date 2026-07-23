# `mint/note.rs` design record

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

## Rejected designs

- Returning an unstructured tuple is rejected because it allows an opening to
  be derived from one interpretation and Registry state to apply another.
- Uppercase hex, non-ASCII aliases, extra separators, nonzero trailing bytes,
  and action-inconsistent empty fields are rejected as noncanonical.
- Treating UA strings as normalized by this codec is rejected. Network and UA
  receiver validation belongs at the request-policy boundary.
