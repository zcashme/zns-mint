# `mint/presale.rs` design record

## 2026-09-21 — AccessCode + publishable key

- `AccessCode` mirrors `OtpCode`: six digits, redacted `Debug`,
  `Zeroize` on drop, `from_digits` / `parse`, `ct_eq`. Derive is
  access-code-v1: TEE root → `HMAC(_, "access-code-v1")` →
  `HMAC(key, name)` → `u32_be % 1e6`. Spec vector (`alice` → `352582`)
  is pinned in unit tests.
- `zn_protected_names` only answers whether `status = protected`
  (`normalized_name` filter). No code column. PostgREST uses the
  project publishable key as `apikey`. `zn_waitlist` is unused.
  Registry `name_live` is redemption; Supabase is never written.

## 2026-09-19 — Read-only pre-sale table for early claims (#83)

- Early-access window closes on `GENERAL_AVAILABILITY_DAY`. Unavailable
  lookups retry via the request queue; wrong codes are decided dead.
