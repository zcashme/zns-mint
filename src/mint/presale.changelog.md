# `mint/presale.rs` design record

## 2026-09-24 — A rate limit keeps the claim queued

- HTTP 429 is `LookupError::Transient`. The paid claim waits for the
  next tip. Other 4xx stays terminal.

## 2026-09-22 — Per-row expiry; terminal vs transient retry

- Every row is protected. `expires_at` (`timestamptz`, nullable)
  picks `ProtectedWithExpiry(Timestamp)` vs `ProtectedForever`; past
  expiry and row absence both flatten to `Open`. `GENERAL_AVAILABILITY_DAY`
  and the `today` parameter to `decide` are gone.
- `Lookup::Unavailable` → `LookupError::{Transient, Terminal}`.
  Transient (transport, timeout, 5xx) → `Retry`. Terminal (4xx,
  non-JSON, unparsable `expires_at`, multi-row) → `Deny` — the queue
  slot is freed instead of burning a fetch every tip on a name that
  can't resolve without operator action.
- `FETCH_TIMEOUT` 5s → 2s to bound the worst-case tip drain when the
  queue holds many transient-deferred claims.
- URL selects `expires_at`; `ProtectedRow` decodes only that column
  via `OffsetDateTime::parse(_, Rfc3339)`. Needs
  `time = { features = ["parsing"] }`.

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
