# `mint/presale.rs` design record

## 2026-09-29 — The table is cached; the claim path is synchronous (#242)

- The per-claim HTTP lookup is gone. `ProtectedNames`
  (`BTreeMap<Name, ProtectionStatus>`) is fetched once at boot
  (retry-until-good, before the attestation write) and refreshed
  once per MTP day beside the vault sweep, after the claim drain.
  No claim waits on Supabase after boot.
- `ProtectionStatus` is three-variant: `WithExpiry(Timestamp)` |
  `Forever`, with `Unprotected` as the flattened absence `get`
  returns — never stored. A lift moment the MTP has reached is
  judged per claim at the gate, so expiry lifts exactly on
  schedule. `Lookup`, `LookupError`, `classify`, and
  `Decision::Retry` die.
- The gate is `AccessCodeDerivationKey::check_access(status, mtp,
  name, offered)`: unprotected names pass, protected names must
  present the key's code for the name. `Deny` means only a wrong
  or missing code — a name already live is refused by
  `authorize_claim` (redemption). `code_for` is the public
  name→code impl.
- `fetch` pages `order=normalized_name.asc&limit=250&offset=N` —
  deterministically ordered, so pages neither repeat nor skip —
  with one end-to-end timeout per page covering the request and
  the body (the old lookup timed out headers only). A page of
  worst-case valid rows (~137 B each) is ~34 KB under the
  unchanged 64 KB cap; the read stops on a short page and refuses
  past 100 full pages (~25,000 names). One bad row — an unlawful
  `normalized_name`, a malformed `expires_at`, a duplicate —
  refuses the read: an existing protection can freeze, never
  silently drop. A failed refresh keeps yesterday's rows and
  tries next midnight.
- `AccessCodeKey` is renamed `AccessCodeDerivationKey`; `AccessCode`
  and the test vectors are unchanged.

## 2026-09-27 — The gate queries `zn_names`

- The Supabase table is `zn_names`; `zn_protected_names` was a
  misnomer in the constant and in these records — no table answers to
  it. `PRESALE_TABLE` is corrected; a lookup 404 is
  `LookupError::Terminal` → `Deny`, so with the constant stale every
  claim was decided dead on first contact with the gate.

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
