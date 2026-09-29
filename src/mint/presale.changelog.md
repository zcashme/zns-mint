# `mint/presale.rs` design record

## 2026-09-29 — Duplicate rows coalesce; the table is deduped upstream (#243)

- `zn_names` was rebuilt upstream while this change was in flight:
  columns are now `(id uuid PK default gen_random_uuid(), name,
  expiry_at)` — one row per name (2197 rows, unique names and ids),
  folded forever-else-max (verified against the pre-rebuild log:
  2197/2197 terms match, `9` and `tom` keep Forever). `select`,
  `order`, the keyset filter, and `ProtectedRow` follow the renamed
  columns.
- The pre-sale had let a name be bought more than once (the old
  log carried 2332 rows over 2197 names). `absorb` no longer
  rejects a duplicate `name`: rows for one name coalesce to the
  strongest bought term — `Forever` covers any expiry, a later
  expiry covers an earlier one — so the loaded table is the union
  of what was actually bought. With the table deduped upstream
  this is now defensive: a future duplicate re-appearing is folded,
  not boot-fatal.
- Pagination is total: the cursor is the unique `(name, id)` pair
  (`or(name.gt.X, and(name.eq.X, id.gt.Y))`), so no row can be
  skipped or repeated even if duplicates return — the old
  name-only cursor truncated any duplicate group straddling a
  page boundary.
- The one reject path is unchanged and stays fail-closed: a `name`
  that is not a lawful [`Name`] refuses the whole read.
  `fetch`'s install check compares the server count against raw
  rows absorbed (duplicates included), not the coalesced map
  length. The per-row duplicate warn becomes one summary line per
  read: names installed, rows read, coalesced, upgraded to
  Forever.

## 2026-09-29 — The table is cached; the claim path is synchronous (#242)

- The per-claim HTTP lookup is gone. `ProtectedNames`
  (`BTreeMap<Name, ProtectionStatus>`) is fetched once at boot
  (retry-until-good, before the attestation write) and refreshed
  once per MTP day by a background fetch whose completed result
  installs on a later pass. No claim waits on Supabase after boot.
- `ProtectionStatus` is three-variant: `WithExpiry(Timestamp)` |
  `Forever`, with `Unprotected` as the flattened absence `get`
  returns — never stored. A lift moment the MTP has reached is
  judged per claim at the gate, so expiry lifts exactly on
  schedule. `Lookup`, `LookupError`, `classify`, and `Decision`
  die.
- The gate is two questions, each on its owner:
  `ProtectedNames::is_protected(name, mtp)` judges protection
  (expiry judged now); `AccessCodeDerivationKey::accepts(name,
  offered)` judges the code. The lane refuses when the first is
  true and the second false — a name already live is refused by
  `authorize_claim` (redemption). `code_for` is the public
  name→code impl.
- `fetch` keyset-pages
  `normalized_name=gt.<last>&order=normalized_name.asc&limit=250`
  — the cursor is a value, not a position, so concurrent inserts
  and deletes cannot make pages repeat or skip — with one
  end-to-end timeout per page covering the request and the body
  (the old lookup timed out headers only). A page of worst-case
  valid rows (~137 B each) is ~34 KB under the unchanged 64 KB
  cap; the read stops on a short page and refuses a 101st nonempty
  page (~25,000 names). The first page demands `count=exact`, and
  the read installs only when the map's length equals the server's
  count — so a duplicate spanning a page boundary, invisible to
  the cursor, refuses the read. One bad row — an unlawful
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
