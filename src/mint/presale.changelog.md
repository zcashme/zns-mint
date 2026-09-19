# `mint/presale.rs` design record

## 2026-09-19 — Read-only pre-sale table for early claims (#83)

- `lookup_name` GETs the Supabase PostgREST collection filtered by name,
  `select=code`. Empty URL means every name is open (table not wired).
  Empty anon key with a wired URL is unavailable (retry). Malformed or
  multi-row bodies are unavailable.
- `decide` is pure: before `GENERAL_AVAILABILITY_DAY`, a `Protected`
  row requires the offered code and a non-live name; `Open` allows;
  `Unavailable` retries. At and after that day every decision is allow
  — codes die worthless. The mint never writes the table; redemption is
  `name_live`.
