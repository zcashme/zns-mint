# Registry liquidity changelog

Tracks design-relevant changes to `src/registry/liquidity.rs`.

## 2026-09-02 — Count through upstream account metadata; refill restores a target pool

- `RegistryFeeLiquidity::from_wallet` counts through upstream
  `InputSource::get_account_metadata` with `NoteFilter::ExceedsMinValue(ZERO)`:
  strictly-positive value excludes value-0 Name Notes by construction, under
  the same spendability rules (one confirmation, unspent, lock-excluded) that
  fee selection itself applies — the count can never disagree with what a
  lifecycle op can actually draw on. Replaces the deleted
  `ironwood_notes_for` enumeration. Note *count* is the metric, not summed
  value: one fee note ≈ one lifecycle op, and change regenerates the pool
  while only the fee proper (10k–25k per op) grinds it down.
- Refill policy restated as restore-to-target: below
  `MIN_REGISTRY_FEE_NOTES` (20 — the burst the pool must absorb while one
  refill confirms; ~20 funded lifecycle ops of headroom), the Treasury
  refills to `REGISTRY_FEE_POOL_TARGET` (40 — twice the floor; steady state
  without overshoot). Supersedes the fixed `REGISTRY_FUNDING_BATCH_SIZE` of
  100, which jumped the pool to six times the floor for no recorded reason.
  `REGISTRY_FEE_NOTE_TARGET_VALUE` (50k = five minimum fees) is unchanged;
  its rationale is now recorded at the constant: a padded 2–5-action
  lifecycle bundle costs 10k–25k ZIP-317, and overshoot is safe because the
  unspent remainder returns as Registry change — itself a fresh fee note.
- `classify_registry_ironwood_note` now takes upstream
  `ReceivedNote<NoteId, orchard::note::Note>` (the value-level classification
  `classify_registry_note_parts` is unchanged); its remaining consumers are
  note-level fee-candidate filters in the registry slice.

## 2026-07-23 — Ordinary notes cannot become Name Notes by memo syntax

- Removed the `Name` classification from the ordinary Ironwood wallet lane.
  A commitment-valid Name Note is represented only by the scanner's opaque
  validated type and never enters Registry fee-note storage.
- Ordinary positive-value Registry notes are fee liquidity regardless of memo
  contents. Ordinary zero-value notes remain unusable `Other` notes.
- This prevents an attacker-controlled memo from changing note capabilities or
  excluding legitimate Registry funding from the fee pool.

