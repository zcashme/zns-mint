# Mint live-work design record

## 2026-09-15 — Liveness τ+L enforcement (issue #14)

- `CHALLENGE_LEAD` (7 days) and `LIVENESS_RETRY_COOLDOWN` (24 h) are
  distinct from `D_OTP` (the response window, 30 min). The lead is how
  far before `release_deadline` the mint begins reminding the current
  controller; the cooldown is the minimum interval between successive
  liveness reminders for the same record.
- The rate-limit ledger lives on `OtpQueue` alongside the active-code
  queue but is scoped by `(name, rcm)` — a fresh update (new
  commitment) is challengeable immediately, and the ledger clears on
  reorg or restart (harmless: at most one extra reminder to a live
  controller).
- Liveness enforcement itself is unchanged: `NameRecord::release_deadline
  = τ + LIVENESS_INTERVAL` on every accepted claim or update, and
  `Registry::release_due` returns `(NameNote::Release, ReleaseReason)`
  when either the purchased term or the deadline has passed. The
  liveness reminder is a mint-originated Relay, not a §5 authorization;
  liveness is only satisfied when a fresh update Name Note lands.

## 2026-09-03 — Oracle-only claim pricing, USD-denominated

- The fixed `CLAIM_PRICE` (1 ZEC) is gone. The claim price is
  `Oracle::quote_forever(name)` — the USD schedule (annual price by name
  length, ×3) converted at the daily rate. `quote_annual` joins it as the
  renewal-day hook.
- The oracle's rate is never optional. `Oracle::new(initial_price, now)`
  is the only constructor — boot fetches the first pricing round or the
  node does not start — and `accumulate(price, now)` can only replace the
  published rate, never clear it: a failed round carries the standing rate
  forward. Pricing is fail-closed at birth, fail-open in life.
  `Oracle::current()` reads the rate, total.
- Policy denomination is USD only. The schedule and every fee are stated
  in whole dollars and settle in zats through the daily rate. Fees snap up
  to the 100,000-zat step (`FEE_STEP`, `grid_usd` in `mint.rs`) —
  `REFUND_FEE_USD = 1` replaces the flat 50,000-zat fee, and the oracle no
  longer knows fees exist.
- Venue hardening in `fetch_last`: response bodies capped at 64 KiB
  (`Limited`) and prints outside 1–1,000,000 USD drop the venue, the same
  collapse-to-`None` as every other failure mode. The range bound is also
  what makes the rate bounded, which is what makes the quotes' plain
  multiplication provably overflow-free — total functions, not checked
  ladders.
- The schedule is typed `u64` (ASCII names: byte length is character
  length); the `Decimal` schedule conversions and `checked_mul` ladders
  are deleted.

## 2026-07-30 — Boot-proven Unified Address validation

- Unified Address receiver validation accepts the immutable consensus
  parameters established at boot. Address interpretation cannot diverge from
  scan, fee, and transaction-signing parameters.

## 2026-07-30 — In-flight tracking redesign

- **Submission** slimmed from 8 fields to 5: dropped `txid` (redundant — it's the
  `BTreeMap` key), `submit_height` (dead — never read by any logic), and
  `name_lock` (redundant with `name_binding` — same data in a wrapper).
- **`name_locks` `BTreeSet` deleted.** Name locking is now derived: a name is
  locked if any unconfirmed lifecycle submission (Claim/Update/Release) carries
  its `name_binding`, or if a pre-submit lock is held during assembly. A small
  `pre_submit_locks: BTreeSet<NameBinding>` replaces the old set and tracks
  only the assembly gap — locks that haven't yet been consumed by
  `record_submission`.
- **`check_confirmations` free function replaced by `OperationalState::reconcile`
  method.** The old 3-pass, 40-line function (mark confirmed → collect expired
  → collect confirmed, with `release_name` calls in each) is now a 2-operation
  method: mark confirmed, then `retain` with a predicate. No `release_name`
  calls — removing a submission from the map IS the unlock.
- **`record_submission` reduced from 10 args to 7:** dropped `name_lock`
  (gone), `submit_height` (dead), and `new_subs` (caller emits metrics inline).
- **`SubmissionKind::is_lifecycle()`** added to distinguish lifecycle
  submissions (which lock names) from OTP relays (which carry `name_binding`
  for reorg invalidation but must not lock).
- **`NameLock.binding` made `pub(crate)`** so `release_name` can access it
  without cloning.

## 2026-07-28 — Sweep amount is assembly-derived

- Auto-sweep work carries no precomputed value. Assembly derives the amount
  from the exact unreserved Treasury Orchard notes after reserving the fixed
  Treasury balance and the exact ZIP-317 fee for the resulting action shape.
- This prevents a policy-time balance snapshot from asking assembly to spend
  both the entire excess and a fee that the same balance cannot cover.

## 2026-07-28 — Name-scoped reorg invalidation

- Reorg handling retains unrelated submissions, locks, and Treasury work.
  Lifecycle submissions and locks are discarded only when their recorded name
  tip no longer matches the rebuilt Registry state.
- Every name-dependent submission, including nonexclusive OTP relays, carries
  a canonical name binding. A reorg resets confirmations above its common
  ancestor and retains an unconfirmed submission only when its exact reserved
  notes remain unspent on the rebuilt branch.
