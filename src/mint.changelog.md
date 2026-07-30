# Mint live-work design record

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
