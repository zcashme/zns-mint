# Mint live-work design record

## 2026-09-24 — The Treasury's mail returns from application (#177)

- `apply_block` keeps the Treasury keys and the one decode, loses the
  queue parameters, and returns the block's arrivals. Where they file
  is the caller's policy: the run loop routes requests to the queue,
  echoes to the OTP queue, and logs a payment with no ask; boot drops
  them — the scratch queues are gone, history scans without filing.
- `Boot` sheds `challenges`; the run loop declares its three queues
  together — born empty at every start, corrected by reorg, decided at
  the tip.
- `NameRequest` drops `txid` — nothing read it. The queue tests that
  only exercised `Vec` are cut; the truncate boundary and the
  accept-once replay guard remain.

## 2026-09-24 — The queue records challenge status (#177)

- `ChallengeStatus { Requested, Relayed, Closed }` rides beside each
  issued challenge. `Relayed` is the live offer; `Closed` is terminal —
  answered, elapsed, or cancelled. `accept` and the expiry sweep are
  now explicit transitions the queue owns, replacing the silent
  `remove`/`retain` calls; a Closed tombstone stays until its window
  itself would have ended, so the whole D_OTP span is accounted for in
  the queue.
- `Requested` has no producer yet — challenges are born `Relayed`, at
  relay acceptance. It is the state the request-to-relay handoff
  (#176) will produce.

## 2026-09-24 — The request queue holds NameRequests (#177)

- `NameRequest { txid, request, paid, height }` names the queue's
  entry: the ask, its carrying transaction, its payment, its block.
  `MintInbound` leaves the queue entirely and settles into its one
  job — the classifier at the door, one `decode` call shared by block
  application and the mempool reader.
- A payment with no ask is decided the moment it is sighted: the
  non-request log moves from the tip drain to block application,
  where the arrival is already known. An orphaned block's payment may
  log and then vanish with the reorg, and a boot rescan replays the
  lines of history — cosmetic; the sweep keeps the value either way.

## 2026-09-24 — Echoes park on the OtpQueue (#177)

- `OtpQueue` holds both sides of the conversation: issued challenges,
  and a responses lane — `OtpResponse { echo, paid, height }` parks a
  received echo with its chain facts. `respond` records at block
  application; `take_responses` hands the drain the batch, and echoes
  leave on read — decided in every outcome, they never defer.
- `apply_block` routes `MintInbound::Echo` to the challenge memory and
  gains a `&mut OtpQueue` parameter — the run loop passes the live
  one, boot a scratch.
- The drain's echo pass runs after the request pass and builds the
  authorized request from the matched pending, not from the echo: the
  controller's utterance is the lookup key; the term it renews was
  the mint's to say. `pending()` makes the pass order
  outcome-equivalent to the old interleaved block order.

## 2026-09-22 — The queue carries the txid for every lane (#137)

- `RequestQueue` entries are `(TxId, MintInbound, Zatoshis,
  BlockHeight)` and `MintInbound::Unrecognized` goes unit: the txid
  rides beside every entry, not inside one variant, and
  `MintInbound::decode` is purely memo → classification. Echo and
  Request keep the provenance the old shape discarded; the drain's
  `Unrecognized` log is unchanged.
## 2026-09-24 — Remove automatic liveness reminders (#174)

- `OtpQueue` now tracks only active OTP challenges. The separate
  liveness reminder cooldown ledger is removed along with the automatic
  reminder path; ordinary update OTP challenges remain unchanged.
- The one-year `LIVENESS_INTERVAL`, `release_deadline` calculation, and
  release enforcement remain in place.

## 2026-09-22 — Malformed Registry spends no longer panic replay

- `apply_block` rejects a Registry spend with no Name Note, or with
  more than one, via `Registry::follow_spends` — on every path, unconditionally, since
  it no-ops when nothing Registry-owned was spent — instead of
  `assert!`/`panic!`. An update/release that also created a claim
  anchor is offered to `accept_*` rather than aborted.

## 2026-09-22 — Treasury memos decode once, at block application (#133)

- `MintInbound::decode(network, txid, &memo)` in `mint.rs` classifies
  each decrypted Treasury memo — echo, request, unrecognized payment —
  exactly once, when the block is applied. `treasury::parse_request`
  moves in as `Request::decode` beside the enum it produces;
  `Challenge::decode` and the controller-UA guard sit beside it,
  private now.
- The Treasury lane carries `zcash_protocol::memo::MemoBytes` end to
  end — decryption, `MintInbound::decode`, `Challenge::encode`, and
  the relay builder — and the grammars lean on upstream's
  `Memo::try_from`/`TextMemo` for the ZIP-302 text rules instead of a
  hand-rolled prelude.
- `apply_block` records the classification per memo; the
  classification loop and its cross-module call into `treasury.rs`
  are gone. `treasury.rs` keeps wallet ops only: sweep, challenge
  builder, queue.
- Grammar tests move into `mint.rs`, trimmed to one test per
  mechanism: term strictness stays at `Term::parse`'s own unit,
  OTP-shape exclusions are subsumed by `MintInbound::decode`, and the
  suite keeps the forms, the pre-sale code discrimination, the
  UA-guard regression vectors, the classification, and the roundtrip.

## 2026-09-21 — The walk is queue-free: chain application, not orchestration (#116)

- `apply_block` loses its `NameNoteQueue` parameter and its
  confirmation-time `fulfill` call. The queue has one writer now —
  `main`'s enactment drain — and the walk applies the chain to the
  registry, wallet, and Treasury intake only. Boot's never-read
  `scratch_orders` fixture dies with the parameter.
## 2026-09-21 — The relay lane, extracted: two entrances, one policy (#121)

- `relay` is the relay-lane body lifted verbatim from the run loop:
  the decided-refusal battery, the challenge fee, and the OTP
  challenge they pay for, parameterized by the trigger's height and
  a lane label. `NameRecord::admits` names the record's five
  refusals where its data lives (registry.rs); its second caller
  arrives in the same diff. `watch_mempool` is the quick path's
  reader — announce, fetch, decrypt, forward; it classifies exactly
  as `apply_block` does and decides nothing. The block pass stays
  the only intake: the reader records nothing, and a gap in the
  stream is a gap in quickness, never in truth.

## 2026-09-21 — Pre-sale AccessCode + publishable key (#83)

- `Request::Claim.code` is `Option<AccessCode>` (six-digit, OTP-shaped:
  redacted `Debug`, `Zeroize`, `ct_eq`). Codes are TEE-derived
  (access-code-v1 HMAC), not stored in Supabase.
- `mint::presale` looks up `zn_protected_names` with the project
  publishable key; protected rows require the matching memo code. Open
  names skip the code. Unavailability returns `Decision::Retry`.
  Redemption is the name live in the registry — the mint never writes
  the table. `GENERAL_AVAILABILITY_DAY` closes the window on the day
  clock.

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

## 2026-09-17 — `apply_block`: one body for block application (issue #55)

- `mint::apply_block` applies one verified canonical successor to every
  faculty: scan, clock, Registry law, wallet commit, Treasury intake,
  Name Note storage, order fulfillment, cursor. It returns nothing —
  every output is caller-owned state passed as `&mut` — and never
  fetches or broadcasts. `main` passes the live queues; boot passes
  scratch ones, so history is balance by construction.
- The confirmation pass lives here: the scanner's transactions in
  canonical order, the ZNS decryption lane joined on txid — the
  authentication boundary — each candidate offered to the Registry
  (`accept_claim` / `accept_update` / `accept_release`). Sequencing is
  the caller of the law; the law is the Registry's.
- Accepted Name Note commitments are marked at the wallet commit via
  `put_blocks_marked` — the scanner cannot decrypt ZNS-domain outputs,
  so they would otherwise enter the Ironwood tree Ephemeral, prune with
  the checkpoints, and leave a dormant name's update FATAL on a
  missing witness.
- The continuity asserts (`from_state` describes the cursor; the block
  extends it) moved inside the body — boot inherits them and now dies
  loudly on a Zebra fork mid-sync instead of silently building on one.
