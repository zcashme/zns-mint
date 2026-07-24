# Harness Task Record

Copy this section for each bounded implementation slice. A record is evidence
of process, not evidence that an invariant is satisfied.

```text
Slice:
Invariant IDs:
Root owner:
Writer and exact file lease:
Initial dirty-worktree snapshot:

Authority read:
Matching changelog and blob hash:
Upstream crate and pinned revision:
Exact upstream APIs (path, lines, signature or trait bound):

Observed repository facts:
Inferences:
Contradictions:
Unresolved questions:

Design:
Rejected alternatives:
Assumptions:
Failure modes:

Files changed:
Tests written:
Commands actually run and exit status:
Independent review findings:
Coverage rows updated:
Remaining evidence:
Uncommitted changes:
```

## 2026-07-24 — Remove the per-block Treasury request queue

```text
Slice:
Delete the unused requests_in_block placeholder and its event-oriented design
contract without adding a replacement request API.

Invariant IDs:
NAME-009, SYNC-007, SYNC-009, AUTH-001; HARNESS-002, HARNESS-003,
HARNESS-006.

Authority and evidence:
Read AGENTS.md, the invariant catalog, Treasury source, the complete Treasury
design, request parser, Wallet received-note storage, and every repository
reference to requests_in_block. The method had no caller and always returned
an empty slice. No upstream API or Zcash representation changes in this local
dead-API deletion.

Design:
Wallet note and transaction state retain canonical memo evidence. Future Live
work will parse and reconcile Wallet with Registry state after exact-tip
verification. Treasury owns no height-indexed request queue. This deletion
does not decide which observations are pending. RequestMemo,
RequestMemo::parse, Wallet memo storage, payment matching, and all policy
methods remain intact. No pending_requests replacement was introduced.

Failure modes:
Deleting canonical memo evidence or the strict parser together with the dead
queue; reintroducing per-block event delivery under another name; or claiming
that request reconciliation is implemented. The source edit removes only the
empty method, and coverage remains sourced rather than tested.

Files changed:
src/treasury.rs; new matching src/treasury.changelog.md;
docs/design/15-treasury-module.md; tests/runtime_replay_boundary.rs;
docs/harness/coverage.csv; this task record.

Tests written:
The runtime boundary guard rejects a Treasury requests_in_block surface.

Commands:
Read-only source/status searches and git diff checks are recorded in the
session. No Cargo command, formatter, build, test, commit, or push was run.

Pre-existing uncommitted state:
The eight-file unit-return canonical-fold slice was already uncommitted at
f1e6b9224b3bee2bc7e6fe7f4fa98f5d7ecc1166 and was preserved.
```

## 2026-07-24 — Canonical fold returns only transition status

```text
Slice:
Remove the redundant height result from apply_canonical_block. A successful
fold returns unit, and its caller reads the exact cursor promoted last.

Invariant IDs:
SYNC-005, SYNC-006, SYNC-009, SYNC-010; HARNESS-001, HARNESS-002,
HARNESS-003, HARNESS-006.

Authority and evidence:
Read AGENTS.md, the invariant catalog, main and run-loop changelogs, current
source/tests, and pinned librustzcash
a97a3d5f46d096b94ceb71271c7d38f20af4e1f1. At that revision,
zcash_client_backend::data_api::BlockMetadata::block_height returns the typed
height, ScannedBlock::to_block_metadata constructs the exact scanned metadata,
and scanning::full::scan_block rejects height/hash discontinuity against prior
metadata.

Design:
Canonical folding is a state transition, not an event-delivery interface. It
returns Result<(), RuntimeError>. After success, canonical gauges read the
promoted cursor. Future Live behavior reconciles installed Wallet, Registry,
and cursor state after exact-tip verification; it will not consume replayed
per-block events. CommittedBlock and raw BlockOutput return alternatives were
rejected because both preserve the wrong event-oriented boundary.

Failure modes:
Publishing gauges after a failed fold, reading pre-promotion height, weakening
cursor-last ordering, or silently retaining the obsolete CommittedBlock design.
The source ordering is unchanged and errors still return before publication.

Files changed:
src/main.rs and its changelog; docs/design/07-mint-run-loop.md and changelog;
tests/runtime_replay_boundary.rs; docs/harness/invariants.md;
docs/harness/coverage.csv; this task record.

Tests written:
The existing canonical-applicator boundary guard now requires a unit result,
rejects CommittedBlock event handoff, and requires post-fold gauges to read the
promoted cursor.

Commands:
Read-only source/upstream/status searches and git diff checks are recorded in
the session. No Cargo command, formatter, build, test, commit, or push was run.

Uncommitted state:
This slice remains uncommitted. The worktree was clean at
f1e6b9224b3bee2bc7e6fe7f4fa98f5d7ecc1166 before the slice.
```

## 2026-07-24 — Scanner metadata as sole accepted-height source

```text
Slice:
Delete the duplicate accepted block height from BlockOutput and derive Wallet,
Registry, and validated Name Note heights only from scanner-owned metadata.

Invariant IDs:
SYNC-003, SYNC-005, SYNC-006; HARNESS-001, HARNESS-002, HARNESS-003,
HARNESS-006.

Authority and evidence:
Read AGENTS.md, the invariant catalog, the matching sync/Wallet/Registry
changelogs, current source and call sites, and pinned librustzcash
a97a3d5f46d096b94ceb71271c7d38f20af4e1f1. At that revision,
zcash_client_backend::data_api::BlockMetadata exposes
block_height(&self) -> BlockHeight, and ScannedBlock::to_block_metadata()
constructs metadata containing the scanned height, hash, and three final tree
sizes. The upstream scanner rejects height and predecessor-hash discontinuity
before producing that ScannedBlock.

Design:
BlockOutput retains only BlockMetadata as accepted block identity. Wallet
application, Registry history, and NameNoteLocator read its typed height
accessor explicitly. The input height remains only where decryption and the
upstream scan API require it. Keeping two fields plus an equality assertion was
rejected because it leaves contradictory evidence representable; retaining a
height convenience accessor was rejected because it obscures the sole
authority.

Files changed:
src/sync.rs, src/wallet.rs, src/registry/state.rs; their matching changelogs;
tests/runtime_replay_boundary.rs; docs/harness/coverage.csv; this task record.

Tests written:
A static boundary test isolates BlockOutput, rejects an independent height
field and height accessor, and requires Wallet, Registry, and NameNoteLocator
to read scanner metadata.

Commands:
Read-only source/upstream/status searches and git diff checks are recorded in
the session. No Cargo command, build, test, commit, or push was run.

Uncommitted state:
This slice remains uncommitted inside the broad pre-existing dirty worktree.
```

## Review gates

- No source edit precedes the changelog receipt and root design critique.
- No upstream citation is accepted until the root reopens it at the pinned
  revision.
- No parallel writer or unleased file edit is allowed.
- No unresolved protocol decision is silently chosen.
- No production secret or decrypted production traffic enters a prompt,
  transcript, fixture, log, error, metric, or artifact.
- No test is recorded as executed unless its command and exit status are
  captured.
- No critical invariant is closed from compilation or a happy path alone.

## 2026-07-22 — Treasury refund transaction hardening

```text
Slice:
Harden the drafted Orchard-payment/Ironwood-refund transaction library without
extending unresolved runtime submission behavior.

Invariant IDs:
TX-001, TX-003, TX-004, TX-005, TX-006, AUTH-001, KEY-002,
HARNESS-001, HARNESS-002, HARNESS-003, HARNESS-005, HARNESS-006.

Root owner:
/root

Writer and exact file lease:
/root exclusively leased src/treasury/assemble.rs,
src/registry/signing.rs, src/treasury/assemble.changelog.md,
src/registry/signing.changelog.md, docs/design/09-transaction-assembly.md,
docs/harness/invariants.md, docs/harness/coverage.csv, and
docs/harness/task-record.md. A post-review corrective lease added src/wallet.rs,
src/wallet/trees.rs, src/wallet.changelog.md, and returned
src/treasury/sweep.changelog.md to sweep-only ownership.

Initial dirty-worktree snapshot:
HEAD 35dad3d829fe29f60345400c9c38d8b9862f235b. Twenty-one tracked files were
already modified (including a 979-line src/main.rs rewrite), src/zcash/submit.rs
was deleted, and .agents/, docs/harness/, several changelogs, and
src/treasury/assemble.rs were untracked. Every unrelated change was preserved.

Authority read:
AGENTS.md; docs/harness/invariants.md; docs/protocol.md;
docs/design/09-transaction-assembly.md; docs/design/15-treasury-module.md;
src/main.changelog.md; src/registry/signing.changelog.md;
src/treasury/sweep.changelog.md; all repository Rust mapped by the read-only
repository reviewer.

Matching changelog and blob hash:
src/registry/signing.changelog.md (b491e59f3bdbee3c2f685e9e1676451585146982),
src/treasury/assemble.changelog.md (7db21433cbad47ee9d29a5df5b8dbdf75f693d11),
and src/wallet.changelog.md (f30e12fee79e455dfd413624a564be7af595478c).
These are uncommitted Git blob hashes, not commit revisions.

Upstream crate and pinned revision:
librustzcash a97a3d5f46d096b94ceb71271c7d38f20af4e1f1. Orchard fork checkout
689c8954d06c9251c0ba412e91705fb2ade0031a, based on
34699d38695ad28c37a022155df5420760a29741 plus the documented compile fix.
Cargo still references Orchard by absolute path and does not enforce that hash.
ShardTree 0.6.2 is registry-pinned by Cargo.lock.

Exact upstream APIs (path, lines, signature or trait bound):
- zcash_primitives/src/transaction/fees.rs:19-35, FeeRule::fee_required.
- zcash_primitives/src/transaction/fees/zip317.rs:157-197, logical-action sum.
- zcash_primitives/src/transaction/mod.rs:396-418, from_parts_v6;
  464-507, fee_paid; 731-745, txid/read; 958-963, write.
- zcash_protocol/src/memo.rs:86-102, MemoBytes::empty and all-zero warning.
- zcash_protocol/src/txid.rs:23-40, RPC/display byte order.
- zcash_keys/src/address.rs:143-147, UnifiedAddress::orchard; 391-407,
  Address::decode; 434-452, Ironwood shares the Orchard receiver.
- unsafe-zns Orchard builder.rs:79-151, BundleType::DEFAULT/num_actions;
  925-945, add_spend; 984-1007, add_output; 1032-1055,
  add_change_output; 1145-1159, build; 1597-1618, create_proof;
  1713-1730, apply_signatures.
- unsafe-zns Orchard bundle.rs:97-176, V3 versions/flags/circuit;
  552-556, value_balance; 982-998, verify_proof.
- shardtree 0.6.2 src/lib.rs:1173-1229,
  root_at_checkpoint_depth/root_at_checkpoint_depth_caching; depth zero is the
  newest retained checkpoint and `None` requests the uncheckpointed latest tree.

Observed repository facts:
The drafted refund shape had correct arithmetic for its hard-coded 2+2 actions,
but lacked request/account binding, a final aggregate-fee check, canonical
no-memo bytes, an NU6.3 gate, and a current Ironwood anchor. The mixed
signer allowed a transparent-only call to reach a panic, used unchecked expiry
addition, and did not validate field bundle versions or cached key versions.

Inferences:
For the approved always-present refund output, standard ZIP-317 requires 20,000
zatoshis. At the threshold, refund is zero and Treasury change is
price + 200,000 - 20,000; the net retained surcharge is 180,000.

Contradictions:
The current src/main.rs runtime reselects a payment instead of consuming the
reserved locator; models a claim as two independently confirming transactions;
uses unapproved retry-every-block behavior; and has incomplete atomic/reorg
handling. docs/design/15-treasury-module.md also says the Treasury policy module
does not sign, while the inherited assembly source is nested under treasury.
Neither contradiction was resolved or extended in this slice.

Unresolved questions:
Payment confirmation depth; exact reserved-note consumption and replay meaning;
two-leg partial-settlement recovery; retry/backoff/replacement/expiry; metrics;
reorg reconciliation; assembly module placement; refund receiver fallback; and
reproducible Orchard dependency pinning.

Design:
Derive action counts from the actual V3 bundle flags; keep the user-approved
always-present Ironwood output; validate account, exact request memo, mainnet
NU6.3 activation, pool versions, anchors, expiry, cached circuit versions, and
aggregate value balance; place both effecting bundles before the shared sighash;
locally verify both proofs; keep the mixed helper crate-private. For the
output-only Ironwood bundle, use the newest retained checkpoint root rather than
requiring an exact target-height checkpoint ID.

Rejected alternatives:
Sapling/transparent fallback, V5 Orchard cross-address refund, omitting a zero
refund output, and runtime wiring that depends on unresolved policy.

Assumptions:
Claims use a mainnet UA containing an Orchard receiver; V6 construction occurs
at or after NU6.3; the gross surcharge includes the network fee; the current
Orchard and Ironwood bundles both use PostNu6_3.

Failure modes:
Action-count drift; wrong account or memo; underpayment/overflow; missing or
wrong anchor; pre-activation construction; wrong bundle field/version; cached
key mismatch; fee imbalance; post-sighash mutation; corrupted proof.

Files changed:
src/treasury/assemble.rs; src/registry/signing.rs; src/wallet.rs;
src/wallet/trees.rs; src/wallet.changelog.md;
src/treasury/assemble.changelog.md; src/treasury/sweep.changelog.md;
src/registry/signing.changelog.md; docs/design/09-transaction-assembly.md;
docs/harness/invariants.md; docs/harness/coverage.csv;
docs/harness/task-record.md.

Tests written:
Refund action-count shape; threshold and overpayment arithmetic; underpayment;
wrong-account and wrong-memo rejection; pre-NU6.3 rejection; missing-anchor
rejection; latest Ironwood root without an exact later checkpoint. No mutation,
proof-corruption, independent sighash, serialized-fee,
integration, Zebra, reorg, or TEE test was added.

Commands actually run and exit status:
- `git status --short`, targeted `git diff`, `git diff --check`, `git rev-parse
  HEAD`, and `git hash-object ...`: exit 0.
- `rg -n ...`, `sed -n ...`, and `nl -ba ...` over repository and pinned
  upstream sources: exit 0 except explicit no-match/path-discovery probes.
- `wc -l`, then `sed -n '1,650p'`, `sed -n '651,1400p'`, and
  `sed -n '1401,2070p'` over ShardTree 0.6.2 README/lib.rs: exit 0.
No Cargo command, formatter, build, test, commit, or push was run after this
hardening edit. The prior handoff reported green Cargo commands before these
edits; they are not evidence for this state.

Independent review findings:
Three read-only reviews identified hard-coded action counts, missing exact fee
postcondition, pre-NU6.3 construction, transparent-only panic, wrong txid display
order, payment rematching, unreserved Registry fee notes, two-leg partial
settlement, retry/expiry gaps, reorg defects, module-boundary conflict, and an
unpinned Orchard path. The transaction-library pass fixed action derivation,
aggregate fee validation, activation/version/expiry checks, panic closure, and
signer ordering checks. A post-write review then identified and corrected the
output-only Ironwood anchor lookup, changelog ownership and signer-contract
wording, explicit refund-policy authority, stale coverage paths/evidence, and
inaccurate design prose. Runtime reservation, atomicity, retry, reorg, metrics,
txid representation, and typed signer-capability findings remain open and are
not claimed as fixed by this slice. The final adversarial corrective review
confirmed that ShardTree checkpoint depth zero is the newest retained root and
that this anchor is sound for the output-only Ironwood bundle; it found no
blocking regression and recommended stronger distinct non-empty-checkpoint and
Treasury integration tests as follow-up evidence.

Coverage rows updated:
KEY-002, AUTH-001, TX-001, TX-003, TX-004, TX-005, TX-006,
NAME-009, SYNC-010, TX-007, TX-008, HARNESS-001, HARNESS-002,
HARNESS-003, HARNESS-006.

Remaining evidence:
Execute the written tests; compile; independently decode a serialized refund and
verify fee/pools/versions; mutation and corrupted-proof tests; Zebra regtest at
NU6.3; resolve and test runtime reservation, atomicity, submission, reorg, and
TEE policy.

Uncommitted changes:
All changes remain uncommitted. The broad pre-existing dirty worktree was
preserved; no commit or push was performed.
```

## 2026-07-23 — Passive canonical replay cleanup

```text
Slice:
Delete replay-reachable operational behavior and remove locks/reservations from
canonical state before introducing the exact-target Rebuild/Live architecture.

Invariant IDs:
NAME-009; SYNC-005 through SYNC-010; AUTH-001, AUTH-005, AUTH-006;
TX-002, TX-007, TX-008; HARNESS-002, HARNESS-003, HARNESS-006.

Root owner:
/root

Writer and exact file lease:
/root was the sole writer. The lease covered src/main.rs, src/wallet.rs,
src/wallet/selection.rs, src/registry/state.rs,
src/registry/transaction.rs, their matching changelogs,
src/zcash.rs and src/zcash.changelog.md,
docs/design/07-mint-run-loop.md, docs/design/08-chain-sync.md,
docs/design/09-transaction-assembly.md, docs/design/14-wallet-design.md,
their changelogs, tests/runtime_replay_boundary.rs, and the three harness
records.

Initial dirty-worktree snapshot:
HEAD 35dad3d829fe29f60345400c9c38d8b9862f235b. Twenty-nine tracked files
already differed from HEAD, src/zcash/submit.rs was deleted, and .agents/,
docs/harness/, multiple changelogs, and src/treasury/assemble.rs were
untracked. git diff --check was initially clean. Unrelated edits were
preserved.

Authority read:
AGENTS.md; .agents/skills/build-zns-mint/SKILL.md;
docs/harness/invariants.md; run-loop, chain-sync, transaction, and Wallet
design documents; all matching source changelogs; current runtime, Boot,
sync, Wallet, Registry, auth, Treasury, metrics, and RPC sources.

Matching changelog and blob hash:
Before editing: src/main.changelog.md
b2b01676f6dacae2b7837a5dce449b009237fb3c;
src/wallet.changelog.md ae3423711b5f614846c4b9fe7f4da4215ba26020;
src/registry/state.changelog.md
4c4ee9f0908e63abe5431923b4987a50dfc978b0; and
src/registry/transaction.changelog.md was read in full. These identify
uncommitted blobs, not repository revisions.

Upstream crate and pinned revision:
librustzcash a97a3d5f46d096b94ceb71271c7d38f20af4e1f1;
shardtree 0.6.2.

Exact upstream APIs (path, lines, signature or trait bound):
- zcash_client_backend/src/data_api.rs:2457-2518:
  #[derive(Debug, Clone, Copy)] pub struct BlockMetadata { ... }.
- zcash_client_backend/src/data_api.rs:2668-2691:
  ScannedBlock::to_block_metadata(&self) -> BlockMetadata.
- zcash_client_backend/src/scanning/full.rs:425-478:
  scan_block verifies next height and previous block hash against prior
  metadata.
- zcash_primitives/src/block.rs:79-131 and 325-353:
  Block header/hash surfaces and the warning that claimed height is not
  authoritative before selected-chain validation.
- shardtree 0.6.2 src/lib.rs:267-358, 456-547, 655-698:
  append/frontier/checkpoint/truncate operations are fallible.

Observed repository facts:
Every replay-reachable request, OTP, reservation, Treasury-policy, proving,
signing, retry, submission, and lifecycle-counter path originated in
src/main.rs. Wallet embedded a BTreeSet<NoteLocator> reservation set; Registry
embedded a BTreeSet<Name> lock set. apply_block also accepted a duplicate
caller-supplied current height despite scanner-owned metadata. NoteLocator and
the opaque exact RegistryFeeInputs plan were neutral planning identities.

Inferences:
The safety cleanup is deletion-dominant and policy-neutral. Canonical request
memos, txids, received/spent notes, nullifiers, commitment streams, validated
Name Notes, and transaction history remain sufficient for later semantic
reconstruction. A future Live owner can supply explicit exclusion sets without
placing operational state back inside Wallet.

Contradictions:
Historical changelog entries described active replay as locally atomic even
though it issued OTPs and reservations before cursor promotion and could prove
and broadcast historical work. Run-loop and Wallet design prose described
deleted scanner/queue shapes and embedded reservation ownership. Coverage
still marked the unsafe runtime as contradicted implementation.

Unresolved questions:
Exact-target capture and Rebuild-to-Live transition; same-height and shorter
reorg detection; staged rollback/crash semantics; semantic atomic-claim
recovery; OTP burn/reissue; and typed retry/replacement/confirmation policy.

Design:
Keep one synchronous apply_canonical_block that receives only block/scanning
inputs, Wallet, Registry, cursor, and accepted history. Scan, simulate
Registry, apply Wallet, install Registry, then promote scanner-derived metadata
last. Give catch-up a read-only block-source facade; retry only typed transport
availability failures. Keep canonical gauges outside the applicator and
republish them after boot, commit, and rewind. Delete every operational runtime
path. Move fee-planner exclusions to an explicit caller-owned set.

Rejected alternatives:
A replay boolean around effectful code; silently selecting all fee notes after
removing reservations; inventing a replacement Live state owner in this
cleanup; deleting exact note locators/plans; and partially implementing phase
types without exact-target and recovery policy.

Assumptions:
Passive canonical reconstruction is preferable to retaining unapproved live
behavior. Wallet::apply_block prior_height remains necessary rollback input
and is not duplicate current-height state. Existing same-height/shorter reorg
gaps remain release blockers and are documented rather than hidden.

Failure modes:
Loss of canonical request/payment evidence; cursor promotion before subsystem
acceptance; operational capability leaking back into replay; selector
weakening; stale locks surviving canonical clone/rewind; replay-multiplied
events; and overstating Live/reorg safety in docs or coverage.

Files changed:
src/main.rs; src/main.changelog.md; src/wallet.rs;
src/wallet/selection.rs; src/wallet.changelog.md;
src/registry/state.rs; src/registry/state.changelog.md;
src/registry/transaction.rs; src/registry/transaction.changelog.md;
src/registry.changelog.md; src/zcash.rs; src/zcash.changelog.md;
docs/design/07-mint-run-loop.md and changelog;
docs/design/08-chain-sync.md and changelog;
docs/design/09-transaction-assembly.md and changelog;
docs/design/14-wallet-design.md and changelog;
tests/runtime_replay_boundary.rs; docs/harness/invariants.md;
docs/harness/coverage.csv; docs/harness/task-record.md.

Tests written:
Static source-boundary tests reject operational invocations in main, RPC or
live inputs in apply_canonical_block, caller-supplied current height, and
operational reservation/lock fields or APIs in Wallet/Registry. A typed error
test distinguishes retryable transport availability from fatal HTTP/client
input and malformed checkpoint/node data. Tests were not executed because the
user did not authorize Cargo commands.

Commands actually run and exit status:
Read-only rg, sed, nl, wc, git status, git diff, git hash-object, and
git diff --check commands; relevant probes and the final statuses are recorded
in the session. `rustfmt --edition 2021 --check` first reported three local
formatting deltas; they were applied surgically and the second check exited 0.
No Cargo command, build, test, commit, or push was run.

Independent review findings:
Three read-only reviews agreed that all unsafe runtime effects were rooted in
main; Wallet reservations and Registry locks were project-local contamination;
BlockMetadata is Copy; scanner metadata is the accepted height source; exact
NoteLocator planning should remain; Registry selection must accept external
exclusions; counters must leave replay; and exact-target/reorg/recovery work
must remain explicit follow-up. Post-write review first found a
submission-capable read RPC, broad retry classification, stale gauges after
rewind, and stale Wallet/chain-source prose. The corrective review verified the
read-only facade, fail-closed retry split, boot/commit/rewind gauge publication,
fully replaced Wallet design, and conservative harness claims. It found no
cleanup-introduced blocker. Staged tree atomicity, exact-target/CommittedBlock,
same-height/shorter reorgs, and semantic recovery remain explicit follow-ups.

Coverage rows updated:
NAME-009; SYNC-005, SYNC-006, SYNC-008, SYNC-009, SYNC-010;
SYNC-011; AUTH-001; TX-007; TX-008.

Remaining evidence:
Execute the written boundary tests; compile only when authorized; add
poison-spy replay, staged fault injection, arbitrary restart equivalence,
same-height/shorter/multi-block reorg, stale operational-state, metric, and
Zebra atomic-claim tests after the phase and recovery designs land.

Uncommitted changes:
All changes remain uncommitted. The broad pre-existing dirty worktree is still
present; no commit or push was performed.
```

## 2026-07-24 — Delete standalone claim refund

```text
Slice:
Delete the Treasury-only refund transaction before designing the one atomic
payment-settlement and Name Note transaction.

Invariant IDs:
AUTH-001; TX-001; TX-003; TX-004; TX-005; TX-006;
HARNESS-001; HARNESS-002; HARNESS-003; HARNESS-006.

Root owner and writer:
/root was the sole writer.

Initial state:
HEAD f70942aeeadc60a1b261eec21c1ac87115ffb691. The worktree was clean and
git diff --check exited 0.

Authority and design records read:
AGENTS.md; .agents/skills/build-zns-mint/SKILL.md;
docs/harness/invariants.md; src/treasury/assemble.changelog.md;
src/treasury.changelog.md; src/registry/signing.changelog.md;
src/registry/transaction.changelog.md; docs/design/09-transaction-assembly.md
and its changelog; docs/design/15-treasury-module.md.

Pinned upstream evidence:
librustzcash a97a3d5f46d096b94ceb71271c7d38f20af4e1f1.
The root README and zcash_primitives README/lib.rs were read. In
zcash_primitives/src/transaction/mod.rs:308-322, TransactionData has distinct
Orchard and Ironwood bundle fields. At lines 383-419,
TransactionData::from_parts_v6 accepts both fields in one V6 transaction.

Observed facts:
src/treasury/assemble.rs owned only the standalone refund transaction.
build_refund_transaction had no caller outside its own unit tests. It spent the
Treasury payment and emitted Treasury change plus an Ironwood refund, but it
could not create the corresponding Name Note. The crate-private
registry::signing::assemble_v6_transaction is separate: it accepts optional
Orchard and Ironwood bundles plus typed Treasury and Registry signers, installs
all effecting bundles before the shared sighash, then proves and signs them.

Design and rejected alternatives:
Delete the entire refund module, export, tests, and obsolete child changelog.
Preserve payment matching, Registry transaction planning, and the generic mixed
V6 signer. Do not adapt the refund builder because that would retain a
Treasury-only settlement boundary. Do not add the atomic replacement until its
complete ZIP-317 fee basis/account contribution and semantic recovery rules are
settled.

Failure modes:
Deleting shared mixed signing; weakening exact payment/memo matching; retaining
a hidden callable refund path; claiming atomic settlement is implemented; or
silently applying the old standalone-refund fee arithmetic to the aggregate
atomic transaction.

Files changed:
Deleted src/treasury/assemble.rs and
src/treasury/assemble.changelog.md. Updated src/treasury.rs,
src/treasury/fee.rs, src/treasury.changelog.md,
src/treasury/sweep.changelog.md, docs/design/09-transaction-assembly.md and
changelog, docs/harness/invariants.md, docs/harness/coverage.csv,
docs/harness/task-record.md, and tests/runtime_replay_boundary.rs.

Verification:
The static boundary test rejects re-exporting a Treasury-only assemble module.
Repository searches found no refund constructor, request, helper, or module
reference in Rust source. The retained mixed signer still has both bundle
inputs and both V6 construction points, and its blob is unchanged from HEAD.
The final diff was reviewed and git diff --check exited 0. Cargo commands and
formatting were not authorized and were not run, so the static test remains
unexecuted.

Uncommitted state:
All changes remain uncommitted; no commit or push was performed.
```

## 2026-07-24 — Delete Treasury fee module

```text
Slice:
Delete the misleading one-function treasury::fee module after explicit user
direction assigned the complete atomic claim fee to Registry.

Invariant IDs:
KEY-004; AUTH-001; TX-001; TX-003;
HARNESS-001; HARNESS-002; HARNESS-003; HARNESS-006.

Root owner and writer:
/root was the sole writer.

Initial state:
HEAD f70942aeeadc60a1b261eec21c1ac87115ffb691. The preceding standalone-refund
deletion remained uncommitted as a 12-file dirty diff with 141 insertions and
548 deletions. git diff --check exited 0. Those changes were preserved and this
slice intentionally builds on them.

Authority and design records read:
AGENTS.md; .agents/skills/build-zns-mint/SKILL.md;
docs/harness/invariants.md; src/treasury.changelog.md;
src/treasury/memo.changelog.md; src/wallet.changelog.md;
docs/design/09-transaction-assembly.md and changelog;
docs/design/15-treasury-module.md; current Treasury, payment matcher, strict
memo parser, and received-note sources.

Pinned upstream evidence:
librustzcash a97a3d5f46d096b94ceb71271c7d38f20af4e1f1.
components/zcash_protocol README, src/lib.rs, and src/value.rs were read.
At value.rs:268-311, Zatoshis::from_u64 accepts only 0..=MAX_MONEY and
Zatoshis::into_u64 returns the checked value. The unsafe-zns Orchard checkout
README and src/lib.rs, src/note.rs, and src/value.rs were read. Note::value at
src/note.rs:350-357 returns NoteValue; NoteValue::inner at
src/value.rs:100-116 returns its u64.

Observed facts:
src/treasury/fee.rs contained only match_fee. Its sole caller was
Treasury::match_payment. It computed no transaction fee: it rejected non-claim
requests, scanned Treasury Orchard notes, compared value against a checked
minimum, strictly reparsed the memo, and required exact RequestMemo equality.
docs/design/15-treasury-module.md already assigned this behavior directly to
Treasury::match_payment.

Explicit policy:
Payment is at least the caller-supplied price. Treasury retains exactly price
and refunds payment minus price through an always-present Ironwood output.
Registry fee notes fund the complete atomic transaction's aggregate ZIP-317
fee. There is no fee-derived Treasury surcharge.

Design and rejected alternatives:
Inline the exact predicate into Treasury::match_payment and delete the module.
Do not rename the module, which would preserve a needless boundary. Do not use
a raw-u64 shortcut, which would bypass the existing checked Zatoshis
conversion. Do not add an atomic planner in this deletion slice.

Failure modes:
Relaxing the claim-only check, scanning a non-Treasury account, weakening
strict memo equality, changing invalid-price behavior, or retaining a
Treasury-owned transaction-fee policy.

Files changed:
Deleted src/treasury/fee.rs. Updated src/treasury.rs,
src/treasury.changelog.md, docs/design/09-transaction-assembly.md and
changelog, docs/harness/invariants.md, docs/harness/coverage.csv,
docs/harness/task-record.md, and tests/runtime_replay_boundary.rs.

Verification:
The static boundary test rejects re-exporting treasury::fee. Repository search,
found no live Rust reference to treasury::fee or match_fee. Manual predicate
comparison confirmed the same checked price conversion, claim-only filter,
Treasury-account iterator, minimum-value comparison, strict memo parse, and
exact typed equality. The combined diff was reviewed and git diff --check
exited 0. Cargo commands and formatting were not authorized and were not run,
so the static test remains unexecuted.

Uncommitted state:
This slice and the preceding standalone-refund deletion remain uncommitted; no
commit or push was performed.
```

## 2026-07-24 — Delete unsafe Treasury selection and implement exact-target Rebuild

```text
Slice:
Delete the unused exclusion-free Treasury::select_funds wrapper, audit the
remaining production APIs for obsolete event/atomicity/reservation boundaries,
and implement exact-target passive reconstruction with supported reorg,
crash-boundary, and restart-schedule fixtures. Add no Live behavior.

Invariant IDs:
SYNC-003, SYNC-005, SYNC-006, SYNC-008, SYNC-009, SYNC-010;
TX-002; HARNESS-001, HARNESS-002, HARNESS-003, HARNESS-005, HARNESS-006.

Root owner and writers:
/root was the sole writer. Three skill workers gathered upstream, repository,
and adversarial evidence read-only. No worker edited files.

Initial state:
HEAD f79416852af12e5609baf32fd1091e3b0d7ff45b. The worktree was clean and
git diff --check exited 0.

Authority and design records read:
AGENTS.md; .agents/skills/build-zns-mint/SKILL.md; the complete invariant
catalog; src/main.changelog.md; src/zcash.changelog.md;
src/wallet.changelog.md; src/registry/state.changelog.md;
src/treasury.changelog.md; docs/design/07-mint-run-loop.md,
08-chain-sync.md, 14-wallet-design.md, 15-treasury-module.md, and their
matching changelogs; current source, tests, and call sites.

Pinned upstream evidence:
librustzcash a97a3d5f46d096b94ceb71271c7d38f20af4e1f1.
zcash_client_backend/src/data_api.rs:2457-2517 defines copyable
BlockMetadata and its private height/hash/tree-size accessors.
data_api.rs:2585-2691 defines ScannedBlock::to_block_metadata from the exact
scanned height, hash, and three final tree sizes.
zcash_client_backend/src/scanning/full.rs:425-474 defines full::scan_block and
rejects a height other than prior+1 or a prev_hash other than prior.hash.
zcash_primitives/src/block.rs:33-77 and 79-177 define BlockHash display order,
BlockHeaderData::freeze, BlockHeader::hash, and public prev_block.
block.rs:179-354 defines Block parsing and claimed_height.
zcash_primitives/src/transaction/mod.rs:308-419 defines TransactionData and
from_parts_v6; transparent/src/builder.rs:332-360 and 473-493 define the
coinbase authorization mapper and build_coinbase used only by test fixtures.
shardtree 0.6.2 src/lib.rs:507-516, 550-564, 680-750, and 1125-1143 define
checkpoint insertion/pruning, truncate_to_checkpoint, and exact checkpoint
root lookup.

Phase 0 result:
Deleted Treasury::select_funds. It had no production caller and always
constructed an empty exclusion set. The audit found the same shortcut in the
unwired treasury::sweep and treasury::note request modules, so those modules,
their request types, Treasury forwarding methods, and unused last-sweep state
were deleted as well. Preserved
wallet::selection::{select_funds, select_sapling_funds}, whose callers must
provide exclusions. Added no replacement API.

Audit result:
No live Rust definition or call remains for requests_in_block,
CommittedBlock delivery, project_live_effects, standalone claim refund, or
treasury::fee. Treasury evidence accessors and payment matching are pure
canonical evidence/policy. RegistryFeeLiquidity remains pure Registry policy
and selects no note. No production Treasury API now owns a default-empty
exclusion set, per-block event queue, or half of an atomic claim.

Phase 1 design:
CanonicalTip binds one height/hash pair from one getblockchaininfo response.
Every fetched block validates its coinbase-claimed height, and every successful
block read and common-ancestor outcome is followed by an exact-tip recheck.
Moving targets discard the read/result and restart target capture. Comparison
begins at min(local,target), history must be contiguous, and same-height,
shorter, and deeper replacement branches rewind through one common path.

Wallet rewind preflights exact Orchard, Ironwood, and Sapling checkpoints
before any pool mutation. Trees rewind before balance/nullifier history;
Registry, accepted history, and cursor follow. Accepted metadata and each tree
retain 101 checkpoints: current plus 100 predecessors. History installs before
cursor, and gauges publish only after final exact-target verification.

Failure and schedule evidence written:
The canonical fold exposes an internal no-op production hook with before/after
boundaries around scan, Registry simulation, Wallet installation, Registry
installation, accepted history, and cursor promotion. Tests panic at all
twelve boundaries, discard interrupted in-memory state, rebuild from origin,
and compare against uninterrupted state. Before discard, each boundary asserts
the Orchard/Ironwood checkpoint, accepted-history, and cursor visibility
expected from the ordered stages. The empty fixtures cannot make Registry,
balance/nullifier, or Sapling-stage installation observable. A private
read-only source trait lets tests feed structurally valid parsed V6 coinbase
blocks through the production scanner, Wallet,
Registry, trees, cursor, and history. Fixtures cover exact advancement,
same-height/shorter/deep replacement, successful-read target movement,
movement after a partial fold and during multiple ancestor reads, movement
before apparent retained-floor failure, history gaps, restart masks, prefix
restarts, each missing tree checkpoint, successful three-pool rewind, and the
full retention boundary.

Limitations:
The deterministic branch blocks contain no received/spent shielded notes or
Name Notes. The property therefore exercises the real scanner and canonical
owners but does not yet satisfy SYNC-008/SYNC-009 evidence for non-empty note
sets, witnesses, or Registry tips. No Live state exists to invalidate.
All new tests remain unexecuted because Cargo execution was not authorized.

Failure modes reviewed:
Combining height/hash from separate tips; accepting a successful read from a
moved target; treating a moving-target retained-floor result as fatal; asking
above a shorter tip; skipping a history gap; pruning the ancestor required for
a full 100-block rewind; mutating one tree before discovering a missing pool;
publishing intermediate rewind state; promoting cursor before history; or
allowing a crash boundary to perform operational work.

Files changed:
src/main.rs and changelog; src/zcash.rs and changelog; src/wallet.rs,
src/wallet/trees.rs, and wallet changelog; src/treasury.rs and changelog;
deleted src/treasury/note.rs, src/treasury/sweep.rs, and the sweep changelog;
docs/design/07-mint-run-loop.md, 08-chain-sync.md, 14-wallet-design.md,
15-treasury-module.md and matching changelogs; docs/harness/invariants.md,
docs/harness/coverage.csv, this task record; tests/runtime_replay_boundary.rs.

Verification:
The full diff was reviewed, forbidden-symbol/call-site searches were run, and
git diff --check exited 0. No formatter, build, test, commit, or push was run.
One read-only repository worker accidentally ran
cargo metadata --no-deps --format-version 1; it exited 0 and changed no file,
dependency, build artifact, or test result.

Uncommitted state:
All changes remain uncommitted. No commit or push was performed.
```
