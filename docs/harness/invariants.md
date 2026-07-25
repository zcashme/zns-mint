# ZNS Mint Invariant Catalog

This is the first contract of the ZNS mint agent harness. Agents may propose
implementations, but they may not weaken, reinterpret, or silently trade away
an invariant in this file.

The catalog describes properties that must remain true across implementation
changes. It deliberately does not prescribe a complete runtime architecture.
Where policy is unresolved, the issue is listed under **Decisions required**
instead of being guessed into an invariant.

## Authority and change control

Invariant IDs are permanent. An ID may be retired with an explanation, but it
must never be reused for a different property.

The authority order is:

1. an explicit user decision;
2. `AGENTS.md` trust-boundary rules;
3. this catalog's stable invariants;
4. `docs/protocol.md` protocol rules;
5. design documents under `docs/design/`;
6. source code and tests, which are evidence of implementation rather than
   authority when they conflict with the layers above.

Changing a critical or safety invariant requires an explicit user decision,
the matching protocol/design-document updates, updated tests, and an
adversarial review. Compilation alone is never evidence that an invariant
holds.

Severity labels:

- **Critical** — violation can expose namespace authority, create an invalid
  Name Note, or make the mint operate on the wrong chain.
- **Safety** — violation can lose funds, corrupt derived state, authorize the
  wrong transition, or mishandle a reorg.
- **Operational** — violation can make the service unavailable or
  unauditable without directly changing valid ownership.

## Upstream evidence for the Ironwood decision

The canonical decision is that Name Notes are Ironwood notes. Ironwood is a
distinct value pool that reuses Orchard-family types and cryptography; it is
not the Orchard value pool.

The `unsafe-zns` Orchard fork is currently sourced from the local checkout
`/Users/jules/ZcashNames/zns-orchard`. That checkout is based on the pinned
revision `34699d38695ad28c37a022155df5420760a29741`. The checkout exposes:

```rust
// /Users/jules/ZcashNames/zns-orchard/src/bundle.rs:106-113
pub const fn ironwood_v3() -> Self

// /Users/jules/ZcashNames/zns-orchard/src/builder.rs:953-960
pub fn add_zns_spend(
    &mut self,
    fvk: FullViewingKey,
    note: Note,
    merkle_path: MerklePath,
    rcm: pasta_curves::pallas::Scalar,
    psi: pasta_curves::pallas::Base,
) -> Result<(), SpendError>

// /Users/jules/ZcashNames/zns-orchard/src/builder.rs:1061-1069
pub fn add_zns_output(
    &mut self,
    ovk: Option<OutgoingViewingKey>,
    recipient: Address,
    value: NoteValue,
    memo: [u8; 512],
    rcm: pasta_curves::pallas::Scalar,
    psi: pasta_curves::pallas::Base,
) -> Result<(), OutputError>

// /Users/jules/ZcashNames/zns-orchard/src/note_encryption.rs:307-313
pub fn try_zns_note_decryption<T, P, F>(
    action: &Action<T>,
    ivk: &PreparedIncomingViewingKey,
    derive_opening: F,
) -> Option<ValidatedZnsNote<P>>
where
    F: FnOnce(&[u8; 512])
        -> Option<(pallas::Scalar, pallas::Base, P)>
```

The relaxed ZNS trial-decryption `Domain` and its candidate are private. The
public facade constructs a `NoteOpening`, compares its extracted commitment to
the action `cmx`, and returns only an opaque result retaining that opening and
the exact typed memo payload. Its nullifier API additionally requires an FVK
that owns the note recipient (`src/note_encryption.rs:227-335`).

`BundleVersion::ironwood_v3()` selects `ValuePool::Ironwood`, protocol V3,
V3 note plaintexts, and the post-NU6.3 circuit. The same file states that
Ironwood bundles exist only in V6 transactions
(`/Users/jules/ZcashNames/zns-orchard/src/bundle.rs:190-208`).

The pinned `librustzcash` revision
`a97a3d5f46d096b94ceb71271c7d38f20af4e1f1` keeps Orchard and Ironwood in
distinct V6 fields:

```rust
// zcash_primitives/src/transaction/mod.rs:396-405 at the pinned revision
pub fn from_parts_v6(
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
) -> Self
```

The same pinned revision exposes Ironwood separately during decryption through
`decrypt_transaction(...)` and `DecryptedTransaction::ironwood_outputs()`
(`zcash_client_backend/src/decrypt.rs:119-138,204-301` and
`zcash_client_backend/src/data_api.rs:2707-2768`). Orchard-family outputs from
the two pools must therefore never be merged merely because their Rust note
types are shared.

## Attested boundary and secrets

| ID | Severity | Invariant | Required evidence |
|---|---|---|---|
| `SEC-001` | Critical | The Registry spending key and its seed plaintext exist only inside the attested TEE. No human or operator can obtain them through any supported path. | Attestation-boundary review; negative tests for every input/output surface; production deployment test. |
| `SEC-002` | Critical | The seed enters only as an encrypted blob whose decryption key is bound to the intended TEE measurement and launch policy. Plaintext seed via environment variable, CLI argument, configuration file, stdin, RPC, log, or metric is forbidden. | Static forbidden-pattern scan; capsule tamper/wrong-measurement tests; attestation verification. |
| `SEC-003` | Critical | No repository runtime or harness code reads behavioral or secret configuration from environment variables or CLI flags. Deployment variation requires a new attested binary or an explicitly designed attestation-bound input. | Repository-wide static scan for environment/argument/config parsing, with zero unexplained matches. |
| `SEC-004` | Critical | Seed bytes, spending keys, authorizing keys, decrypted capsules, OTP secrets, and equivalent secret-bearing wrappers are never formatted, logged, serialized, included in errors, exposed in metrics, or copied outside the boundary. | Trait/static audit plus capture tests over logs, panics, errors, metrics, and serialized artifacts. |
| `SEC-005` | Critical | Plaintext seed buffers and derived temporary secret buffers are zeroized as soon as their final key objects have been derived. Failure paths zeroize before aborting. | Drop/failure-path review and focused zeroization tests where observable without exposing the secret. |
| `SEC-006` | Critical | Development escape hatches such as `dev-seed` and `pre-nu63-activation` cannot be present in a production artifact. | Release-artifact feature attestation and a build-policy test that rejects forbidden features. |
| `SEC-007` | Safety | The development agent harness remains outside the mint's trusted runtime. It never receives a seed capsule, spending key, production OTP, or production decrypted memo. | Harness architecture review and fixtures containing synthetic data only. |

## Accounts and capability separation

| ID | Severity | Invariant | Required evidence |
|---|---|---|---|
| `KEY-001` | Critical | One seed derives Treasury at ZIP-32 account `0` and Registry at account `1`; these indices are constants and may not be configured or swapped. | Unit vectors against upstream derivation plus static constant checks. |
| `KEY-002` | Critical | Registry account `1` is the sole signer for claim, update, and release Name Note transactions. Treasury account `0` can never authorize a Name Note. | Type/API boundary tests and transaction signer inspection. |
| `KEY-003` | Safety | Treasury account `0` receives name payments and request memos and is the shielded origin and fee payer for OTP relay transactions. | Address/account attribution tests and regtest transaction inspection. |
| `KEY-004` | Safety | Registry self-funds each Name Note transaction from Registry-owned Ironwood fee notes. Treasury may replenish Registry liquidity only through a separate Treasury-authorized transaction. | Cross-account transaction tests proving input ownership and value flow. |
| `KEY-005` | Critical | Scanning, policy, Registry state, Treasury policy, metrics, and submission tracking receive viewing material or opaque signing requests—not Registry spending authority. Spending keys are reachable only by the narrow assembly/signing boundary. | Visibility/call-graph audit and compile-fail tests where practical. |

## Name Note protocol

| ID | Severity | Invariant | Required evidence |
|---|---|---|---|
| `NAME-001` | Critical | Every Name Note is in an `ironwood_v3` bundle in the V6 transaction's `ironwood_bundle` field. The Orchard and Ironwood pools, commitment trees, anchors, nullifiers, and scanner outputs remain distinct. | Serialized transaction inspection, pool-specific scan tests, and negative tests placing a Name Note in `orchard_bundle`. |
| `NAME-002` | Critical | A Name Note has value `0` and is addressed to the Registry's external Orchard-family address so only Registry authority can spend it. | Builder tests and independent transaction decoding. |
| `NAME-003` | Critical | The `unsafe-zns` commitment override receives exactly the protocol-derived `(rcm, psi)`; no alternate commitment path or fallback standard note commitment may mint a Name Note. | Fork-level proof tests and independent commitment verification. |
| `NAME-004` | Critical | `psi` and `rcm` are derived exactly from `ZcashName/v1`, the field tag, canonical action bytes, canonical name, UA, and `prev_rcm` using the specified length-prefixing and BLAKE2b-512 wide reductions. | Sacred vectors shared byte-for-byte with the independent verifier plus mutation tests for every absorbed field. |
| `NAME-005` | Critical | A Name Note memo is exactly `ZNS:<verb>:<name>:<ua>:<prev_rcm_hex>`, strict ASCII, strict field count, lowercase hex, and zero-padded to 512 bytes. Release has an empty positional UA; a Name Note never contains an OTP. | Round-trip, rejection, boundary-length, and differential verifier tests. |
| `NAME-006` | Critical | A canonical name is 1 through 63 bytes of lowercase `a-z`, `0-9`, or `-`, with no leading or trailing hyphen. Validation never silently normalizes an on-chain name. | Exhaustive boundary/property tests and verifier differential tests. |
| `NAME-007` | Critical | Legal transitions are exactly: claim from unseen or released with zero `prev_rcm`; update from live with the tip's `rcm`; release from live with the tip's `rcm`. All other transitions are rejected before assembly. | State-machine model tests covering every state/action pair. |
| `NAME-008` | Critical | Update and release spend the current live Name Note and create its successor in the same Ironwood bundle. The successor's `prev_rcm` equals the spent tip's derived `rcm`. | End-to-end spend/output linkage tests and adversarial stale-tip tests. |
| `NAME-009` | Critical | The Name Note chain on the selected Zcash best chain is the sole ownership authority. Registry maps, queues, submissions, mempool observations, and policy databases are caches or intent only. | Replay-equivalence and reorg tests; API review preventing operational state from answering authoritatively. |
| `NAME-010` | Critical | The mint and `zns-verify` remain independent implementations pinned by common vectors. A shared implementation dependency must not make the same bug self-validating. | Differential test job using separately built producer and verifier. |

## Chain, wallet, and runtime transitions

| ID | Severity | Invariant | Required evidence |
|---|---|---|---|
| `SYNC-001` | Critical | Zebra liveness, network/branch, tip identity, structural block checks, freshness policy, and NU6.3 activation are verified before seed decryption or key derivation. | Boot ordering test with instrumented failures at every stage. |
| `SYNC-002` | Critical | The origin checkpoint is `(height, block hash, per-pool tree state)` at `ironwood_activation_height - 1`. The canonical-chain identity of the node is verified via the mainnet genesis block hash and `MAIN_NETWORK` parameters; the SEV-SNP measurement of the container image is the primary guarantee that only mainnet Zebra runs inside the TEE. The checkpoint's tree state is fetched from the same-TEE Zebra node after network identity is verified. | Genesis-hash check, measurement-bound image attestation, and wrong-network tests. |
| `SYNC-003` | Safety | A block is scanned only after verifying height/hash continuity with the fully applied cursor. The same scanning-key set is used for upstream decryption and scan phases. | Discontinuity, wrong-parent, skipped-height, and mismatched-key tests. |
| `SYNC-004` | Critical | Every commitment from every scanned block is appended in consensus order to its own Sapling, Orchard, or Ironwood tree, including commitments unrelated to the mint. Pools are never merged. | Tree-root comparison against Zebra at checkpoints and cross-pool collision fixtures. |
| `SYNC-005` | Critical | Accepting one block is one logical state transition across wallet notes, nullifier indexes, trees, Registry tips, request observations, submission reconciliation, and the cursor. Partial acceptance is not externally observable. | Fault injection after each phase proving rollback or no cursor advance. |
| `SYNC-006` | Critical | The cursor means “every subsystem has fully accepted every canonical block through this exact height and hash.” It advances last and by exactly one block. | State-transition assertions and crash/fault tests around cursor promotion. |
| `SYNC-007` | Safety | Within a block, confirmed Registry Name Notes and spends are applied before Treasury requests whose validity depends on resulting name state. Across blocks, consensus order is preserved. | Same-block ordering fixtures with conflicting Name Notes and requests. |
| `SYNC-008` | Critical | A reorg rewinds wallet notes, nullifier indexes, all three trees, Registry tips/history, request reservations, OTP effects, submission confirmations, and the cursor to one common ancestor before replay. | Multi-block reorg tests with received, spent, minted, and pending transactions. |
| `SYNC-009` | Critical | Restarting from the origin checkpoint and replaying the same canonical chain produces identical wallet balances, spendable notes, witnesses, Registry tips, and cursor. No derived durable state is authoritative. | Deterministic replay/property tests and restart regtests. |
| `SYNC-010` | Safety | Mempool presence, successful broadcast, and local transaction construction never mutate confirmed ownership state. Only canonical block application does. | Broadcast-without-mine, eviction, expiry, rejection, and reorg tests. |
| `SYNC-011` | Operational | Trust-path failures are fatal; malformed or unauthorized individual requests are redacted per-request failures and do not stop chain following. | Failure-classification tests and daemon liveness assertions. |

## Authorization and request processing

| ID | Severity | Invariant | Required evidence |
|---|---|---|---|
| `AUTH-001` | Critical | A claim is assembled only after the name is available and one eligible Treasury payment observed under the chosen canonical-chain confirmation policy has been uniquely reserved for that claim. A payment cannot authorize two claims. | Duplicate-payment, duplicate-request, underpayment, wrong-name, and reorg tests. |
| `AUTH-002` | Critical | Update and release are authorized by the current controller derived from the canonical live tip—not by the requested new controller, cached state, or operator input. | Controller-change and stale-tip adversarial tests. |
| `AUTH-003` | Safety | An OTP is generated by a CSPRNG, scoped to the exact `(name, action, request payload)` challenge, compared in constant time, expires, and can authorize at most one transition. | Deterministic state-machine tests around a mocked entropy boundary plus replay/expiry tests. |
| `AUTH-004` | Critical | OTP relay is a Treasury-authored shielded transaction sent to the current controller. The OTP never appears in the Name Note or in public/logged data. | Regtest receiver inspection and negative log/memo tests. |
| `AUTH-005` | Critical | At most one in-flight transition may reserve a given name tip, payment, fee note, or OTP. Retries are the same intent, not a second independent authorization. | Concurrent duplicate-request and retry property tests. |
| `AUTH-006` | Safety | Authorization decisions are bound to the chain cursor/tip used to make them. If that state becomes stale before submission or confirmation, the intent is revalidated or invalidated. | New-block and reorg races injected between authorization, proving, and submission. |

## Transaction construction and submission

| ID | Severity | Invariant | Required evidence |
|---|---|---|---|
| `TX-001` | Critical | Name payments, Name Note value, and network fees are distinct: payment is received by Treasury, Name Note value is zero, and the Registry pays the Name Note transaction fee. | Full value-flow accounting for every lifecycle transaction. |
| `TX-002` | Safety | Input selection excludes every note reserved by another live intent and remains deterministic for identical state and exclusions. | Selection property tests and concurrent reservation tests. |
| `TX-003` | Critical | ZIP-317 fees are computed from the complete final transaction's logical actions. The serialized transaction's aggregate value balance equals the intended fee exactly. | Independent fee calculation and boundary-action-count tests. |
| `TX-004` | Critical | The consensus branch ID, V6 format, Ironwood bundle version, flags, note version, anchor, and expiry height are valid for the target height. No pre-NU6.3 production transaction is assembled. | Height-boundary vectors and Zebra acceptance/rejection regtests. |
| `TX-005` | Critical | The signature hash commits to every non-authorization component of the exact transaction that is ultimately serialized. A bundle may not be added, removed, or changed after its committed sighash is computed. | Transaction mutation tests and independent sighash comparison. |
| `TX-006` | Critical | The Ironwood proof is verified locally against the correct circuit verifying key after signing and before broadcast. | Corrupted-proof and wrong-version negative tests. |
| `TX-007` | Safety | Broadcast is idempotently associated with one typed origin and records txid, first-submit height/time, retry count, confirmation, expiry, and final failure without storing secrets. | Duplicate-submit, timeout, rejection, expiry, and restart/replay tests. |
| `TX-008` | Critical | A transaction is confirmed only when its txid is observed in an applied canonical block. Reorg removes that confirmation and reconciles or invalidates its reservations and intent. | Confirmation/reorg regtest with competing chain branches. |

## Agent harness and verification gates

| ID | Severity | Invariant | Required evidence |
|---|---|---|---|
| `HARNESS-001` | Safety | Before changing Zcash-facing code, the acting agent reads the pinned upstream README, crate `lib.rs`, every relevant source file, and quotes exact reused APIs with revision, path, and line range. | Task record checked by review gate. |
| `HARNESS-002` | Safety | Before editing source, the acting agent reads its matching changelog, states design and failure modes, and updates design-relevant documentation in the same change. | Changed-file/changelog check plus recorded rationale. |
| `HARNESS-003` | Safety | Every implementation change names the invariant IDs it preserves or implements. Every invariant has an explicit test, static check, attestation check, or documented manual review owner. | Machine-readable coverage matrix with no unexplained critical gaps. |
| `HARNESS-004` | Safety | Tests are layered: pure unit/model tests, property and mutation tests, independent verifier differentials, component integration, Zebra regtest lifecycle tests, reorg/fault injection, and production TEE acceptance. A lower layer cannot substitute for a missing higher layer. | Test manifest and retained artifacts for each layer. |
| `HARNESS-005` | Critical | The harness treats compilation, green tests, and agent confidence as evidence—not proof. A critical invariant requires an adversarial test or independent review in addition to the happy path. | Release-gate report. |
| `HARNESS-006` | Safety | The harness never edits unrelated user changes, commits, pushes, builds, or runs production-affecting commands without the authority required by `AGENTS.md` and the user. | Clean-scope diff review and action log. |
| `HARNESS-007` | Critical | Test fixtures use synthetic seeds, names, addresses, OTPs, blocks, and capsules. Production secrets and production decrypted traffic are forbidden from prompts, transcripts, artifacts, and test logs. | Fixture provenance scan and secret-scanning gate. |

## Decisions required before the runtime is complete

These are not invariants yet. The harness must block dependent implementation
rather than choose silently.

1. The five user request forms are fixed by explicit user direction. The
   Treasury-to-controller OTP relay grammar and its replay/domain binding
   remain unresolved.
2. Atomic claim value-flow policy is resolved by explicit user direction:
   payment is at least the caller-supplied price; Treasury retains exactly that
   price; overpayment is returned through an always-present Ironwood output,
   including a value-zero output at the threshold; and Registry fee notes fund
   the complete transaction's aggregate ZIP-317 fee. There is no fee-derived
   Treasury surcharge. The durable meaning of “payment already consumed” in a
   replay-built runtime remains unresolved.
3. OTP expiry expressed in blocks or time, and the precise reservation/burn
   behavior across proof failure, broadcast failure, expiry, and reorg.
4. Confirmation policy for accepting claim payments and for retrying dependent
   transactions, distinct from best-chain state tracking.
5. Restart recovery has one approved floor: a reconstructed claim waits one
   maximum transaction-expiry window before replacement. Typed submission
   identity, retry backoff, replacement construction, and final-failure policy
   remain unresolved.
6. Treasury Registry-replenishment and auto-sweep arbitration when both are
   eligible in the same block.
7. The production origin height/hash and deployment-specific attested public
   identities. Placeholder values are forbidden by `SYNC-002`.
8. The Name Note outgoing-viewing-key policy and scope for outputs and change.
9. Expiration, renewal, forced revocation, and governance remain outside the
   current protocol unless explicitly added through a future protocol change.

## Current implementation baseline

This baseline is descriptive and should change as work lands. It does not
weaken any invariant.

| Area | Current state |
|---|---|
| Ironwood direction | Source transaction/scanner code follows Ironwood V3/V6. `AGENTS.md`, the protocol, and the chain/transaction design documents were corrected when this catalog was introduced. Other older design documents still contain pre-Ironwood paths and checkpoint assumptions and require reconciliation. |
| Secret boundary | Sealed-capsule, SEV-SNP derivation, account derivation, and attestation scaffolding exist. Production artifact and negative exfiltration tests do not. |
| Name kernel | Encoding, derivation, and vectors exist. Independent Ironwood transaction-level verifier coverage is not demonstrated here. |
| Sync and wallet | Passive canonical folding captures one checked Zebra height/hash target, rechecks every successful read/result, detects same-height, shorter, and taller divergence, preflights three-pool rewind, retains current plus 100 predecessor checkpoints, and promotes accepted history before the cursor. Before/after commit crash fixtures and deterministic empty-block restart/reorg properties are written but unexecuted. Non-empty note/Name Note properties and Zebra branch evidence are missing. |
| Authorization | Request parsing, OTP storage, and lifecycle authorization helpers exist as unwired libraries. Passive replay preserves canonical request evidence but performs no authorization. |
| Transactions | Registry construction and the crate-private mixed Orchard/Ironwood V6 signer are unwired. The standalone Treasury refund constructor has been deleted; no claim transaction exists until atomic payment settlement and Name Note creation share one V6 transaction. Canonical Wallet/Registry state contains no locks or reservations; a cursor-bound Live owner is missing. |
| Submission | No submission path is wired into the runtime. Typed retry, expiry, restart recovery, confirmation, and reorg policy remain unimplemented. |
| Runtime | `main` performs exact-target passive Rebuild and canonical rewind only. Replay invokes no OTP, policy, reservation, proving, signing, submission, or lifecycle-counter operation. Rebuild receives a read-only block-source capability, rejects successful reads and ancestor results from a moved target, and returns only after cursor, target block bytes, and a second exact-tip read agree. Live state reconciliation remains absent. |
| Regtest | The harness boots components and shields funds but does not submit or verify a ZNS lifecycle transaction. |

Known release blockers include:

- `SEC-003`: the existing regtest harness uses environment variables;
- `SEC-006`: production artifacts do not yet prove development features absent;
- `SYNC-002`: the origin hash is an all-zero placeholder;
- `SYNC-005` and `SYNC-006`: canonical ordering, cursor-last promotion,
  exact-target entry, and before/after crash/target-race fixtures exist but
  remain unexecuted; non-empty transition fixtures are still missing;
- `SYNC-007`: Live request reconciliation is intentionally absent;
- `SYNC-008`: same-height, shorter, and multi-block passive handling plus
  three-pool preflight fixtures are implemented but unexecuted and presently
  use empty blocks; operational invalidation remains absent until Live exists;
- `SYNC-009`: deterministic empty-block restart/reorg properties are written
  but unexecuted; received/spent-note, witness, and Registry-tip coverage is
  still missing;
- `SYNC-010`: the unsafe runtime authority path is deleted, but broadcast,
  eviction, expiry, and reorg isolation evidence is still absent;
- `AUTH-001`, `AUTH-005`, `AUTH-006`, and `TX-002`: a cursor-bound Live
  authorization/reservation owner is absent; all exclusion-free Treasury
  selection wrappers and unwired sweep/funding request surfaces are deleted;
- `TX-001` and `TX-003`: atomic claim value-flow and Registry-funded aggregate
  ZIP-317 fee policy are defined, but their construction is not implemented;
- `TX-007` and `TX-008`: submission/retry/confirmation/reorg reconciliation
  are intentionally unwired pending approved semantic recovery policy;
- `TX-005`: the Registry signer is now Ironwood-only, but the fail-closed
  pre-serialization effecting-digest equality postcondition still needs
  mutation and independent-sighash tests before it is considered verified;
- `HARNESS-003`: an invariant-to-test coverage matrix now exists in
  `docs/harness/coverage.csv`, but it remains a manual artifact that must be
  kept in sync with source changes;
- `HARNESS-004`: no end-to-end Name Note lifecycle or reorg test exists; and
- `HARNESS-002`: several lower-level design documents still describe deleted
  paths, the old Orchard pool, or the old block-3,000,000 checkpoint.
