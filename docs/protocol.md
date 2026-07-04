# Zcash Name Service Protocol

---

## 1. Motivation and scope

ZNS maps a human-readable name (e.g. `alice`) to a Zcash Unified Address (UA),
so a sender can address by name instead of pasting a `z`-address. "Owning" a
name means being able to rebind which UA it resolves to, or to release it.

The protocol answers four questions:

1. **Identity:** what is the canonical on-chain artifact that *is* the binding?
2. **Authorization:** who may create, extend, or terminate a binding, and how
   is that enforced?
3. **Lifecycle:** how do claim, update, and release compose into a verifiable
   per-name history?
4. **Resolution:** how does a third party, holding only public chain data,
   compute the current binding without trusting the operator?

---

## 2. Parties and trust model

A **party** is an autonomous stateful agent behind a trust boundary, observed by
others only through its messages. ZNS has the following parties.

### 2.1 Out-of-band (upstream of the protocol)

**P0. The human (principal).** Holds the real private state upstream of every
party: the name they want and the UA they want it bound to. The human provisions
P1 and issues *intents*. The human is never an on-chain signer in v1. The
protocol cannot enforce honest provisioning; the human is modeled as the
environment that can mis-provision, mis-attest, or ignore warnings. This seam is
the one assumption the protocol cannot enforce.

**P1. The user's wallet (UA controller).** The human's delegate. Holds the
spending key for the UA being bound. Authors the **request memo** that travels
on-chain to the Registry. Its trust boundary is the user's device. It is a
distinct party from the Registry because its key is *user* key material, not
Registry key material; compromising P1 compromises one user, not the namespace.

### 2.2 Inside the protocol (the attested boundary)

**P2. The Registry.** The sole party authorized to spend and create Name Notes.
Implemented by `zns-mint` account 1 inside a Trusted Execution Environment
(TEE). Its private state is the **Registry spending key** (a ZIP-32 Orchard
spending key, account index 1). The Registry scans memos addressed to its
Orchard address, validates requests, derives `(psi, rcm)`, builds and proves and
signs the Orchard bundle that mints, updates, or releases a Name Note.

The Registry's capability is narrow and auditable: *authorizing name lifecycle
transitions*. It does not custody user funds, it does not pick resolutions, it
does not serve lookups. Compromise of the Registry spending key is total
namespace compromise -- every name can be rebound or released -- so the key is
treated as radioactive: it must never exist outside attested hardware. The
entire `zns-mint` design exists to make the answer to "can a human see the
Registry key?" provably *no*.

The Registry may keep local per-block state: scanned heights, block hashes,
request queues, parsed Name Notes, nullifier observations, current tips, and
reorg checkpoints. This state is operational only. It must be rebuildable by
replaying the canonical chain, and it must never become a second source of truth
for name ownership.

The attested Registry binary is the policy executor. In v1, "the mint followed
policy" means the emitted Name Note was produced by the attested code under the
policy implemented by that code. The protocol does not require a separate
authoritative policy log. If the English policy document and the attested code
disagree, attestation proves only which code ran.

**P3. The Treasury.** Same seed as P2, different ZIP-32 account (index 0),
distinct *capability*: it pays transaction fees and sweeps excess to a cold
address. A separate logical principal because its spending key is a different,
narrower authority -- a fee-funder, not a name-authorizer. Same physical TEE
boundary; separate logical key. Compromise of the Treasury key costs the
operator funds, not the namespace.

### 2.3 The settlement layer

**P4. The chain oracle (Zebra / indexer).** The Registry's eyes and mouth on
chain state: tip height, block bytes, mempool messages, broadcast. Implemented
today by the gRPC `Indexer` service (`zebra-indexer-proto`). Not trusted beyond
the structural checks the Registry performs at boot (`verify_tip_block`: header
hash recomputation, coinbase presence, height consistency). Full consensus
verification (PoW/Equihash, Merkle roots over txs, signatures, chain linkage)
remains Zebra's job. The oracle is the one external input the TEE consumes and
is named separately because a malicious oracle is in scope for the threat model.

**P5. Zcash consensus (validators/miners).** The party that *finalizes* a Name
Note by including the Orchard bundle in a block. The Registry proposes; P5
disposes. Reorgs here are the Registry's failure case (section 10). Finality is
inherited from Zcash: a Name Note is *tentative* until its containing block is
buried under enough work to match the resolver's chosen confirmation depth.

### 2.4 Downstream (read-only principals, no state-changing authority)

**P6. The resolver.** Reads public chain state, interprets the Name Note chain
for a name, returns `name -> ua` at a queried height. Distinct party because it
has its own trust relationship with the *reader* (someone looking up `alice`),
separate from the Registry. The resolver must not require privileged access or
secret material; section 9 fixes the resolution algorithm.

**P7. The independent verifier (`zns-verify`).** A second implementation of the
ZNS kernel, run by clients or resolvers, kept deliberately separate from the
mint's `payload.rs`. Its whole purpose is to *not trust* the Registry: anyone
can run it to recompute `psi`/`rcm` and check a Name Note's commitment. This is
the protocol's structural defense against the Registry becoming "a hidden trust
oracle" (a load-bearing requirement; see section 11). The two implementations
are pinned by shared, byte-identical test vectors (section 12).

### 2.5 Trust summary

```
human -> wallet -> [request memo on-chain] ->
  Registry (TEE) validates  +  Treasury funds ->
    Zcash consensus finalizes ->
      resolver serves it,  zns-verify checks it
```

Two boundaries are load-bearing:

- **human <-> wallet (P0/P1):** the seam the protocol cannot enforce.
- **wallet <-> Registry (P1/P2):** the Registry must act on a request only when
  the request is authentically bound to the name's current controller. In v1
  this is the authorization problem; section 8.

A separate, deeper boundary:

- **operator <-> Registry key (P2):** the Registry spending key must never be
  visible to the operator or any human. This is why the daemon runs in a TEE,
  why the seed arrives as an attestation-bound encrypted blob, and why no env
  var / CLI flag / config file is permitted as an input channel. Bend any of
  these and the rest is theatre.

---

## 3. Cryptographic primitives

The protocol composes the following primitives. All are fixed by v1; changing
any one is a protocol version bump (section 13).

| Primitive | Use | Source |
|---|---|---|
| Orchard note commitment (Sinsemilla, Pallas) | Bind `(rcm, psi, rho, value, recipient)` of a Name Note into `cmx` | Zcash Orchard, with the `unsafe-zns` override (section 4) |
| Orchard nullifier | Detect double-spend of a prior Name Note; supplies `rho` to the next note via `Rho::from_nf_old` | Orchard |
| Orchard spend authority | Prove knowledge of the Registry spending key on each spend | Orchard |
| BLAKE2b-512 | Domain-tagged hash for `(psi, rcm)` derivation | `blake2b_simd` |
| Pallas base field `from_uniform_bytes` | Wide-reduce 64 bytes -> `psi in F_q` | `pasta_curves` |
| Pallas scalar field `from_uniform_bytes` | Wide-reduce 64 bytes -> `rcm in F_r` (commitment trapdoor) | `pasta_curves` |
| ZIP-32 Orchard derivation | One seed -> Treasury (acct 0) + Registry (acct 1) spending keys | `zcash_keys`, `zip32` |
| ZIP-302 512-byte memo | Carrier for the canonical Name Note grammar | `zcash_protocol` |
| TEE attestation | Bind the running binary + launch config to the seed blob's decryption key | platform (e.g. SGX, SNP) |

### 3.1 Why two independent implementations of the kernel

`psi` and `rcm` are *deterministic public derivations*: anyone with
`(action, name, ua, prev_rcm)` can recompute them. They are not secrets. But
they *are* the interop contract: if the mint computes them one way and the
verifier another, every Name Note's commitment silently disagrees. The protocol
therefore mandates that the mint (`payload.rs`) and the reference verifier
(`zns-verify`) keep *separate* copies of the derivation, pinned by
byte-identical test vectors (section 12). A derivation bug surfaces as a
mismatch instead of cancelling out.

---

## 4. The Name Note

### 4.1 Definition

A **Name Note** is an Orchard note with three deviations from spec-faithful
Orchard:

1. Its `value` is `0` (a self-send; no ZEC moves).
2. Its `recipient` is the Registry's own external Orchard address
   (`fvk.address_at(0, Scope::External)`), so the Registry can later spend it.
3. Its note commitment is overridden: instead of committing to
   `(recipient, value, rcm)`, the commitment binds a **ZNS payload** through a
   second trapdoor `psi` supplied alongside `rcm`.

The override is provided by the `orchard` crate's `unsafe-zns` feature
(`Builder::add_zns_output`, `Builder::add_zns_spend`, `OutputInfo::new_zns`).
The `unsafe-` prefix is deliberate: it breaks Orchard's standard safety
guarantees by design. The commitment now ties to *ZNS state* (`psi`), not just
to note ownership. The security implication is that the note's value envelope is
repurposed as a commitment to a name binding; we rely on the rest of Orchard
(nullifier, spend authority, proof) continuing to function, which the fork's
tests verify.

### 4.2 What a Name Note commits to

A Name Note commits, via the Sinsemilla `cmx`, to:

- `psi` -- a Pallas base-field element, a deterministic function of
  `(action, name, ua, prev_rcm)` (section 5). `psi` is committed *inside* the
  Sinsemilla message *and* feeds the nullifier.
- `rcm` -- a Pallas scalar, the commitment trapdoor, also a deterministic
  function of the same inputs.
- `rho` -- the note's nullifier seed. `rho` is *not* a derivation input; it is
  `Rho::from_nf_old` from the action's spend nullifier, chosen by the builder.
  For a fresh `claim` (no spend), `rho` is chosen by the builder from the
  dummy spend.
- `value = 0`, `recipient = Registry external address`.

The memo (section 6) carries the *human-readable* form of the same fields. The
memo is not part of the cryptographic commitment; it is the recoverable
attestation. A resolver reads the memo to learn `(action, name, ua, prev_rcm)`
and then recomputes `psi`/`rcm` to verify that the on-chain commitment matches.

### 4.3 The Name Note chain

A name's history is a **chain** of Name Notes. Each note after the first spends
its predecessor and mints its successor in the same Orchard bundle. The chain
rule is:

- `prev_rcm` of note `i+1` equals `rcm` of note `i`.
- The genesis `prev_rcm` is `ZERO_PREV_RCM = [0u8; 32]`.

`rcm_i` is a deterministic function of `(action_i, name_i, ua_i, prev_rcm_i)`,
and `prev_rcm_i = rcm_{i-1}`, so each link is bound to the entire prior history.
Forging an alternative history for the same name requires finding a collision
on `tagged_zns_hash` (section 5) at some link, which reduces to BLAKE2b-512
collision resistance.

The chain is also the *lifecycle state machine* (section 7): the action verb
and the chain position together determine what transitions are legal.

---

## 5. The `(psi, rcm)` derivation

### 5.1 Inputs

- `action in { "claim", "update", "release" }` -- canonical ASCII bytes,
  case-sensitive, never changing.
- `name` -- canonical lowercase, DNS-label-valid (section 6.3), 1..63 bytes.
- `ua` -- the Unified Address string being bound. Empty for `release` (the field
  stays positional; section 6).
- `prev_rcm` -- 32 bytes, the prior link's `rcm`, or `ZERO_PREV_RCM` for a
  genesis claim.

### 5.2 Construction

Let `ZNS_DOMAIN_TAG = b"ZcashName/v1"`. Let `TAG_PSI = b"psi"`,
`TAG_RCM = b"rcm"`. For a field tag `t`, compute a 64-byte digest:

```
BLAKE2b-512(
    u32le(len(ZNS_DOMAIN_TAG)) || ZNS_DOMAIN_TAG ||
    u32le(len(t))             || t             ||
    u32le(len(action))        || action        ||
    u32le(len(name))          || name          ||
    u32le(len(ua))            || ua            ||
    prev_rcm[32]                                  // fixed length, no prefix
)
```

Then:

- `psi = pallas::Base::from_uniform_bytes(digest(TAG_PSI))`
- `rcm = pallas::Scalar::from_uniform_bytes(digest(TAG_RCM))`

Both reductions are *wide*: 64 bytes into the field with no modulus-rejection,
so outputs are uniform over the field with no timing/branch leak and no
unfair-distribution concern. The length-prefixing prevents `(name, ua)` tuple
collisions on raw concatenation (e.g. `("alice", "")` vs `("ali", "ce")`).
`prev_rcm` is fixed at 32 bytes and needs no prefix.

### 5.3 Properties

- **Deterministic.** Same inputs always yield the same `(psi, rcm)`.
- **Binding.** Distinct `(action, name, ua, prev_rcm)` tuples yield distinct
  outputs (reduces to BLAKE2b-512 collision resistance).
- **Public.** No secret input. Anyone can recompute and verify.
- **History-bound.** Because `prev_rcm` chains, `psi_i` is a function of the
  entire chain up to link `i`.

### 5.4 Why `psi` feeds both the commitment and the nullifier

`psi` is committed in the Sinsemilla message (so the on-chain `cmx` proves the
note binds the claimed `(action, name, ua, prev_rcm)`), and `psi` is also an
input to the nullifier computation (so two different notes for the *same* name
at the *same* chain position would derive the same nullifier and one could not
double-spend the other without contradiction). The dual use is intentional: it
ties the cryptographic identity of the note to its spend-prevention.

`rho` is *not* a derivation input. It is supplied by the builder from the spend
action's nullifier. This keeps `psi`/`rcm` a pure function of payload, and keeps
the resolver's verification independent of in-transaction positioning.

### 5.5 Versioning

Bumping `ZNS_DOMAIN_TAG` is a protocol version change. It moves every test
vector and breaks interop with every resolver and client verifier. New vectors
must be added simultaneously to the mint (`payload.rs::tests::VECTORS`) and to
`zns-verify::tests::vectors::VECTORS`.

---

## 6. The memo grammar

### 6.1 Carrier

A Name Note's payload travels in the ZIP-302 512-byte memo field. The grammar is
a positional, colon-separated, ASCII text, zero-padded to 512 bytes. Trailing
zero padding is stripped on parse. The grammar is *strict*: exact field counts,
exact verb bytes, lowercase-hex `prev_rcm`, no fallback normalization. A lenient
parser would let implementations drift; this matches `zns-verify`.

### 6.2 Name Note form (on-chain, verifiable)

```
ZNS:<verb>:<name>:<ua>:<prev_rcm_hex>
```

- `verb in { "claim", "update", "release" }`
- `name` -- canonical lowercase, DNS-label-valid
- `ua` -- the Unified Address string (empty for `release`; the field stays
  positional so `prev_rcm_hex` never shifts columns)
- `prev_rcm_hex` -- 64 lowercase hex chars encoding the 32-byte `prev_rcm`

Examples:

```
ZNS:claim:alice:u1abc:0000...0000      (genesis claim, prev_rcm = 0^32)
ZNS:update:alice:u1def:<64 hex chars>  (rebind; prev_rcm = prior rcm)
ZNS:release:alice::<64 hex chars>      (terminate; empty ua field)
```

### 6.3 Name validation (DNS-label rule)

A canonical name is 1..=63 bytes of `a-z 0-9 -`, with no leading or trailing
hyphen. Validation does *not* lowercase; canonicalization is a separate step
(`canonicalize_name(input) = lowercase then validate`). The on-chain form is
always the lowercase canonical string. Two inputs that canonicalize to the same
label are the same name.

### 6.4 Request memo form **[deferred]**

A user-to-Registry request is a `ZNS:`-prefixed memo that is *not* a Name Note.
The v1 kernel only needs to *classify* it as a request (`classify_memo`
returns `ZnsRequest` for any `ZNS:` memo that fails Name-Note parsing for a
non-`NotZns` reason). The full request grammar -- including the OTP
challenge/response fields that carry the authorization proof from P1 to P2 --
is fixed by the auth step and is **not** part of the v1 interop contract. The
load-bearing rule that *is* fixed now: the Name Note itself never carries an
OTP, so the on-chain verifiable artifact stays parseable by the unmodified
`zns-verify` kernel.

---

## 7. Lifecycle state machine

### 7.1 Per-name states (derived, not stored)

A name's state is fully determined by the tip of its Name Note chain. There is
no separate registry state machine; the chain *is* the state.

- **unseen** -- no Name Note exists for this name.
- **live** -- the chain tip is `claim` or `update`.
- **released** -- the chain tip is `release`.

`Tip { action, rcm }` is the on-chain-derived state. `prev_rcm_for(tip, action)`
is the single shared implementation of the transition rule (section 7.2).

### 7.2 Transition rule

Let `ZERO_PREV_RCM = [0u8; 32]`. Given the current tip (or `None` for an unseen
name) and a proposed action:

- `Claim` is legal iff `tip` is `None` or `tip.action == Release`. It starts a
  fresh chain; `prev_rcm = ZERO_PREV_RCM`.
- `Update` is legal iff `tip.action in { Claim, Update }` (the name is live).
  It extends the chain; `prev_rcm = tip.rcm`.
- `Release` is legal iff `tip.action in { Claim, Update }` (the name is live).
  It extends the chain; `prev_rcm = tip.rcm`.

Any other `(tip, action)` pair is illegal and the Registry must not build a
bundle for it. Resolver and verifier compute the same rule, so an illegal
transition is detectable by anyone.

### 7.3 Visual

```
                claim                 update/release
  unseen  ---------------->  live  ---------------->  released
              ^                    |                        |
              |                    |     (illegal)          |
              |                    v                        |
              |               (rejected)                   |
              |                                               |
              +-----------------------------------------------|
                                  claim (re-claim)
```

A released name may be re-claimed, starting a fresh chain from
`ZERO_PREV_RCM`. The prior chain remains on-chain and verifiable; the new chain
supersedes it for resolution (section 9).

### 7.4 Expiration, renewal, and revocation **[deferred / policy]**

The v1 kernel has no expiration, grace period, or revocation primitives.
`release` is the only termination path and it is *authorized* (requires the
Registry to spend the prior note). Expiration-by-block-height, renewal, and
forced revocation are policy-layer extensions; if added, they extend the state
machine and the chain grammar, and require a protocol version bump. See
section 14 for the policy/protocol split.

---

## 8. Operations

### 8.1 Claim

**Inputs:** canonical `name`, target `ua`.

**Authorization (v1, deferred detail):** a request memo from P1 to the
Registry's address, carrying proof that the requester is entitled to claim the
name. The exact proof is the auth step; the v1 kernel only requires that the
Registry *accepts* the request before building.

**Preconditions:** `prev_rcm_for(None_or_released, Claim) == Some(ZERO_PREV_RCM)`
(section 7.2). Name passes validation (section 6.3). Policy eligibility
(reserved names, rate limits, fees) is satisfied -- these are policy, not
protocol (section 14).

**Registry action:**

1. Compute `prev_rcm = ZERO_PREV_RCM`.
2. `memo = encode_name_note(Claim, name, ua, prev_rcm)`.
3. `(psi, rcm) = zns_psi_rcm(b"claim", name, ua, prev_rcm)`.
4. Build an Orchard bundle: `Builder::add_zns_output(None, registry_addr,
   NoteValue::ZERO, memo, rcm, psi)`. No spend (output-only; the dummy spend
   covers the action).
5. Prove, prepare, finalize. Sign with the Registry spending key (output-only
   path skips spend-auth signing; the dummy spend is signed in `prepare`).
6. Treasury funds fees; broadcast (P3, P4); P5 finalizes.

**Effects:** a new Name Note exists on chain, spendable only by the Registry,
committing to `(claim, name, ua, ZERO_PREV_RCM)`. The name is now `live`.

### 8.2 Update

**Inputs:** canonical `name`, new target `ua`.

**Authorization:** a request memo from the *current controller* of the name. In
v1, "current controller" is defined by the request authorization model
(deferred); the protocol invariant is that the Registry must not extend a live
chain on a request that is not authentically bound to the prior `ua`.

**Preconditions:** `tip.action in { Claim, Update }` (live).

**Registry action:**

1. Recover the prior note `(old_note, old_parsed, merkle_path)` from the
   wallet/scanner.
2. Recompute `(old_psi, old_rcm) = zns_psi_rcm(old.action, old.name, old.ua,
   old.prev_rcm)`.
3. `new_prev_rcm = old_rcm.to_repr()` -- the chain rule, enforced inside the
   signer.
4. `memo = encode_name_note(Update, name, new_ua, new_prev_rcm)`.
5. `(new_psi, new_rcm) = zns_psi_rcm(b"update", name, new_ua, new_prev_rcm)`.
6. Build: `add_zns_spend(fvk, old_note, merkle_path, old_rcm, old_psi)` then
   `add_zns_output(None, registry_addr, NoteValue::ZERO, memo, new_rcm,
   new_psi)`.
7. Prove, prepare, sign with the Registry `ask`, finalize.
8. Fund, broadcast, finalize.

**Effects:** the prior Name Note is nullified; a new Name Note commits to
`(update, name, new_ua, old_rcm)`. The chain is extended by one link. The name
is still `live`, now bound to `new_ua`.

### 8.3 Release

**Inputs:** canonical `name`.

**Authorization:** a request memo from the current controller.

**Preconditions:** `tip.action in { Claim, Update }` (live).

**Registry action:** as `update`, but the successor memo is
`encode_name_note(Release, name, "", old_rcm)`. The release output is a normal
Name Note with empty `ua`, new deterministic `(psi, rcm)`, and `prev_rcm` equal
to the prior tip's `rcm`.

**Effects:** the prior Name Note is nullified; a successor Name Note commits to
`(release, name, "", old_rcm)`. The chain is extended by one terminal link. The
name is `released`. It may be re-claimed later, starting a fresh chain from
`ZERO_PREV_RCM`.

### 8.4 Resolve

**Inputs:** canonical `name`, optional target height.

**Algorithm (v1, deterministic from chain state):**

1. Scan the chain for all memos that parse as `NameNote` with the given `name`
   (section 6.2), in chain order.
2. Reconstruct the chain: a sequence is valid iff each link's `prev_rcm` equals
   the prior link's recomputed `rcm`, and the first link's `prev_rcm` is
   `ZERO_PREV_RCM`.
3. The current tip is the last valid link. If the tip's action is `release`,
   the name is `released` and resolves to nothing. If `claim` or `update`, it
   resolves to the tip's `ua`.
4. Reject any fork that does not satisfy the chain rule. If two valid chains
   share a prefix and diverge, the one contained in the heavier proof-of-work
   chain wins (this is just Zcash finality applied to the Name Note chain).

**Output:** `{ canonical_name, controller_ua, status, tip_height, schema_version }`.
Resolution must not expose secrets or require privileged access. A resolver
that trusts the operator's index without recomputing `psi`/`rcm` is *not* a
verifier; it is a cache.

### 8.5 Renew / revoke **[deferred / policy]**

Not in v1. See section 14.

---

## 9. Resolution and the on-chain/off-chain boundary

The protocol separates:

- **on-chain (authoritative):** the Name Note chain itself -- Orchard note
  commitments, nullifiers, the 512-byte memos, and the chain order induced by
  block ordering.
- **off-chain (derived):** indexes that map `name -> chain tip` for fast
  lookup; caches of parsed memos; per-block scanner state; pending request
  queues; UX helpers; display metadata.

A resolver may use any off-chain index for speed, but the answer it returns
must be *derivable* from on-chain state at the queried height. Local caches are
not authoritative. Reorg handling restores the previous valid chain tip by
re-reading the chain (section 10).

The Registry itself is *not* authoritative for resolution. It is an execution
component: it produces state transitions that any resolver can validate
independently. This is the load-bearing property that keeps the Registry from
becoming a hidden trust oracle (section 11).

The Registry is allowed, and expected, to maintain per-block derived state so it
can operate efficiently. The test is replayability: deleting the Registry's
local database and replaying the canonical chain must recover the same name
ownership state.

---

## 10. Settlement, finality, and reorgs

A Name Note is **tentative** from the moment its containing transaction appears
in a block, and **final** once that block is buried under the resolver's chosen
confirmation depth (Zcash finality). The protocol does not define its own
finality; it inherits Zcash's.

**Reorgs:** if a block containing a Name Note is reorged out, the note ceases
to exist from the perspective of the new best chain. The Registry must rewind
its local view to the last common ancestor and re-derive the chain tip for any
affected name. Two invariants:

1. **Replayability.** All externally visible state is derivable from the
   ordered chain. The Registry can reconstruct its registry view from canonical
   history after a restart or a reorg. No local state is authoritative.
2. **No silent loss.** A controller must not silently lose ownership. If a
   reorg undoes a `claim`, the name returns to `unseen` or to whatever prior
   tip the reorg exposes; it does not silently transfer to another party.

The Registry should checkpoint per-block scanner state for performance, but a
checkpoint is valid only if it names the block hash and height it summarizes.
If the checkpoint's block is not on the canonical chain, the Registry must
discard or rewind it.

**Mempool:** a request memo in the mempool is *not* a state change. The
Registry may track pending requests for UX, but no Name Note exists until a
bundle is included in a block.

---

## 11. Security analysis

### 11.1 What is cryptographically enforced

- **Binding integrity.** A Name Note's commitment binds
  `(action, name, ua, prev_rcm)` via `psi`. Forgery requires either the
  Registry spending key (to spend/create) or a BLAKE2b-512 collision (to find
  `(psi, rcm)` matching a target commitment). Reduces to BLAKE2b-512
  collision resistance and Orchard commitment soundness.
- **Chain integrity.** `prev_rcm_{i+1} = rcm_i` and `rcm` is a deterministic
  function of all prior inputs, so the chain is tamper-evident. Altering any
  link breaks the `prev_rcm` equality at the next link and is detectable by any
  verifier.
- **Double-spend prevention.** Orchard nullifiers prevent the same prior Name
  Note being spent twice. Because `psi` feeds the nullifier, two distinct
  notes at the same chain position derive conflicting nullifiers.
- **Spend authority.** Only the Registry spending key can authorize a spend of
  a Name Note (the recipient is the Registry's own address). Forging a
  transition requires forging an Orchard spend proof.
- **Independent verifiability.** `psi`/`rcm` are public derivations; any third
  party can recompute and check `cmx` against the on-chain commitment without
  trusting the Registry, the operator, or the resolver. `zns-verify` exists
  precisely to exercise this property with an independent implementation.

### 11.2 What is enforced by the TEE boundary

- **Registry key confidentiality.** The Registry spending key never leaves
  attested hardware. The seed arrives as an encrypted blob bound to the TEE's
  measurement; any operator-readable input channel (env var, CLI flag, config
  file) is forbidden because it would undo the attestation guarantee. Plaintext
  seed is zeroized the moment derivation is complete.
- **Narrow capability.** The Registry key's sole capability is authorizing name
  lifecycle transitions. The Treasury key (different account) is a separate,
  narrower authority (fee funding, sweeping). Compromise of one does not imply
  compromise of the other.
- **Attested execution.** The binary, its launch config, and the seed blob's
  decryption key are all bound by the TEE measurement. A different binary or a
  different config produces a different measurement and cannot decrypt the
  seed. This is the load-bearing defense against a malicious operator
  substituting a key-exfiltrating binary.

### 11.3 What is *not* enforced (known gaps)

- **Human provisioning.** The protocol cannot prevent the human from
  mis-provisioning their wallet, pasting a UA into a phishing UI, or signing a
  request that binds their name to an attacker's address. This is the seam
  between P0 and P1; no downstream cryptography recovers it.
- **Request authorization (v1 detail deferred).** The v1 kernel fixes *that*
  the Registry must act only on an authentically-bound request, but the
  concrete OTP/challenge grammar is the auth step. Until that lands, the
  request path is a trust assumption on the Registry, not a cryptographic
  guarantee. This is the most important open item.
- **Operator -> Registry key exfiltration via side channels.** TEE attestation
  binds the *binary*, not the *hardware*. Side-channel, physical, or
  firmware-compromise attacks on the TEE itself are out of scope for the
  protocol and are the TEE platform's problem.
- **Censorship.** The Registry can refuse to build a bundle for any request.
  v1 has no forced-update or censorship-resistance mechanism; the Registry is
  a trusted-by-policy operator for *availability*, even though it is
  *untrusted* for correctness (section 11.1).
- **Name squatting / dispute.** Policy. Section 14.
- **Front-running.** A request memo in the mempool is visible. An attacker
  with the Registry key could front-run (but they already have the key, so
  this is subsumed by key compromise). An attacker *without* the key cannot
  front-run because they cannot build a valid Name Note. So front-running is
  not an additional risk in v1.

### 11.4 Threat model summary

| Adversary | Can they rebind a name? | Can they read user UAs? | Notes |
|---|---|---|---|
| Network observer | No (shielded) | No (shielded) | Orchard privacy |
| Compromised resolver | No | Sees UAs (public) | Can lie to *its* readers; readers run `zns-verify` |
| Compromised oracle (P4) | No (cannot forge proofs) | No | Can censor/DOS, can serve stale tip; `verify_tip_block` catches structural tampering |
| Compromised Treasury key | No (different account) | No | Loses operator funds |
| Compromised operator (no TEE) | No (attestation binds binary) | No | Cannot decrypt seed |
| Compromised TEE platform | **Yes (total)** | If in memos | Out of protocol scope |
| Compromised Registry key | **Yes (total)** | If in memos | Namespace-wide compromise |
| Compromised user wallet | For that user's name only | Yes for that user | P0/P1 seam; unrecoverable |

---

## 12. Test vectors

The interop contract is pinned by byte-identical vectors in:

- `zns-mint/src/payload.rs::tests::VECTORS`
- `zns-verify::tests::vectors::VECTORS`

Four tuples covering: a minimal claim, an update with non-zero `prev_rcm`, a
release with empty `ua`, and a longer name + UA. Each vector fixes
`(action, name, ua, prev_rcm)` and the expected `psi`/`rcm` 32-byte hex
representations.

A change to `tagged_zns_hash` (absorption order, length prefixing, domain tag,
field tags) or to the field reductions moves these values and breaks interop.
Bumping `ZNS_DOMAIN_TAG` is a protocol version change and requires new vectors
in *both* implementations simultaneously.

---

## 13. Versioning and upgrades

The protocol is versioned. `ZNS_DOMAIN_TAG = b"ZcashName/v1"` is the version
tag.

- **Breaking changes** (hash construction, memo grammar, action set, chain
  rule, commitment override) require a new protocol version. The domain tag
  bumps; new test vectors land in both implementations; resolvers and clients
  must detect the version and refuse incompatible notes.
- **Additive changes** (new record types, new policy hooks that do not touch
  the chain) may land without a version bump.
- **Upgrades must preserve the ability to interpret historical state.** A v2
  resolver must still parse v1 Name Notes; v2 may *add* semantics but must not
  *misinterpret* v1.
- **Deprecation windows** should be explicit and on-chain-observable if
  possible.

---

## 14. Policy vs protocol

The protocol fixes the byte-stable objects and replay rules that make ownership
verifiable. Policy is the set of choices the mint applies before it decides to
emit a Name Note. In v1, policy is enforced by the attested Registry binary:
code is the policy executor.

The following are **policy**, not protocol. They may evolve through governance
without a protocol version bump, unless they touch a protocol invariant.

- registration fees
- renewal fees
- grace period duration
- reserved name list
- namespace segmentation
- rate limits
- eligibility requirements
- dispute resolution
- recovery procedures
- administrative backdoors, if any

Policy values should be documented separately, versioned independently, and
referenced by protocol version. A rule affects *protocol* iff it changes who
can own a name, what state a name may be in, how a resolver interprets records,
or the byte-stable derivations. Otherwise it is policy.

The Name Note chain remains the sole source of truth for name ownership state.
Policy determines whether the attested mint is willing to create the next Name
Note; once created and finalized, ownership is read from the Name Note chain,
not from a policy database.

---

## 15. Governance

Governance controls changes to policy and, where necessary, protocol evolution.
The governance model should answer:

- who may propose changes
- who may approve changes
- how changes are activated
- how emergency fixes are handled
- how disputes are recorded

Governance must not be able to rewrite history without an explicit and auditable
process. In particular, governance cannot retroactively alter a Name Note
chain; it can only authorize *future* transitions (e.g. forced revocation as a
policy extension).

---

## 16. Open issues (v1)

1. **Request authorization grammar.** The OTP/challenge/response shape that
   binds a request memo to the current controller. This is the most important
   open item: until it lands, the wallet -> Registry authorization is a trust
   assumption, not a cryptographic guarantee.
2. **Expiration and renewal.** Whether v1 ships without expiration (simplest)
   or with a block-height-based expiry that extends the chain grammar.
3. **Forced revocation.** Whether governance can authorize a `release` on a
   live name without the controller's request, and how that is represented on
   the chain (a new action verb? a policy-signed override?).
4. **Reorg recovery UX.** How the Registry exposes a reorg-induced rewind to
   downstream consumers without ambiguity.
5. **Confirmation depth.** A recommended default for resolver finality.

---

## 17. Minimal initial recommendation

For the first implementation, the simplest viable protocol is:

- lowercase ASCII names only (DNS-label rule, 1..=63 bytes)
- one controller per name, identified by a UA string
- claim / update / release; no expiration, no renewal, no revocation
- direct controller-authorized updates and releases (auth detail deferred)
- the canonical Name Note memo grammar (section 6.2)
- the deterministic `(psi, rcm)` derivation (section 5)
- the Name Note chain as the sole source of truth (section 4.3)
- deterministic resolution from chain-backed registry state (section 8.4)
- the Registry as sole signer, in a TEE, with the Treasury as fee funder
  (section 2.2)
- independent verification via `zns-verify` (section 2.4)

This is intentionally small. Subnames, delegated controllers, multi-sig
control, shielded credentials, or advanced recovery can be added later only
through a protocol version bump.
