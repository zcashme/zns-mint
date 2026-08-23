# Key module changelog

Tracks design-relevant changes to `src/key.rs`.

## 2026-09-01 — Upstream ZIP-316 vector regression tests

- Added two tests using upstream's own cross-implementation vectors
  (`zcash_address::test_vectors::UNIFIED`, enabled via a dev-only
  `test-dependencies` feature on the already-direct `zcash_address` dep):
  - `unified_vectors_bind_accounts_correctly` iterates the vectors filtered
    to accounts 0/1, derives through `TreasuryKeys`/`RegistryKeys`, and
    compares receivers against each vector's unified address — the body
    mirrors upstream's `ufvk_derivation` test (`zcash_keys` `keys.rs:2077`).
    This is the only regression that can catch a wrong `ACCOUNT_ID` binding,
    the one fact upstream cannot test for us.
  - `type_bound_derivation_matches_value_keyed` proves the capability
    derivation is byte-identical to `UnifiedSpendingKey::from_seed` at the
    same account, compared through `UIVK` equality (`zcash_keys`
    `keys.rs:1316`; `UFVK` has no `PartialEq`).
- No golden address strings are hand-pinned: the vectors are the external
  oracle, and no fabricated constants can go stale. Written but not executed;
  `cargo test` was not run.

## 2026-09-01 — USK zeroization removed; the seed is the wiped secret

- Deleted the hand-written `Zeroize`/`Drop` impls for `AccountKeys` (and the
  `!needs_drop` soundness assertion they required). The USK wipe fired only
  at process teardown, when no further code runs, inside SEV-SNP
  memory-encrypted guest RAM — no adversary in the stated threat model
  reaches that window. It also never delivered a coherent property:
  `UnifiedSpendingKey::from_seed` leaves derivation intermediates (ask, IVK,
  FVK bytes) unzeroized by upstream, so scrubbing the final struct was RAM
  hygiene, not custody. The security story remains the attested boundary,
  per AGENTS.md — not byte-scrubbed RAM.
- The radioactive object is the seed, and it was already covered: boot holds
  it as `Secret<[u8; 32]>`, whose `Drop` zeroizes (secrecy lib.rs:172–179).
  Boot now scopes the seed so it is dropped the instant both capabilities
  are derived instead of living to the end of the boot function; the
  sealing-key zeroization in `decrypt_sealed_blob` is unchanged.
- The module now contains no `unsafe`. Its entire upstream surface is
  `UnifiedSpendingKey` (held privately), `UnifiedFullViewingKey` (handed
  out), `AccountId` (bound in the sealed trait), and `Parameters`
  (derivation). Supersedes the 2026-07-25 and 2026-09-01 wipe entries.

## 2026-09-01 — Type-state account capabilities

- Replaced the two tuple-struct role wrappers with a single generic
  `AccountKeys<A: MintAccount>` parameterized by uninhabited marker types
  (`Treasury`, `Registry`). The public type aliases `TreasuryKeys` and
  `RegistryKeys` are preserved, so every existing signature and import is
  unchanged; the only call-site churn is boot's two derivation lines.
- The ZIP-32 account index is now bound in the sealed `MintAccount` trait
  impl rather than passed as a construction argument: a capability's account
  is correct by compilation, and the seal (upstream trait-sealing pattern)
  makes "exactly two accounts, ever" a type-system fact. This generalizes the
  2026-07-23 capability separation from two hand-written wrappers to one
  shared impl, with account-specific accessors expressible as
  `impl AccountKeys<Treasury>` blocks when a role genuinely needs more.
- Deleted the Treasury `sapling_spending_key`/`transparent_spending_key`
  accessors: zero call sites exist (verified by grep). The marker is
  `PhantomData<fn() -> A>` — no `A` value, no auto-trait perturbation.
- The zeroize byte-view wipe (see below) carries over, now generic over `A`.

## 2026-09-01 — Wipe delegated to zeroize via exact-size byte view

- Replaced the hand-rolled `ptr::write_bytes` + `compiler_fence` zeroization
  with a hand-written `impl Zeroize for AccountKeys` that delegates to
  `zeroize`'s own `[Z; N]` implementation (`zeroize` lib.rs:369) through an
  exact-size `*mut [u8; size_of::<UnifiedSpendingKey>()]` view. The only
  remaining `unsafe` is the pointer cast; the wipe loop and atomic fence are
  zeroize's audited code.
- Why not `#[derive(Zeroize, ZeroizeOnDrop)]`: the derives require every
  field to implement `Zeroize`, and no upstream key type does at the pinned
  revisions (`UnifiedSpendingKey` zcash_keys keys.rs:213,
  `ExtendedSpendingKey` sapling-crypto zip32.rs:261, `AccountPrivKey`
  zcash_transparent keys.rs:229, `SpendingKey` zns-orchard keys.rs:43 — all
  `Clone`-only). The orphan rule forbids a foreign impl, so the local
  `AccountKeys` owner remains the only legal home for the wipe.
- This also closes a latent gap: `ptr::write_bytes` is not volatile and can
  in principle be dead-store-eliminated — the precise reason `zeroize`
  exists (lib.rs:19). Delegation inherits the volatile-write + fence
  guarantee.
- The `!needs_drop::<UnifiedSpendingKey>()` compile-time assertion is kept
  as the soundness guard for the byte wipe: it proves no drop glue exists to
  read the zeroed bytes, so the cast cannot skip a destructor.

## 2026-07-30 — Boot-proven ZIP-32 network parameters

- Treasury and Registry derivation now require the consensus parameters that
  boot validated. This keeps ZIP-32 coin-type derivation aligned with parsing,
  scanning, address encoding, fees, and transaction branch selection.

## 2026-07-25 — Sound zeroization of UnifiedSpendingKey

- Added a compile-time assertion `!std::mem::needs_drop::<UnifiedSpendingKey>()`
  to guard the manual `ptr::write_bytes` zeroization in `AccountKeys::Drop`.
  Upstream `UnifiedSpendingKey` and its components have no `Drop` impl at the
  pinned revision, so the zeroization is sound today; the assertion forces a
  re-audit before the code can compile if upstream ever adds a destructor.
- Simplified the safety comment around the zeroization block.

## 2026-07-23 — Account-role spending capabilities

- Replaced the public role-neutral `AccountKeys` surface with distinct
  `TreasuryKeys` and `RegistryKeys` capability types.
- Each public derivation function fixes its ZIP-32 account internally
  (`Treasury=0`, `Registry=1`); callers cannot swap an `AccountId` at runtime.
- Raw Orchard spending-key access is crate-private and remains behind the role
  wrapper. Transaction builders and signers accept the role type they require,
  so Treasury authority cannot satisfy a Registry signer parameter or vice
  versa.
- Viewing-key access remains available for boot attestation and scanner setup.
