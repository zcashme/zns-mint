# NU6.3 Readiness Handoff

Date: 2026-07-11

## Goal

Prepare the ZNS mint stack for NU6.3 / Ironwood while staying shielded-only:

- Sapling remains supported.
- Orchard remains supported for NU5 through NU6.2.
- Ironwood / NU6.3 support is required for the new Orchard v3 / Ironwood pool path.

The work was split into:

1. Rebase the ZNS Orchard fork.
2. Update `zns-mint` to the new dependency stack.
3. Re-check what remains unchanged or not yet ready upstream, and how that affects the mint.

This handoff covers item 1 completed, and items 2-3 still pending.

## Completed: `zns-orchard` Rebase

Repository:

`/Users/jules/ZcashNames/zns-orchard`

Branch:

`main-ironwood`

Upstream base:

`zcash/orchard` tag `0.15.0`

Base commit:

`8995ee7 Release orchard v0.15.0`

Resulting local branch head:

`cd4afc0 chore(zns): clean up rebased builder test formatting`

Final local commit stack:

```text
cd4afc0 chore(zns): clean up rebased builder test formatting
6536e47 feat(zns): expose NoteCommitTrapdoor serialize/equality surface under unsafe-zns
ec76c85 Update zns fork for NU6.3 (orchard 0.15.0-pre.1) compatibility
8995ee7 Release orchard v0.15.0
```

Branch status after completion:

```text
main-ironwood...origin/main-ironwood [ahead 17, behind 2]
```

This is expected because the local branch was rebased from the old `0.15.0-pre.1` base onto upstream final `0.15.0`. No push has been performed. Updating `origin/main-ironwood` will require:

```sh
git push --force-with-lease origin main-ironwood
```

Run that only when ready to rewrite the remote branch.

## Rebase Details

Before rebase, `main-ironwood` had two ZNS commits on top of upstream `0.15.0-pre.1`:

```text
a24bfa6 feat(zns): expose NoteCommitTrapdoor serialize/equality surface under unsafe-zns
e9edfa6 Update zns fork for NU6.3 (orchard 0.15.0-pre.1) compatibility
840cd68 Prerelease 0.15.0-pre.1
```

Rebase command used:

```sh
git rebase --onto 0.15.0 840cd68 main-ironwood
```

One conflict occurred in `src/builder.rs`.

Conflict resolution:

- Upstream `0.15.0` changed fabricated spend-paired outputs so randomized ciphertext is conditional:

```rust
randomized_ciphertext: matches!(spent_scope, Scope::External),
```

- The ZNS patch needed to preserve:

```rust
#[cfg(feature = "unsafe-zns")]
zns_override: None,
```

Final merged result kept both.

After rebase, rustfmt/clippy cleanup was committed as a normal third commit:

```text
cd4afc0 chore(zns): clean up rebased builder test formatting
```

## Validation Completed

All of the following commands passed in `/Users/jules/ZcashNames/zns-orchard` after the final commit:

```sh
cargo fmt --check
cargo build
cargo build --all-features
cargo check --features unsafe-zns,circuit
cargo check --no-default-features --features unsafe-zns
cargo check --all-targets --all-features
cargo test
cargo test --no-default-features --features unsafe-zns
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --all-features --no-deps
```

Important test confirmations:

- `builder::tests::zns_output_bundle_verifies` passed.
- `builder::tests::zns_spend_bundle_verifies` passed.
- NU6.3 / Ironwood restricted and unrestricted bundle proof tests passed.
- PCZT cross-address restriction and proof tests passed.

No CI workflow file was found in the checkout (`.github`, `Makefile`, and `justfile` were absent), so the above Cargo matrix is the local CI-equivalent that was run.

## Current `zns-mint` State

Repository:

`/Users/jules/ZcashNames/zns-mint`

Important: `zns-mint` was inspected but not updated in this pass. It already has many unrelated dirty changes. Do not assume a clean worktree.

Current dependency situation in `zns-mint/zns-mint/Cargo.toml`:

- `zcash_keys`, `zcash_protocol`, `zcash_primitives`, and `zcash_client_backend` are pinned to `zcash/librustzcash` rev:

```text
eb828caadb4b2be4a39823f95e50b42731a515f5
```

- `orchard` points to the ZNS fork rev:

```text
e9edfa65b249d1f5ffa78dd04173530b52607162
```

- `[patch.crates-io] orchard` also points to that same old ZNS fork rev.

After pushing or otherwise selecting the rebased orchard commit, `zns-mint` needs to update those orchard revs from old `e9edfa6...` to new `cd4afc0...` or another chosen pushed commit.

## Upstream / crates.io Status Checked

As of 2026-07-11:

Released on crates.io:

- `orchard 0.15.0`
- `zcash_protocol 0.10.0`
- `zcash_primitives 0.29.0`
- `zcash_proofs 0.29.0`
- `zcash_keys 0.15.0`
- `sapling-crypto 0.7.0`

Upstream `zcash/librustzcash` `main`:

- default branch `main`
- observed commit: `a97a3d5f46d096b94ceb71271c7d38f20af4e1f1`
- commit message: `zcash_client_backend: add bulk-flush methods to WalletCommitmentTrees`
- includes new `WalletCommitmentTrees::put_ironwood_shards` related API in `zcash_client_backend`

Not fully released as new wallet crate versions:

- `zcash_client_backend` is still `0.23.0` on crates.io and upstream `main`.
- `zcash_client_sqlite` is still `0.21.1` on crates.io and upstream `main`.

Important interpretation:

- The low-level protocol/primitives/proofs/key crates have NU6.3-ready crates.io releases.
- The wallet backend/storage layer has important Ironwood API work on upstream `main`, but no new version bump has been cut yet.
- For `zns-mint`, if it needs the latest wallet scanning/storage behavior for Ironwood before a backend/sqlite release, it likely needs a Git pin to `zcash/librustzcash` `main` or a specific post-Ironwood commit, not just crates.io versions.

## Remaining Task A: Push / Publish `zns-orchard`

Decide how to expose the rebased ZNS Orchard fork to `zns-mint`.

Recommended next step:

1. Push the rewritten branch:

```sh
cd /Users/jules/ZcashNames/zns-orchard
git push --force-with-lease origin main-ironwood
```

2. Use commit `cd4afc0` in `zns-mint` dependency pins, assuming that pushed commit is accepted as the new branch head.

Alternative:

- Create a new branch name instead of rewriting `origin/main-ironwood`.
- Pin `zns-mint` directly to `cd4afc0` after pushing that branch.

## Remaining Task B: Update `zns-mint` Dependencies

Target file:

`/Users/jules/ZcashNames/zns-mint/zns-mint/Cargo.toml`

Likely changes:

- Update the direct `orchard` dependency rev to the rebased fork commit.
- Update `[patch.crates-io] orchard` to the same rev.
- Update librustzcash Git pins from old `eb828ca...` to a NU6.3-ready commit, probably current upstream `main` or a chosen stable commit after:

```text
a97a3d5f46d096b94ceb71271c7d38f20af4e1f1
```

This should be done carefully because `zcash_client_backend` APIs changed. Expect compile errors around:

- scanning APIs
- note commitment tree storage
- Ironwood tree handling
- transaction/bundle version selection
- any assumptions that Orchard is only one pool instead of Orchard plus Ironwood protocol variants

After dependency edits:

```sh
cd /Users/jules/ZcashNames/zns-mint/zns-mint
cargo update
cargo check
cargo test
```

Also run any project-specific regtest or harness checks if feasible.

## Remaining Task C: Mint Readiness Review

Shielded-only readiness questions to answer after `zns-mint` compiles:

1. Sapling path

- Confirm current Sapling usage is unaffected by `sapling-crypto 0.7.0`.
- Confirm keys/address derivation still behaves as expected.

2. Orchard NU5-NU6.2 path

- Confirm existing Orchard Name Note creation/spend still works against bundle version `orchard_v2`.
- Confirm the ZNS override still produces the expected commitment and nullifier behavior for existing Name Notes.

3. Ironwood / NU6.3 path

- Decide how `zns-mint` chooses bundle and note versions:
  - pre-NU6.3 Orchard should use Orchard v2 / existing note version.
  - post-NU6.3 Ironwood should use Orchard v3 / Ironwood note version.
- Audit hard-coded calls to `BundleVersion::orchard_v2`, `NoteVersion`, `BranchId::for_height`, and any transaction builder defaults.
- Confirm Name Note ZNS override works with Ironwood commitments and nullifiers.
- Confirm wallet scanning stores and exposes Ironwood notes distinctly where upstream expects that distinction.
- Confirm any Merkle tree/frontier code accounts for Ironwood tree roots and not only Sapling/Orchard.

4. Wallet backend readiness risk

- `zcash_client_backend` and `zcash_client_sqlite` have not been released with a higher version yet.
- If `zns-mint` depends on unreleased Ironwood wallet APIs, use a Git pin.
- If trying crates.io only, expect gaps in Ironwood storage/scanning APIs.

5. Transparent exclusion

- The stated target is shielded-only.
- `zns-mint` currently has transparent-related code/dependencies because Treasury accepts transparent payments in existing comments/code.
- For NU6.3 shielded-only readiness, decide whether to:
  - leave transparent code untouched but not exercise it, or
  - actively remove/disable transparent paths.
- This decision affects dependency features like `transparent-inputs`.

## Notes / Caveats

- `zns-mint` worktree is dirty with many pre-existing changes. Avoid broad cleanup or resets.
- `zns-orchard` is outside the `zns-mint` workspace root, so future agents may need filesystem approval to edit/push there.
- Network access was needed for GitHub/crates.io checks.
- The crates.io HTTP API was returning transient 500/503 errors during discovery, so sparse registry index URLs were used successfully.

