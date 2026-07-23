# Invariant catalog changelog

Tracks design-relevant changes to `docs/harness/invariants.md`.

## 2026-07-22 — Orchard fork dependency source

- Updated the upstream-evidence section to note that the `unsafe-zns` Orchard
  fork is currently sourced from the local checkout
  `/Users/jules/ZcashNames/zns-orchard` rather than directly from the GitHub
  revision `34699d38695ad28c37a022155df5420760a29741`.
- The local checkout is based on that revision with a compile-fix commit that
  makes `ZnsCandidateNote` public. The protocol properties cited (Ironwood v3
  bundle version, `add_zns_spend` / `add_zns_output`, V6-only Ironwood bundles)
  remain unchanged.

## 2026-07-23 — Validated Name Note decryption boundary

- Replaced the obsolete public-candidate evidence with the private-domain
  `try_zns_note_decryption` facade and opaque `ValidatedZnsNote<P>` contract.
- Recorded that the fork now performs the memo-derived opening versus action
  commitment comparison internally, retains the exact parsed payload, and
  gates nullifier derivation on recipient ownership by the supplied FVK.
- This is fork-level evidence only; the mint scanner still needs to consume the
  facade and enforce Name Note value, recipient, transition, and tree-position
  semantics before Registry state can be treated as validated.
