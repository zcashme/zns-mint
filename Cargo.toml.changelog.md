# Cargo.toml changelog

Tracks design-relevant dependency and build-configuration changes.

## 2026-07-25 — Production build guards for development escape hatches

- Added `compile_error!` guards in `src/lib.rs` so `dev-seed` and
  `pre-nu63-activation` cannot be enabled in release builds
  (`not(debug_assertions)`). Both features exist only for local development
  and regtest; a production artifact must never include them.

## 2026-07-22 — Orchard fork compile fix

The pinned `unsafe-zns` Orchard fork revision `34699d38695ad28c37a022155df5420760a29741`
failed to compile because `ZnsCandidateNote` was private while appearing as the `Note`
associated type in the public `zcash_note_encryption::Domain` implementation for
`ZnsIronwoodDomain`.

- Pointed the `orchard` direct dependency and the `[patch.crates-io]` override to the
  local checkout at `/Users/jules/ZcashNames/zns-orchard`.
- Applied a visibility fix on top of the pinned revision in that checkout:
  `struct ZnsCandidateNote` is now `pub` and derives `Debug`.
- This is a temporary build-unblock patch pending an upstream fork revision that
  includes the same visibility fix. The protocol behavior of the `unsafe-zns` fork
  is unchanged.
