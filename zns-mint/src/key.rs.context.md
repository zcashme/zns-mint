# Context for src/key.rs (zns-mint)

This file defines the ZIP-32 key-derivation primitives for the daemon.

## Current State
- `Keys::from_seed([u8; 32])` derives two Orchard spending keys from a single seed.
- Account assignment is fixed:
  - Treasury = account 0
  - Registry = account 1
- The seed is wrapped in `Zeroizing` so plaintext seed material is wiped when it goes out of scope.
- Public helpers expose:
  - treasury / registry UFVKs
  - encoded UFVK strings
  - raw Orchard spending key references for signing
- Tests verify the two accounts differ and that both UFVKs are derivable.

## Purpose
`key.rs` is the narrow place where the daemon turns one seed into the two logical wallet identities it needs.

The intent is:
- keep the derivation logic isolated from boot/run orchestration
- avoid leaking seed material
- make it easy to upgrade the surrounding wallet flow without rethinking the key model

## Constraints
- Do not add configuration parsing or env-var access here.
- Keep the account mapping stable unless the project explicitly changes it.
- Treat the seed as sensitive input; do not log or persist it.
- Preserve the small surface area unless the user asks for more wallet/key functionality.

## Related Files
- `src/boot.rs.context.md` - boot flow that consumes `Keys`
- `src/main.rs.context.md` - overall TEE and two-account design
- `src/main.changelog.md` - when the key/boot context changed

