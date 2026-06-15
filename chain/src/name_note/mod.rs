//! Name Note scanning support — relaxed Orchard decrypt + binding verify.
//!
//! Registry-authored Name Notes use deterministic `(ψ, rcm)` rather than ZIP-212
//! `rseed`, so standard trial decryption drops them. This module ports the
//! consumer-side path from `zns-verify` without re-adding that dependency.

mod commit;
mod decrypt;
mod hash;
mod verify;

pub use commit::note_commitment_cmx;
pub use decrypt::{try_compact_orchard_relaxed, try_decrypt_orchard_relaxed};
pub use hash::zns_psi_rcm;
pub use verify::{verify_name_note, verify_name_note_decrypted};

#[cfg(test)]
mod tests;