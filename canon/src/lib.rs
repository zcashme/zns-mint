//! Shared ZNS custody cryptography.
//!
//! [`capsule`] seals the ZIP-32 seed. [`sealing`] is the TEE seam that
//! derives the sealing key and requests a report. [`attestation`] verifies
//! a SEV-SNP report against a pinned AMD ARK. The genesis ceremony stays
//! in `zns-keygen`.

#[cfg(all(feature = "fake-tee", not(debug_assertions)))]
compile_error!(
    "fake-tee is a development-only feature and must not be enabled in release/production builds"
);

pub mod attestation;
pub mod capsule;
pub mod sealing;
