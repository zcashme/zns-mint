//! Shared ZNS custody cryptography.
//!
//! [`capsule`] seals the ZIP-32 seed. [`sealing`] is the TEE seam that
//! derives the sealing key and requests a report. [`attestation`] verifies
//! a SEV-SNP report against a pinned AMD ARK.
//!
//! [`genesis`], [`upgrade`], and [`migration`] are the canonical statements
//! for a finished ceremony and for moving that seed to a new measurement.
//! Ceremony and migration orchestration stay outside this crate.

#[cfg(all(feature = "fake-tee", not(debug_assertions)))]
compile_error!(
    "fake-tee is a development-only feature and must not be enabled in release/production builds"
);

pub mod attestation;
pub mod capsule;
pub mod genesis;
pub mod migration;
pub mod sealing;
pub mod upgrade;
