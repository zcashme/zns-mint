//! `zns-signer` — ZNS Orchard note construction + commitment verification.
//!
//! This is the cryptographic core and the only crate that pulls the orchard
//! `circuit` (halo2) proving stack. It is destined to become the **in-enclave
//! signer**: the `(sighash, alpha) -> spend-auth signature` boundary will live
//! here, behind which a single AWS Nitro-enclave key authorizes mints today —
//! and, if the threat model ever demands it, t-of-n FROST signers later, without
//! the host changing.

pub mod mint;
pub mod policy;
pub mod sign;
pub mod verify;

pub use mint::{build_funded_mint, build_name_note, MintParams, MintResult};
pub use policy::{
    validate_name, FundingInput, MintIntent, MintPlan, MintProposal, PolicyError, RequestId,
    SpendGuard, SpendPolicy, SweepPlan,
};
pub use sign::{SignError, Signer};
pub use verify::{expected_cmx, verify_cmx};
