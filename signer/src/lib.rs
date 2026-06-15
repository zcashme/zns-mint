//! `zns-mint` — ZNS Orchard note construction, proving, and the spend gate.
//!
//! Cryptographic core (only crate pulling the proving stack). Owns spend
//! key; authorizes under [`policy::SpendPolicy`]. Derives `(ψ, rcm)`
//! independently of any verifier.

pub mod derive;
pub mod error;
pub mod mint;
pub mod policy;
pub mod sign;

pub use derive::{zns_psi_rcm, ZNS_DOMAIN_TAG};
pub use error::{BuildError, SignError};
pub use mint::{
    build_funded_mint, build_memo_send, build_name_note, build_sweep, derive_psi_rcm, MintParams,
    MintResult, RelayResult,
};
pub use policy::{
    validate_name, FundingInput, MintIntent, MintPlan, MintProposal, PolicyError, RequestId,
    SpendGuard, SpendPolicy,
};
pub use sign::{test_orchard_ivk, test_registry_address, test_sapling_ivk, Signer, SweepResult};
