//! `zns-signer` — ZNS Orchard note construction, proving, and the spend gate.
//!
//! The cryptographic core and the only crate that pulls the orchard `circuit`
//! (halo2) proving stack. It is the **in-enclave signer**: it owns the spend
//! key and authorizes mints/sweeps under [`policy::SpendPolicy`].
//!
//! It derives `(ψ, rcm)` with its own [`derive`] implementation and does **not**
//! depend on `zns-verify` — the registry (producer) and the verification kernel
//! (consumer) keep independent copies of the spec so each can catch the other's
//! bugs. The registry never verifies its own output; that is the client's job.

pub mod derive;
pub mod mint;
pub mod policy;
pub mod sign;

pub use derive::{zns_psi_rcm, ZNS_DOMAIN_TAG};
pub use mint::{
    build_funded_mint, build_memo_send, build_name_note, build_sweep, MintParams, MintResult,
};
pub use policy::{
    validate_name, FundingInput, MintIntent, MintPlan, MintProposal, PolicyError, RequestId,
    SpendGuard, SpendPolicy, SweepPlan,
};
pub use sign::{SignError, Signer, SweepResult};
