//! Registry: the ZNS name-chain state machine, transition authorization, and
//! transaction assembly path.
//!
//! Submodules:
//! - [`state`] — `Registry`, `Tip`, `Rcm`, `Psi`, `RegistryHistoryRecord`
//! - [`authorize`] — `NameNoteRequest`, `authorize_claim`/`update`/`release`
//! - [`liquidity`] — Registry fee-note classification and top-up policy
//! - [`transaction`] — `build_transaction`, `TransparentOutput`
//! - [`signing`] — `assemble_and_sign_transaction`

pub mod authorize;
pub mod liquidity;
pub mod signing;
pub mod state;
pub mod transaction;

// Re-export the primary public API so existing `crate::registry::` paths work.
pub use authorize::{
    authorize_claim, authorize_release, authorize_update, current_tip, NameNoteRequest,
};
pub use liquidity::{
    classify_registry_ironwood_note, classify_registry_note_parts, RegistryFeeLiquidity,
    RegistryFundingPlan, RegistryNoteClass,
};
pub use signing::assemble_and_sign_transaction;
pub use state::{Psi, Rcm, Registry, RegistryHistoryRecord, Tip};
pub use transaction::{build_transaction, TransparentOutput};
