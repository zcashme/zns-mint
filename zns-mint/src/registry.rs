//! Registry: the ZNS name-chain state machine, transition authorization, and
//! transaction assembly path.
//!
//! Submodules:
//! - [`state`] — `Registry`, `Tip`, `Rcm`, `Psi`, `RegistryHistoryRecord`
//! - [`authorize`] — `NameNoteRequest`, `authorize_claim`/`update`/`release`
//! - [`transaction`] — `build_transaction`, `TransparentOutput`, `ScriptPubKey`
//! - [`signing`] — `assemble_and_sign_transaction`

pub mod state;
pub mod authorize;
pub mod transaction;
pub mod signing;

#[cfg(test)]
mod sapling_test;

// Re-export the primary public API so existing `crate::registry::` paths work.
pub use authorize::{
    authorize_claim, authorize_release, authorize_update, current_tip, NameNoteRequest,
};
pub use signing::assemble_and_sign_transaction;
pub use state::{Registry, RegistryHistoryRecord, Rcm, Psi, Tip};
pub use transaction::{build_transaction, ScriptPubKey, TransparentOutput};