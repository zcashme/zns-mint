//! `zns-core` — shared ZNS domain types with no cryptographic dependencies.
//!
//! Holds the action kinds, the memo parser, and the cross-cutting
//! [`RegistryError`]. Persistence lives in `zns-state`; crypto in `zns-signer`.
//! It deliberately pulls in **no** orchard / halo2, so a light consumer (memo
//! parsing, action types) never compiles the proving stack.

pub mod action;
pub mod error;
pub mod memo;

pub use action::{Action, ZERO_PREV_RCM};
pub use error::RegistryError;
pub use memo::{parse_memo, ParsedMemo};
