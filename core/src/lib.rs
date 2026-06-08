//! `zns-core` — shared ZNS types with no cryptographic dependencies.
//!
//! Holds the memo parser, the [`RegistryError`] type, and SQLite persistence.
//! Both the `zns-host` daemon and the `zns-signer` (crypto / future enclave)
//! crate depend on this. It deliberately pulls in **no** orchard / halo2, so a
//! light consumer (memo parsing, DB lookups) never compiles the proving stack.

pub mod db;
pub mod error;
pub mod memo;
pub mod store;

pub use db::NameRecord;
pub use error::RegistryError;
pub use memo::{parse_memo, Action, ParsedMemo};
