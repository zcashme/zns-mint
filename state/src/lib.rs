//! `zns-state` — ZNS registry persistence.
//!
//! Owns the SQLite store: the `name_records` table (current tip per name) and,
//! as it lands, the append-only minted-action log. Split out of `zns-core` so
//! the storage layer is its own crate (cf. `zebra-state`) and pure consumers of
//! the domain types never link rusqlite.

pub mod db;

pub use db::{delete_record, get_record, init_schema, upsert_record, NameRecord};
