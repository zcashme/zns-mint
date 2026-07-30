#![allow(dead_code)]

// Development escape hatches must never reach a production artifact.
#[cfg(all(feature = "dev-seed", not(debug_assertions)))]
compile_error!("dev-seed is a development-only feature and must not be enabled in release/production builds");

#[cfg(all(feature = "dev-regtest", not(debug_assertions)))]
compile_error!("dev-regtest is a development-only feature and must not be enabled in release/production builds");

pub mod auth;
pub mod boot;
pub mod key;
pub mod metrics;
pub mod mint;
pub mod registry;
pub mod sync;

pub mod treasury;
pub mod wallet;
pub mod zcash;
