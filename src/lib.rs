#![allow(dead_code)]

// Development escape hatches must never reach a production artifact.
#[cfg(all(feature = "regtest", not(debug_assertions)))]
compile_error!("regtest is a development-only feature and must not be enabled in release/production builds");

pub mod boot;
pub mod key;
pub mod mint;
pub mod wallet;
pub mod zcash;