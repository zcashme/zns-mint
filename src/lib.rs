// Development escape hatches must never reach a production artifact.
#[cfg(all(feature = "regtest", not(debug_assertions)))]
compile_error!(
    "regtest is a development-only feature and must not be enabled in release/production builds"
);
#[cfg(all(feature = "fake-tee", not(debug_assertions)))]
compile_error!(
    "fake-tee is a development-only feature and must not be enabled in release/production builds"
);

pub mod boot;
pub mod capsule;
mod key;
pub use key::{RegistryKeys, TreasuryKeys};
pub mod metrics;
pub mod mint;
pub mod tee;
pub mod wallet;
pub mod zcash;
