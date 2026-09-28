// Development escape hatches must never reach a production artifact.
#[cfg(all(feature = "regtest", not(debug_assertions)))]
compile_error!(
    "regtest is a development-only feature and must not be enabled in release/production builds"
);
#[cfg(all(feature = "fake-tee", not(debug_assertions)))]
compile_error!(
    "fake-tee is a development-only feature and must not be enabled in release/production builds"
);
#[cfg(all(feature = "testnet", feature = "regtest"))]
compile_error!("testnet and regtest are mutually exclusive network features");

pub mod boot;
pub use boot::{capsule, tee, RegistryKeys, TreasuryKeys};
pub mod metrics;
pub mod mint;
pub mod wallet;
pub mod zcash;
