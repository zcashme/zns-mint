//! The Zcash network the registry operates on.
//!
//! `zcash_protocol::consensus::Network` only models Main and Test; a local
//! regtest chain (which activates every upgrade at height 1 and uses the
//! `uregtest` address HRP) is a third case. [`ZcashNetwork`] adds it and
//! implements [`Parameters`], so it drives both `BranchId::for_height` (correct
//! transaction parsing) and Unified Address encode/decode (correct HRP).

use zcash_protocol::consensus::{
    BlockHeight, NetworkType, NetworkUpgrade, Parameters, MAIN_NETWORK, TEST_NETWORK,
};

/// Which Zcash network the registry runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZcashNetwork {
    /// Production mainnet.
    Main,
    /// Public testnet.
    Test,
    /// A local regtest chain — all upgrades active from height 1.
    Regtest,
}

impl ZcashNetwork {
    /// Parse the `ZNS_NETWORK` value (`main` / `test` / `regtest`).
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "main" | "mainnet" => Some(Self::Main),
            "test" | "testnet" => Some(Self::Test),
            "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }
}

impl Parameters for ZcashNetwork {
    fn network_type(&self) -> NetworkType {
        match self {
            ZcashNetwork::Main => NetworkType::Main,
            ZcashNetwork::Test => NetworkType::Test,
            ZcashNetwork::Regtest => NetworkType::Regtest,
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            ZcashNetwork::Main => MAIN_NETWORK.activation_height(nu),
            ZcashNetwork::Test => TEST_NETWORK.activation_height(nu),
            // Regtest: everything up to NU6 is live from block 1 (matches zebra's
            // Regtest, which reports Overwinter…NU6 active at height 1).
            ZcashNetwork::Regtest => match nu {
                NetworkUpgrade::Overwinter
                | NetworkUpgrade::Sapling
                | NetworkUpgrade::Blossom
                | NetworkUpgrade::Heartwood
                | NetworkUpgrade::Canopy
                | NetworkUpgrade::Nu5
                | NetworkUpgrade::Nu6 => Some(BlockHeight::from_u32(1)),
                _ => None,
            },
        }
    }
}
