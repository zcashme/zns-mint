//! Key derivation for the ZNS mint daemon.
//!
//! Two Orchard spending keys are derived from a single seed via ZIP-32:
//!   - Treasury (account 0): receives user deposits, pays OTP fees, sweeps to registry + cold
//!   - Registry (account 1): creates and spends Name Notes
//!
//! The seed is used once at construction and zeroized immediately after.
//! The two `UnifiedSpendingKey`s are held for the daemon's lifetime.
//! Viewing keys are derived on demand (matching zingolib's `UnifiedKeyStore` pattern).

use std::convert::TryInto;

use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::TEST_NETWORK;
use zeroize::Zeroizing;

/// The two spending keys the daemon needs.
pub struct Keys {
    treasury: UnifiedSpendingKey,
    registry: UnifiedSpendingKey,
}

impl Keys {
    /// Derive both accounts from a seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let treasury =
            UnifiedSpendingKey::from_seed(&TEST_NETWORK, seed.as_ref(), 0u32.try_into().unwrap())
                .expect("treasury key derivation");

        let registry =
            UnifiedSpendingKey::from_seed(&TEST_NETWORK, seed.as_ref(), 1u32.try_into().unwrap())
                .expect("registry key derivation");

        // seed is dropped here, Zeroizing wipes it

        Self { treasury, registry }
    }

    /// Derive the treasury's full viewing key (for scanning incoming notes).
    pub fn treasury_fvk(&self) -> UnifiedFullViewingKey {
        self.treasury.to_unified_full_viewing_key()
    }

    /// Derive the registry's full viewing key (for scanning incoming Name Notes).
    pub fn registry_fvk(&self) -> UnifiedFullViewingKey {
        self.registry.to_unified_full_viewing_key()
    }

    /// Borrow the treasury's raw Orchard spending key (for signing).
    pub fn treasury_spend(&self) -> &impl ::core::fmt::Debug {
        self.treasury.orchard()
    }

    /// Borrow the registry's raw Orchard spending key (for signing).
    pub fn registry_spend(&self) -> &impl ::core::fmt::Debug {
        self.registry.orchard()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_accounts_produce_different_keys() {
        let keys = Keys::from_seed([0u8; 32]);

        let t_bytes = keys.treasury.orchard().to_bytes();
        let r_bytes = keys.registry.orchard().to_bytes();

        assert_ne!(t_bytes, r_bytes, "treasury and registry must differ");
    }

    #[test]
    fn fvks_are_derivable() {
        let keys = Keys::from_seed([0u8; 32]);

        let t_fvk = keys.treasury_fvk();
        let r_fvk = keys.registry_fvk();

        assert!(t_fvk.orchard().is_some());
        assert!(r_fvk.orchard().is_some());
    }
}
