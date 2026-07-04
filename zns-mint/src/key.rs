//! Key derivation for the ZNS mint daemon.
//!
//! Two Orchard spending keys are derived from a single seed via ZIP-32:
//!   - Treasury (account 0): receives user deposits, pays OTP fees, sweeps to registry + cold
//!   - Registry (account 1): creates and spends Name Notes

use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::MAIN_NETWORK;
use zeroize::Zeroizing;
use zip32::AccountId;

/// The two spending keys the mint needs.
pub struct Keys {
    treasury: UnifiedSpendingKey,
    registry: UnifiedSpendingKey,
}

impl Keys {
    /// Derive both accounts from a seed.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        let treasury = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            seed.as_ref(),
            AccountId::const_from_u32(0),
        )
        .expect("treasury key derivation");

        let registry = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            seed.as_ref(),
            AccountId::const_from_u32(1),
        )
        .expect("registry key derivation");

        // `seed` (the Zeroizing wrapper) is wiped by its Drop when the
        // caller lets it go out of scope.

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

    /// The Registry's Orchard spending key -- the sole signer for every Name
    /// Note lifecycle transition. This is the attested-boundary capability: it
    /// is `pub(crate)` so only the signer module can reach it, and it must never
    /// be `Debug`-formatted, logged, or copied out of the attested boundary.
    pub(crate) fn registry_orchard_spending_key(&self) -> &orchard::keys::SpendingKey {
        self.registry.orchard()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_accounts_produce_different_keys() {
        let keys = Keys::from_seed(Zeroizing::new([0u8; 32]));

        let t_bytes = keys.treasury.orchard().to_bytes();
        let r_bytes = keys.registry.orchard().to_bytes();

        assert_ne!(t_bytes, r_bytes, "treasury and registry must differ");
    }

    #[test]
    fn fvks_are_derivable() {
        let keys = Keys::from_seed(Zeroizing::new([0u8; 32]));

        let t_fvk = keys.treasury_fvk();
        let r_fvk = keys.registry_fvk();

        assert!(t_fvk.orchard().is_some());
        assert!(r_fvk.orchard().is_some());
    }
}
