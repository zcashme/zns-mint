//! Key derivation for the ZNS mint daemon.
//!

use secrecy::{ExposeSecret, Secret};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::MAIN_NETWORK;
use zip32::AccountId;

use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

// ===========================================================================
// AccountKeys — per-account keys, generated at boot, held by each module
// ===========================================================================

/// An account's keys — the spending key and everything derivable from it.
struct AccountKeys {
    pub(crate) spending: UnifiedSpendingKey,
}

impl AccountKeys {
    /// The account's unified full viewing key — for scanning.
    ///
    /// Derived on demand from the spending key via
    /// `UnifiedSpendingKey::to_unified_full_viewing_key`. Contains Orchard,
    /// Sapling, and Transparent components.
    fn fvk(&self) -> UnifiedFullViewingKey {
        self.spending.to_unified_full_viewing_key()
    }

    /// The account's Orchard spending key.
    fn orchard_spending_key(&self) -> &orchard::keys::SpendingKey {
        self.spending.orchard()
    }

    /// The account's Sapling extended spending key.
    pub(crate) fn sapling_spending_key(&self) -> &sapling::zip32::ExtendedSpendingKey {
        self.spending.sapling()
    }

    /// The account's transparent account private key.
    pub(crate) fn transparent_spending_key(&self) -> &transparent::keys::AccountPrivKey {
        self.spending.transparent()
    }
}

/// Treasury account-0 signing capability.
pub struct TreasuryKeys(AccountKeys);

impl TreasuryKeys {
    pub fn fvk(&self) -> UnifiedFullViewingKey {
        self.0.fvk()
    }

    pub(crate) fn orchard_spending_key(&self) -> &orchard::keys::SpendingKey {
        self.0.orchard_spending_key()
    }

    pub(crate) fn sapling_spending_key(&self) -> &sapling::zip32::ExtendedSpendingKey {
        self.0.sapling_spending_key()
    }

    pub(crate) fn transparent_spending_key(&self) -> &transparent::keys::AccountPrivKey {
        self.0.transparent_spending_key()
    }
}

/// Registry account-1 signing capability.
pub struct RegistryKeys(AccountKeys);

impl RegistryKeys {
    pub fn fvk(&self) -> UnifiedFullViewingKey {
        self.0.fvk()
    }

    pub(crate) fn orchard_spending_key(&self) -> &orchard::keys::SpendingKey {
        self.0.orchard_spending_key()
    }
}

// `UnifiedSpendingKey` has no `Drop`; if upstream ever adds one, the assertion
// below makes this fail to build instead of silently becoming UB.
const _: () = assert!(!std::mem::needs_drop::<UnifiedSpendingKey>());

impl Drop for AccountKeys {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_bytes(
                &mut self.spending as *mut _ as *mut u8,
                0,
                std::mem::size_of::<UnifiedSpendingKey>(),
            );
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// ===========================================================================
// Derivation function — called once at boot per account, never again
// ===========================================================================

/// Derive an account's keys from the seed.
///
/// Panics if derivation fails — a zero-seed on mainnet is a bug, not a runtime
/// condition. The upstream derivation code rejects invalid seeds (zero ask,
/// invalid IVKs); a panic here means the seed is cryptographically broken.
fn derive_account(seed: &Secret<[u8; 32]>, account: AccountId) -> AccountKeys {
    let usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, seed.expose_secret(), account)
        .expect("key derivation");
    AccountKeys { spending: usk }
}

pub fn derive_treasury(seed: &Secret<[u8; 32]>) -> TreasuryKeys {
    TreasuryKeys(derive_account(seed, TREASURY_ACCOUNT))
}

pub fn derive_registry(seed: &Secret<[u8; 32]>) -> RegistryKeys {
    RegistryKeys(derive_account(seed, REGISTRY_ACCOUNT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;
    use zip32::fingerprint::SeedFingerprint;

    fn test_seed() -> Secret<[u8; 32]> {
        Secret::new([0u8; 32])
    }

    fn test_treasury() -> TreasuryKeys {
        derive_treasury(&test_seed())
    }

    fn test_registry() -> RegistryKeys {
        derive_registry(&test_seed())
    }

    // ------------------------------------------------------------------
    // Seed fingerprint (upstream standalone function)
    // ------------------------------------------------------------------

    #[test]
    fn seed_fingerprint_is_derivable() {
        let seed = test_seed();
        let fp = SeedFingerprint::from_seed(seed.expose_secret()).unwrap();
        assert!(
            fp.to_string().starts_with("zip32seedfp1"),
            "fingerprint must be bech32m-encoded with zip32seedfp HRP, got: {}",
            fp
        );
    }

    #[test]
    fn seed_fingerprint_is_deterministic() {
        let seed_a = Secret::new([0u8; 32]);
        let seed_b = Secret::new([0u8; 32]);
        let fp_a = SeedFingerprint::from_seed(seed_a.expose_secret()).unwrap();
        let fp_b = SeedFingerprint::from_seed(seed_b.expose_secret()).unwrap();
        assert_eq!(fp_a, fp_b, "same seed must produce same fingerprint");
    }

    #[test]
    fn different_seeds_produce_different_fingerprints() {
        let seed_a = Secret::new([0u8; 32]);
        let seed_b = Secret::new([1u8; 32]);
        let fp_a = SeedFingerprint::from_seed(seed_a.expose_secret()).unwrap();
        let fp_b = SeedFingerprint::from_seed(seed_b.expose_secret()).unwrap();
        assert_ne!(
            fp_a, fp_b,
            "different seeds must produce different fingerprints"
        );
    }

}
