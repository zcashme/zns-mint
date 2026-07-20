//! Key derivation for the ZNS mint daemon.
//!

use secrecy::{ExposeSecret, Secret};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::MAIN_NETWORK;
use zip32::AccountId;

// ===========================================================================
// AccountKeys — per-account keys, generated at boot, held by each module
// ===========================================================================

/// An account's keys — the spending key and everything derivable from it.
pub struct AccountKeys {
    pub(crate) spending: UnifiedSpendingKey,
}

impl AccountKeys {
    /// The account's unified full viewing key — for scanning.
    ///
    /// Derived on demand from the spending key via
    /// `UnifiedSpendingKey::to_unified_full_viewing_key`. Contains Orchard,
    /// Sapling, and Transparent components.
    pub fn fvk(&self) -> UnifiedFullViewingKey {
        self.spending.to_unified_full_viewing_key()
    }

    /// The account's Orchard spending key.
    pub(crate) fn orchard_spending_key(&self) -> &orchard::keys::SpendingKey {
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

impl Drop for AccountKeys {
    fn drop(&mut self) {
        // UnifiedSpendingKey doesn't implement Zeroize (upstream limitation),
        // so we manually zeroize its memory. The individual spending key types
        // (orchard::keys::SpendingKey is [u8; 32], sapling::ExtendedSpendingKey,
        // transparent::keys::AccountPrivKey) contain raw key bytes that must not
        // persist in freed memory.
        //
        // SAFETY: We are dropping self.spending, so no other references to it
        // exist. write_bytes overwrites every byte of the struct with zeros.
        // This is safe because:
        // - We own the memory (it's a field of self, which is being dropped)
        // - No destructors need to run on the zeroed bytes (UnifiedSpendingKey
        //   has no Drop impl, only #[derive(Clone)])
        // - The memory is valid and properly aligned (it's a field of self)
        unsafe {
            std::ptr::write_bytes(
                &mut self.spending as *mut _ as *mut u8,
                0,
                std::mem::size_of::<UnifiedSpendingKey>(),
            );
        }
        // Prevent the compiler from optimizing away the zeroization.
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
pub fn derive_account(seed: &Secret<[u8; 32]>, account: AccountId) -> AccountKeys {
    let usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, seed.expose_secret(), account)
        .expect("key derivation");
    AccountKeys { spending: usk }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;
    use zip32::fingerprint::SeedFingerprint;

    fn test_seed() -> Secret<[u8; 32]> {
        Secret::new([0u8; 32])
    }

    fn test_treasury() -> AccountKeys {
        derive_account(&test_seed(), AccountId::const_from_u32(0))
    }

    fn test_registry() -> AccountKeys {
        derive_account(&test_seed(), AccountId::const_from_u32(1))
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

    // ------------------------------------------------------------------
    // Derivation
    // ------------------------------------------------------------------

    #[test]
    fn derive_account_succeeds_for_valid_accounts() {
        let seed = test_seed();
        let usk_0 = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            seed.expose_secret(),
            AccountId::const_from_u32(0),
        );
        let usk_1 = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            seed.expose_secret(),
            AccountId::const_from_u32(1),
        );
        assert!(usk_0.is_ok(), "account 0 derivation must succeed");
        assert!(usk_1.is_ok(), "account 1 derivation must succeed");
    }

    // ------------------------------------------------------------------
    // AccountKeys — viewing
    // ------------------------------------------------------------------

    #[test]
    fn fvk_has_all_three_pools() {
        let treasury = test_treasury();
        let fvk = treasury.fvk();
        assert!(fvk.orchard().is_some(), "must have Orchard");
        assert!(fvk.sapling().is_some(), "must have Sapling");
        assert!(fvk.transparent().is_some(), "must have Transparent");
    }

    #[test]
    fn fvk_is_deterministic() {
        let a = test_treasury();
        let b = test_treasury();
        assert!(
            a.fvk().subsumes_ufvk(&b.fvk()) && b.fvk().subsumes_ufvk(&a.fvk()),
            "same seed + account must produce same UFVK"
        );
    }

    // ------------------------------------------------------------------
    // AccountKeys — spending
    // ------------------------------------------------------------------

    #[test]
    fn orchard_spending_key_is_accessible() {
        let treasury = test_treasury();
        let _ = treasury.orchard_spending_key();
    }

    #[test]
    fn sapling_spending_key_is_accessible() {
        let treasury = test_treasury();
        let _ = treasury.sapling_spending_key();
    }

    #[test]
    fn transparent_spending_key_is_accessible() {
        let treasury = test_treasury();
        let _ = treasury.transparent_spending_key();
    }

    // ------------------------------------------------------------------
    // Cross-account
    // ------------------------------------------------------------------

    #[test]
    fn orchard_spending_keys_differ_between_accounts() {
        let treasury = test_treasury();
        let registry = test_registry();
        let t = treasury.orchard_spending_key().to_bytes();
        let r = registry.orchard_spending_key().to_bytes();
        assert_ne!(t, r, "orchard spending keys must differ");
    }

    #[test]
    fn sapling_spending_keys_differ_between_accounts() {
        let treasury = test_treasury();
        let registry = test_registry();
        let t = treasury.sapling_spending_key().to_bytes();
        let r = registry.sapling_spending_key().to_bytes();
        assert_ne!(t, r, "sapling spending keys must differ");
    }

    #[test]
    fn fvks_differ_between_accounts() {
        let t = test_treasury().fvk();
        let r = test_registry().fvk();
        assert!(!t.subsumes_ufvk(&r), "UFVKs must differ between accounts");
    }
}
