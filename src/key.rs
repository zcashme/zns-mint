//! Key derivation for the ZNS mint daemon.
//!
//! Two fixed capabilities are derived once at boot from the sealed seed:
//! Treasury (ZIP-32 account 0) and Registry (account 1). The accounts are
//! separated at the type level by uninhabited marker types, so a signing
//! capability can never be passed to the wrong consumer.

use std::marker::PhantomData;

use secrecy::{ExposeSecret, Secret};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zip32::AccountId;
use zcash_protocol::consensus::Parameters;

use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

mod sealed {
    pub trait Sealed {}
}

/// One of the mint's two fixed ZIP-32 accounts.
///
/// The trait is sealed: exactly [`Treasury`] and [`Registry`] can ever
/// implement it, so "one seed, two accounts, forever" is a type-system fact,
/// not a convention.
pub trait MintAccount: sealed::Sealed {
    /// The ZIP-32 account index this capability derives from.
    const ACCOUNT_ID: AccountId;
}

/// Treasury — account 0, the user-facing payment lane.
pub enum Treasury {}
/// Registry — account 1, the sole Name Note signer.
pub enum Registry {}

impl sealed::Sealed for Treasury {}
impl MintAccount for Treasury {
    const ACCOUNT_ID: AccountId = TREASURY_ACCOUNT;
}

impl sealed::Sealed for Registry {}
impl MintAccount for Registry {
    const ACCOUNT_ID: AccountId = REGISTRY_ACCOUNT;
}

/// An account's signing capability: the spending key and everything derived
/// from it.
///
/// Generated once per account at boot and never cloned — capabilities move,
/// they don't copy.
pub struct AccountKeys<A: MintAccount> {
    spending: UnifiedSpendingKey,
    /// `fn() -> A` holds no `A` value and does not affect auto traits; the
    /// account exists only in the type.
    marker: PhantomData<fn() -> A>,
}

/// Existing names keep their meaning; the type parameter is the account.
pub type TreasuryKeys = AccountKeys<Treasury>;
pub type RegistryKeys = AccountKeys<Registry>;

impl<A: MintAccount> AccountKeys<A> {
    /// Derives this account's keys from the sealed seed.
    ///
    /// Panics if derivation fails — upstream derivation rejects
    /// cryptographically broken seeds (zero ask, invalid IVKs), so a panic
    /// here is a bug, not a runtime condition. The account index comes from
    /// `A`'s [`MintAccount`] impl; no caller can supply or swap one.
    pub fn derive<P: Parameters>(network: &P, seed: &Secret<[u8; 32]>) -> Self {
        let usk = UnifiedSpendingKey::from_seed(network, seed.expose_secret(), A::ACCOUNT_ID)
            .expect("FATAL: key derivation");
        Self {
            spending: usk,
            marker: PhantomData,
        }
    }

    /// The account's unified full viewing key — for scanning and address
    /// derivation. Reconstructed on demand from the spending key; upstream
    /// provides no inverse.
    pub fn fvk(&self) -> UnifiedFullViewingKey {
        self.spending.to_unified_full_viewing_key()
    }

    /// The account's Orchard-family full viewing key — the Ironwood
    /// viewing lane: note commitment addresses, OVKs, and builder spends.
    /// Ironwood notes are signed by the Orchard-family keys, so the accessor
    /// names the family, not the pool (upstream `add_ironwood_spend` likewise
    /// consumes `ufvk.orchard()`, zcash_client_backend `wallet.rs:2009`).
    pub(crate) fn orchard_fvk(&self) -> orchard::keys::FullViewingKey {
        self.spending.orchard().into()
    }

    /// The account's Orchard-family spend-authorizing key (`ask` in the
    /// spec) — the sole Ironwood signing capability.
    pub(crate) fn orchard_ask(&self) -> orchard::keys::SpendAuthorizingKey {
        self.spending.orchard().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_address::test_vectors;
    use zcash_keys::address::Address;
    use zcash_keys::keys::{ReceiverRequirement::*, UnifiedAddressRequest};
    use zcash_protocol::consensus::MAIN_NETWORK;

    /// The type-level account binding is the one thing upstream cannot test
    /// for us: `TreasuryKeys`/`RegistryKeys` must derive exactly the accounts
    /// the ZIP-316 unified test vectors name. The derivation-and-comparison
    /// body mirrors upstream's own `ufvk_derivation` test
    /// (`zcash_keys` `keys.rs:2077`), which regresses against the same
    /// vectors.
    #[test]
    fn unified_vectors_bind_accounts_correctly() {
        for tv in test_vectors::UNIFIED {
            let derive = |account: u32| -> Option<UnifiedFullViewingKey> {
                match account {
                    0 => Some(TreasuryKeys::derive(&MAIN_NETWORK, &Secret::new(tv.root_seed)).fvk()),
                    1 => Some(RegistryKeys::derive(&MAIN_NETWORK, &Secret::new(tv.root_seed)).fvk()),
                    // The mint has exactly two accounts; vectors for other
                    // ZIP-32 accounts exercise nothing we can express.
                    _ => None,
                }
            };
            let Some(ufvk) = derive(tv.account) else {
                continue;
            };

            let d_idx = zip32::DiversifierIndex::from(tv.diversifier_index);

            // The test vectors contain some diversifier indices that do not
            // generate valid Sapling addresses, so skip those (as upstream
            // does).
            if ufvk.sapling().unwrap().address(d_idx).is_none() {
                continue;
            }

            let ua = ufvk
                .address(
                    d_idx,
                    UnifiedAddressRequest::unsafe_custom(Omit, Require, Require),
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "unified address generation failed for account {}: {:?}",
                        tv.account, err
                    )
                });

            match Address::decode(&MAIN_NETWORK, tv.unified_addr) {
                Some(Address::Unified(tvua)) => {
                    // We always derive transparent and Sapling receivers, but
                    // not every value in the test vectors has these present.
                    if tvua.has_transparent() {
                        assert_eq!(tvua.transparent(), ua.transparent());
                    }
                    if tvua.has_sapling() {
                        assert_eq!(tvua.sapling(), ua.sapling());
                    }
                }
                _other => {
                    panic!(
                        "{} did not decode to a valid unified address",
                        tv.unified_addr
                    );
                }
            }
        }
    }

    /// The capability's derivation must be byte-identical to upstream's
    /// value-keyed derivation for the same account. `UFVK` has no equality,
    /// so compare through `UIVK`, which does (`zcash_keys` `keys.rs:1316`).
    #[test]
    fn type_bound_derivation_matches_value_keyed() {
        let seed = Secret::new(test_vectors::UNIFIED[0].root_seed);

        let treasury =
            TreasuryKeys::derive(&MAIN_NETWORK, &seed).fvk().to_unified_incoming_viewing_key();
        let value_keyed = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            seed.expose_secret(),
            TREASURY_ACCOUNT,
        )
        .expect("vector seed derives a valid USK")
        .to_unified_full_viewing_key()
        .to_unified_incoming_viewing_key();
        assert_eq!(treasury, value_keyed);

        let registry =
            RegistryKeys::derive(&MAIN_NETWORK, &seed).fvk().to_unified_incoming_viewing_key();
        let value_keyed = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            seed.expose_secret(),
            REGISTRY_ACCOUNT,
        )
        .expect("vector seed derives a valid USK")
        .to_unified_full_viewing_key()
        .to_unified_incoming_viewing_key();
        assert_eq!(registry, value_keyed);
    }
}
