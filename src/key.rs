//! Key derivation for ZNS mint .

use std::marker::PhantomData;

use secrecy::{ExposeSecret, Secret};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::Parameters;
use zip32::AccountId;

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

    /// The account's Orchard-family spending key — the raw
    /// `orchard::keys::SpendingKey` from which FVKs and spend-authorizing
    /// keys derive. Callers that need a specific capability should prefer
    /// [`orchard_fvk`](Self::orchard_fvk) or [`orchard_ask`](Self::orchard_ask);
    /// this accessor exists for the assembly paths that wrap the spending key
    /// into upstream types themselves (`FullViewingKey::from`, etc.).
    pub fn orchard_spending_key(&self) -> &orchard::keys::SpendingKey {
        self.spending.orchard()
    }

    /// The account's Orchard-family full viewing key — the Ironwood
    /// viewing lane: note commitment addresses, OVKs, and builder spends.
    /// Ironwood notes are signed by the Orchard-family keys, so the accessor
    /// names the family, not the pool (upstream `add_ironwood_spend` likewise
    /// consumes `ufvk.orchard()`, zcash_client_backend `wallet.rs:2009`).
    pub fn orchard_fvk(&self) -> orchard::keys::FullViewingKey {
        self.spending.orchard().into()
    }

    /// The account's Orchard-family spend-authorizing key (`ask` in the
    /// spec) — the sole Ironwood signing capability.
    pub(crate) fn orchard_ask(&self) -> orchard::keys::SpendAuthorizingKey {
        self.spending.orchard().into()
    }

    /// The account's full unified spending key, owned.
    ///
    /// Upstream's generic payment path
    /// ([`data_api::wallet::create_proposed_transactions`][upstream])
    /// takes an owned [`UnifiedSpendingKey`] inside `SpendingKeys`. This is
    /// the one sanctioned clone of a capability: the caller hands the clone
    /// straight to upstream and drops it with the call. The mint's own
    /// assembly paths continue to use the Orchard-family accessors above;
    /// the upstream path is additionally constrained by a Sapling-disabled
    /// prover and an Ironwood-only spend policy, so no other pool can be
    /// signed for even though the key is whole.
    ///
    /// [upstream]: zcash_client_backend::data_api::wallet::create_proposed_transactions
    pub(crate) fn usk_clone(&self) -> UnifiedSpendingKey {
        self.spending.clone()
    }
}
