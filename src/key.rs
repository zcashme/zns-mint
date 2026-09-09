//! The mint's keys: two accounts, one seed, capabilities over copies.

use std::marker::PhantomData;

use secrecy::{ExposeSecret, Secret};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::Parameters;
use zip32::AccountId;

use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

mod sealed {
    pub trait Sealed {}
}

/// A mint-controlled ZIP-32 account — Treasury (0) or Registry (1), sealed.
pub trait MintAccount: sealed::Sealed {
    /// The ZIP-32 account index.
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

/// An account's signing capability — generated once at boot, moved never copied.
pub struct AccountKeys<A: MintAccount> {
    spending: UnifiedSpendingKey,
    /// `fn() -> A` holds no value and touches no auto traits.
    marker: PhantomData<fn() -> A>,
}

/// The Treasury's keys.
pub type TreasuryKeys = AccountKeys<Treasury>;
/// The Registry's keys.
pub type RegistryKeys = AccountKeys<Registry>;

impl<A: MintAccount> AccountKeys<A> {
    /// Derives the account's keys from the sealed seed; panics only on a cryptographically broken seed.
    pub fn derive<P: Parameters>(network: &P, seed: &Secret<[u8; 32]>) -> Self {
        let usk = UnifiedSpendingKey::from_seed(network, seed.expose_secret(), A::ACCOUNT_ID)
            .expect("FATAL: key derivation");
        Self {
            spending: usk,
            marker: PhantomData,
        }
    }

    /// The unified full viewing key — for scanning and address derivation.
    pub fn fvk(&self) -> UnifiedFullViewingKey {
        self.spending.to_unified_full_viewing_key()
    }

    /// The Orchard-family spending key, for assembly paths that wrap it into upstream types themselves.
    pub fn orchard_spending_key(&self) -> &orchard::keys::SpendingKey {
        self.spending.orchard()
    }

    /// The Orchard-family full viewing key — the Ironwood viewing lane (Ironwood notes are signed by Orchard-family keys).
    pub fn orchard_fvk(&self) -> orchard::keys::FullViewingKey {
        self.spending.orchard().into()
    }

    /// The one sanctioned copy of the spending key — handed to upstream's generic payment path ([`create_proposed_transactions`][upstream], Sapling-disabled and Ironwood-only) and dropped with the call.
    ///
    /// [upstream]: zcash_client_backend::data_api::wallet::create_proposed_transactions
    pub(crate) fn usk_clone(&self) -> UnifiedSpendingKey {
        self.spending.clone()
    }
}
