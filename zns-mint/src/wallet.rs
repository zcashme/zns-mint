//! ZNS mint wallet.
//!
pub mod selection;
pub mod trees;
pub mod transaction;
pub mod balance;

use std::collections::BTreeMap;

use zcash_keys::keys::UnifiedFullViewingKey;
use zip32::AccountId;

use balance::WalletBalance;
use trees::ShardTrees;

/// The in-memory ZNS wallet engine: a notes table and a tree.
pub struct Wallet {
    // Identity / scanning inputs (read-only after boot).
    ufvk_map: BTreeMap<AccountId, UnifiedFullViewingKey>,

    // Tracks unspent notes and spent nullifiers.
    pub ledger: WalletBalance,

    // The running commitment trees for Orchard and Sapling.
    pub trees: ShardTrees,
}

impl Wallet {
    /// Create a new, empty wallet.
    pub fn new(ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>) -> Self {
        Self {
            ufvk_map: ufvks.into_iter().collect(),
            ledger: WalletBalance::new(),
            trees: ShardTrees::new(),
        }
    }

    /// Read-only access to an account's unified full viewing key.
    /// Used by the scanner to derive IVKs for trial decryption.
    pub fn ufvk_for(&self, account: AccountId) -> Option<&UnifiedFullViewingKey> {
        self.ufvk_map.get(&account)
    }

    pub fn notes_for(&self, account: AccountId) -> impl Iterator<Item = &crate::wallet::transaction::ReceivedOrchardNote> {
        self.ledger
            .unspent
            .orchard
            .get(&account)
            .into_iter()
            .flat_map(|m| m.values())
    }

    pub fn balance(&self, account: AccountId) -> zcash_protocol::value::Zatoshis {
        let orchard_val: u64 = self
            .ledger
            .unspent
            .orchard
            .get(&account)
            .map(|m| m.values().map(|n| n.note.value().inner()).sum())
            .unwrap_or(0);
        let sapling_val: u64 = self
            .ledger
            .unspent
            .sapling
            .get(&account)
            .map(|m| m.values().map(|n| n.note.value().inner()).sum())
            .unwrap_or(0);
        zcash_protocol::value::Zatoshis::from_u64(orchard_val + sapling_val).unwrap()
    }
}

pub type SpendableNote = crate::wallet::transaction::ReceivedOrchardNote;