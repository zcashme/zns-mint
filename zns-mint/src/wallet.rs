//! ZNS mint wallet.
//!
pub mod selection;
pub mod trees;
pub mod transaction;
pub mod balance;

use std::collections::BTreeMap;

use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::value::Zatoshis;
use zip32::AccountId;

use balance::WalletBalance;
use trees::ShardTrees;

/// The in-memory ZNS wallet engine: a notes table and a tree.
pub struct Wallet {
    // Identity / scanning inputs (read-only after boot).
    ufvk_map: BTreeMap<AccountId, UnifiedFullViewingKey>,

    // Tracks unspent notes and spent nullifiers. Private so all mutation
    // flows through `Wallet` methods and can be kept in sync with `trees`.
    balance: WalletBalance,

    // The running commitment trees for Orchard and Sapling. Private for the
    // same reason as `balance`: must stay in sync with the note set.
    trees: ShardTrees,
}

impl Wallet {
    /// Create a new, empty wallet.
    pub fn new(ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>) -> Self {
        Self {
            ufvk_map: ufvks.into_iter().collect(),
            balance: WalletBalance::new(),
            trees: ShardTrees::new(),
        }
    }

    /// Read-only access to an account's unified full viewing key.
    /// Used by the scanner to derive IVKs for trial decryption.
    pub fn ufvk_for(&self, account: AccountId) -> Option<&UnifiedFullViewingKey> {
        self.ufvk_map.get(&account)
    }

    pub fn orchard_notes_for(&self, account: AccountId) -> impl Iterator<Item = &crate::wallet::transaction::ReceivedOrchardNote> {
        self.balance
            .unspent
            .orchard
            .get(&account)
            .into_iter()
            .flat_map(|m| m.values())
    }

    pub fn sapling_notes_for(&self, account: AccountId) -> impl Iterator<Item = &crate::wallet::transaction::ReceivedSaplingNote> {
        self.balance
            .unspent
            .sapling
            .get(&account)
            .into_iter()
            .flat_map(|m| m.values())
    }

    pub fn balance(&self, account: AccountId) -> Zatoshis {
        let orchard_val: u64 = self
            .balance
            .unspent
            .orchard
            .get(&account)
            .map(|m| m.values().map(|n| n.note.value().inner()).sum())
            .unwrap_or(0);
        let sapling_val: u64 = self
            .balance
            .unspent
            .sapling
            .get(&account)
            .map(|m| m.values().map(|n| n.note.value().inner()).sum())
            .unwrap_or(0);
        Zatoshis::from_u64(orchard_val + sapling_val).unwrap()
    }

    pub fn orchard_anchor(&mut self, height: zcash_protocol::consensus::BlockHeight) -> Result<Option<orchard::tree::MerkleHashOrchard>, trees::TreeError> {
        self.trees.orchard_anchor(height)
    }

    pub fn orchard_witness(
        &mut self,
        position: incrementalmerkletree::Position,
        height: zcash_protocol::consensus::BlockHeight,
    ) -> Result<Option<incrementalmerkletree::MerklePath<orchard::tree::MerkleHashOrchard, 32>>, trees::TreeError> {
        self.trees.orchard_witness(position, height)
    }
}
