//! Treasury wallet view and Treasury policy for the mint.

pub use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

pub mod claim;
pub mod memo;
pub mod replenish;
pub mod relay;
pub mod sweep;

use crate::wallet::transaction::ReceivedOrchardNote;
use crate::wallet::Wallet;

/// Treasury wallet view.
///
/// The Treasury does not own notes; `Wallet` owns all notes and commitment
/// trees. These methods project the Treasury account's slice of the wallet.
#[derive(Default)]
pub struct Treasury;

impl Treasury {
    pub fn unspent_notes<'w>(
        &self,
        wallet: &'w Wallet,
    ) -> impl Iterator<Item = &'w ReceivedOrchardNote> {
        wallet.orchard_notes_for(TREASURY_ACCOUNT)
    }

    pub fn balance(&self, wallet: &Wallet) -> u64 {
        wallet.balance(TREASURY_ACCOUNT).into_u64()
    }
}
