//! Treasury wallet view and Treasury policy for the mint.

pub use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

pub mod fee;
pub mod memo;
pub mod note;
pub mod sweep;

use crate::wallet::Wallet;
use crate::wallet::transaction::ReceivedOrchardNote;
use zcash_protocol::consensus::BlockHeight;

pub struct Treasury<'w> {
    wallet: &'w Wallet,
}

impl<'w> Treasury<'w> {
    pub fn from_wallet(wallet: &'w Wallet) -> Self {
        Self { wallet }
    }

    pub fn unspent_notes(&self) -> impl Iterator<Item = &'w ReceivedOrchardNote> {
        self.wallet.orchard_notes_for(TREASURY_ACCOUNT)
    }

    pub fn balance(&self) -> u64 {
        self.wallet.balance(TREASURY_ACCOUNT).into_u64()
    }

    pub fn select_funds(&self, target: u64) -> Option<Vec<&'w ReceivedOrchardNote>> {
        let exclude = std::collections::BTreeSet::new();
        let target_zat = zcash_protocol::value::Zatoshis::from_u64(target).unwrap();
        crate::wallet::selection::select_funds(self.wallet, TREASURY_ACCOUNT, target_zat, &exclude)
            .map(|(notes, _)| notes)
    }

    pub fn requests_in_block(&self, _height: BlockHeight) -> &[crate::treasury::memo::RequestMemo] {
        // T3 implementation is not yet hooked to the scanner's output
        &[]
    }

    pub fn auto_sweep(&self, current_height: BlockHeight, last_sweep_height: Option<BlockHeight>) -> Option<crate::treasury::sweep::SweepRequest> {
        crate::treasury::sweep::sweep_policy(self.wallet, current_height, last_sweep_height)
    }

    pub fn registry_funding(&self) -> Option<RegistryFundingRequest> {
        let registry_bal = self.wallet.balance(REGISTRY_ACCOUNT).into_u64();
        if registry_bal < REGISTRY_FUNDING_FLOOR {
            let target_zat = zcash_protocol::value::Zatoshis::from_u64(REGISTRY_FUNDING_TOPUP).unwrap();
            let exclude = std::collections::BTreeSet::new();
            if let Some((notes, _)) = crate::wallet::selection::select_funds(self.wallet, TREASURY_ACCOUNT, target_zat, &exclude) {
                return Some(RegistryFundingRequest {
                    selected_notes: notes.into_iter().map(|n| n.note.rho()).collect(),
                    amount: REGISTRY_FUNDING_TOPUP,
                });
            }
        }
        None
    }

    pub fn match_payment(&self, request: &crate::treasury::memo::RequestMemo, price: u64) -> Option<&'w ReceivedOrchardNote> {
        let price_zat = zcash_protocol::value::Zatoshis::from_u64(price).unwrap();
        crate::treasury::fee::match_fee(self.wallet, request, price_zat)
    }
}

pub struct RegistryFundingRequest {
    pub selected_notes: Vec<orchard::note::Rho>,
    pub amount: u64,
}

pub const REGISTRY_FUNDING_FLOOR: u64 = 5_000_000;
pub const REGISTRY_FUNDING_TOPUP: u64 = 10_000_000;
