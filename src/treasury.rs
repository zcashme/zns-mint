//! Treasury wallet view and Treasury policy for the mint.

pub use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

pub mod fee;
pub mod memo;
pub mod note;
pub mod sweep;

use crate::wallet::transaction::ReceivedOrchardNote;
use crate::wallet::Wallet;
use zcash_protocol::consensus::BlockHeight;

pub use note::RegistryFundingRequest;

#[derive(Default)]
struct TreasuryState {
    last_sweep_height: Option<BlockHeight>,
}

/// Owned Treasury policy state.
///
/// The Treasury does not own notes; `Wallet` owns all notes and commitment
/// trees. Treasury methods take `&Wallet` when evaluating policy.
#[derive(Default)]
pub struct Treasury(TreasuryState);

impl Treasury {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn unspent_notes<'w>(
        &self,
        wallet: &'w Wallet,
    ) -> impl Iterator<Item = &'w ReceivedOrchardNote> {
        wallet.orchard_notes_for(TREASURY_ACCOUNT)
    }

    pub fn balance(&self, wallet: &Wallet) -> u64 {
        wallet.balance(TREASURY_ACCOUNT).into_u64()
    }

    pub fn select_funds<'w>(
        &self,
        wallet: &'w Wallet,
        target: u64,
    ) -> Option<Vec<&'w ReceivedOrchardNote>> {
        let exclude = std::collections::BTreeSet::new();
        let target_zat = zcash_protocol::value::Zatoshis::from_u64(target).unwrap();
        crate::wallet::selection::select_funds(wallet, TREASURY_ACCOUNT, target_zat, &exclude)
            .map(|(notes, _)| notes)
    }

    pub fn requests_in_block(&self, _height: BlockHeight) -> &[crate::treasury::memo::RequestMemo] {
        // T3 implementation is not yet hooked to the scanner's output
        &[]
    }

    pub fn auto_sweep(
        &self,
        wallet: &Wallet,
        current_height: BlockHeight,
    ) -> Option<crate::treasury::sweep::SweepRequest> {
        crate::treasury::sweep::sweep_policy(wallet, current_height, self.0.last_sweep_height)
    }

    pub fn registry_funding(&self, wallet: &Wallet) -> Option<RegistryFundingRequest> {
        crate::treasury::note::registry_funding_policy(wallet)
    }

    pub fn match_payment<'w>(
        &self,
        wallet: &'w Wallet,
        request: &crate::treasury::memo::RequestMemo,
        price: u64,
    ) -> Option<&'w ReceivedOrchardNote> {
        let price_zat = zcash_protocol::value::Zatoshis::from_u64(price).unwrap();
        crate::treasury::fee::match_fee(wallet, request, price_zat)
    }
}
