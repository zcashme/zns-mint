//! Treasury wallet view and Treasury policy for the mint.

pub use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

pub mod claim;
pub mod memo;
pub mod replenish;
pub mod relay;
pub mod sweep;

use crate::wallet::transaction::ReceivedOrchardNote;
use crate::wallet::Wallet;
use crate::{mint::Name, registry::Registry};

/// Owned Treasury policy state.
///
/// The Treasury does not own notes; `Wallet` owns all notes and commitment
/// trees. Treasury methods take `&Wallet` when evaluating policy.
#[derive(Default)]
pub struct Treasury;

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

    pub fn match_payment<'w>(
        &self,
        wallet: &'w Wallet,
        registry: &Registry,
        request: &crate::treasury::memo::RequestMemo,
        price: u64,
    ) -> Option<&'w ReceivedOrchardNote> {
        let price_zat = zcash_protocol::value::Zatoshis::from_u64(price).unwrap();
        if !matches!(request, crate::treasury::memo::RequestMemo::Claim { .. }) {
            return None;
        }
        let name = Name::parse(request.name())?;
        let tip_height = registry.tip(&name).map(|tip| tip.confirmed_height);

        wallet
            .orchard_notes_for(TREASURY_ACCOUNT)
            .find(|note| {
                note.note.value().inner() >= price_zat.into_u64()
                    && tip_height.map_or(true, |height| note.confirmed_height > height)
                    && crate::treasury::memo::RequestMemo::parse(note.memo.as_array())
                        .is_ok_and(|parsed| &parsed == request)
            })
    }
}
