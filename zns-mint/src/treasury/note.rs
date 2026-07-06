use crate::wallet::Wallet;
use crate::treasury::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zcash_protocol::value::Zatoshis;

/// A request to assemble a Registry funding transaction.
#[derive(Debug, Clone)]
pub struct RegistryFundingRequest {
    pub selected_notes: Vec<orchard::note::Rho>,
    pub funding_amount: Zatoshis,
}

/// Evaluates the Registry funding policy.
///
/// If the Registry balance is below `floor`, this returns a `RegistryFundingRequest`
/// to top it up by `top_up_amount`.
pub fn registry_funding_policy(
    wallet: &Wallet,
    floor: Zatoshis,
    top_up_amount: Zatoshis,
) -> Option<RegistryFundingRequest> {
    let registry_balance = wallet.balance(REGISTRY_ACCOUNT);
    if registry_balance.into_u64() < floor.into_u64() {
        let exclude = std::collections::BTreeSet::new();
        if let Some((selected, _)) =
            crate::wallet::selection::select_funds(wallet, TREASURY_ACCOUNT, top_up_amount, &exclude)
        {
            return Some(RegistryFundingRequest {
                selected_notes: selected.into_iter().map(|n| n.note.rho()).collect(),
                funding_amount: top_up_amount,
            });
        }
    }
    None
}
