use crate::wallet::Wallet;
use crate::treasury::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

/// A request to assemble a Registry funding transaction.
#[derive(Debug, Clone)]
pub struct RegistryFundingRequest {
    pub selected_notes: Vec<[u8; 32]>,
    pub funding_amount: u64,
}

/// Evaluates the Registry funding policy.
///
/// If the Registry balance is below `floor`, this returns a `RegistryFundingRequest`
/// to top it up by `top_up_amount`.
pub fn registry_funding_policy(
    wallet: &Wallet,
    floor: u64,
    top_up_amount: u64,
) -> Option<RegistryFundingRequest> {
    let registry_balance = wallet.balance(REGISTRY_ACCOUNT);
    if registry_balance < floor {
        let exclude = std::collections::HashSet::new();
        if let Some((selected, _)) =
            crate::wallet::selection::select_funds(wallet, TREASURY_ACCOUNT, top_up_amount, &exclude)
        {
            return Some(RegistryFundingRequest {
                selected_notes: selected.into_iter().map(|n| n.note.rho().to_bytes()).collect(),
                funding_amount: top_up_amount,
            });
        }
    }
    None
}
