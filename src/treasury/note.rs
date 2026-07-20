use crate::registry::RegistryFeeLiquidity;
use crate::treasury::TREASURY_ACCOUNT;
use crate::wallet::Wallet;
use zcash_protocol::value::Zatoshis;

/// A request to assemble a Registry funding transaction.
#[derive(Debug, Clone)]
pub struct RegistryFundingRequest {
    /// Treasury Orchard notes selected to fund the transaction.
    pub selected_notes: Vec<orchard::note::Rho>,
    /// Number of Registry fee-note outputs the transaction should create.
    pub registry_output_count: usize,
    /// Value of each Registry fee-note output.
    pub registry_output_value: Zatoshis,
    /// Total value sent to the Registry across all fee-note outputs.
    pub registry_total_amount: Zatoshis,
}

/// Evaluates the Registry funding policy.
///
/// If the Registry fee-note pool is below its target, this returns a
/// [`RegistryFundingRequest`] that asks transaction assembly to create many
/// small Registry fee-note outputs, not one large top-up note.
pub fn registry_funding_policy(wallet: &Wallet) -> Option<RegistryFundingRequest> {
    let plan = RegistryFeeLiquidity::from_wallet(wallet).treasury_funding_plan()?;

    let funding_amount = Zatoshis::from_u64(plan.total_amount).ok()?;
    let exclude = std::collections::BTreeSet::new();
    let (selected, _) =
        crate::wallet::selection::select_funds(wallet, TREASURY_ACCOUNT, funding_amount, &exclude)?;

    Some(RegistryFundingRequest {
        selected_notes: selected.into_iter().map(|n| n.note.rho()).collect(),
        registry_output_count: plan.output_count,
        registry_output_value: Zatoshis::from_u64(plan.output_value).ok()?,
        registry_total_amount: funding_amount,
    })
}
