use crate::wallet::Wallet;
use crate::treasury::TREASURY_ACCOUNT;

/// A request to assemble a transparent auto-sweep transaction.
#[derive(Debug, Clone)]
pub struct SweepRequest {
    pub selected_notes: Vec<[u8; 32]>,
    pub sweep_amount: u64,
}

/// Evaluates the auto-sweep policy for the Treasury.
///
/// If the Treasury balance exceeds `threshold`, this returns a `SweepRequest`
/// for the excess funds.
pub fn sweep_policy(wallet: &Wallet, threshold: u64) -> Option<SweepRequest> {
    let balance = wallet.balance(TREASURY_ACCOUNT);
    if balance > threshold {
        let sweep_amount = balance - threshold;
        let exclude = std::collections::HashSet::new();
        if let Some((selected, _)) = crate::wallet::selection::select_funds(wallet, TREASURY_ACCOUNT, sweep_amount, &exclude) {
            return Some(SweepRequest {
                selected_notes: selected.into_iter().map(|n| n.note.rho().to_bytes()).collect(),
                sweep_amount,
            });
        }
    }
    None
}
