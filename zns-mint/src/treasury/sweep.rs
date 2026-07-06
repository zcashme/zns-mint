use crate::wallet::Wallet;
use crate::treasury::TREASURY_ACCOUNT;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

/// A request to assemble a transparent auto-sweep transaction.
#[derive(Debug, Clone)]
pub struct SweepRequest {
    pub selected_notes: Vec<orchard::note::Rho>,
    pub sweep_amount: Zatoshis,
}

// 1 ZEC = 100,000,000 zatoshis
const ZATOSHIS_PER_ZEC: u64 = 100_000_000;

/// The balance above which a sweep is considered.
pub const SWEEP_THRESHOLD: u64 = 10 * ZATOSHIS_PER_ZEC;

/// The amount to leave behind in the Treasury for operations.
pub const SWEEP_RESERVE: u64 = 1 * ZATOSHIS_PER_ZEC;

/// Minimum blocks between sweeps (1152 blocks = ~1 day at 75s/block).
pub const SWEEP_COOLDOWN_BLOCKS: u32 = 1152;

/// Evaluates the auto-sweep policy for the Treasury.
pub fn sweep_policy(
    wallet: &Wallet,
    current_height: BlockHeight,
    last_sweep_height: Option<BlockHeight>,
) -> Option<SweepRequest> {
    // 1. Rate Limit (Time/Block lock)
    if let Some(last_height) = last_sweep_height {
        let blocks_elapsed = u32::from(current_height).saturating_sub(u32::from(last_height));
        if blocks_elapsed < SWEEP_COOLDOWN_BLOCKS {
            return None; // Cooldown active, don't sweep yet
        }
    }

    let balance = wallet.balance(TREASURY_ACCOUNT);
    if balance.into_u64() > SWEEP_THRESHOLD {
        let sweep_amount_u64 = balance.into_u64().saturating_sub(SWEEP_RESERVE);
        if sweep_amount_u64 == 0 {
            return None;
        }
        let sweep_amount = Zatoshis::from_u64(sweep_amount_u64).unwrap();

        let exclude = std::collections::BTreeSet::new();
        if let Some((selected, _)) = crate::wallet::selection::select_funds(wallet, TREASURY_ACCOUNT, sweep_amount, &exclude) {
            
            // 2. Exact ZIP-317 Fee Calculation
            // max(2, inputs + outputs) * 5000. Sweep has 2 outputs: cold address + change.
            let inputs_count = selected.len() as u64;
            let exact_fee = std::cmp::max(2, inputs_count + 2) * 5_000;

            // 3. Fee Ratio Guard (Fee must be less than 0.01% of sweep_amount)
            // mathematically: exact_fee < sweep_amount / 10,000
            if exact_fee > (sweep_amount.into_u64() / 10_000) {
                // The fee ratio is too high because there are too many dust notes.
                // Abort the sweep and let the Treasury accumulate more funds.
                return None;
            }

            return Some(SweepRequest {
                selected_notes: selected.into_iter().map(|n| n.note.rho()).collect(),
                sweep_amount,
            });
        }
    }
    None
}
