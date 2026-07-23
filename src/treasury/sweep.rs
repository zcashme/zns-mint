use crate::treasury::TREASURY_ACCOUNT;
use crate::wallet::Wallet;
use transparent::address::TransparentAddress;
use zcash_primitives::transaction::fees::{
    zip317::{FeeRule, P2PKH_STANDARD_OUTPUT_SIZE},
    FeeRule as _, transparent::InputSize,
};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

// 1 ZEC = 100,000,000 zatoshis
const ZATOSHIS_PER_ZEC: u64 = 100_000_000;

/// A request to assemble a transparent auto-sweep transaction.
#[derive(Debug, Clone)]
pub enum SweepRequest {
    Sapling {
        notes: Vec<incrementalmerkletree::Position>,
        amount: Zatoshis,
    },
    Orchard {
        notes: Vec<orchard::note::Rho>,
        amount: Zatoshis,
    },
}

/// The Treasury cold-storage transparent address for auto-sweeps.
///
/// Address: `t1ZqkmvGxQmANohacyq2YnyVL41jrzovkBQ`
///
/// P2PKH script: `OP_DUP OP_HASH160 <key_id> OP_EQUALVERIFY OP_CHECKSIG`
/// where `key_id = af288016bfca2b4d3c97f7919c943b6e5d0a6623`.
pub const COLD_ADDRESS: TransparentAddress = TransparentAddress::PublicKeyHash([
    0xaf, 0x28, 0x80, 0x16, 0xbf, 0xca, 0x2b, 0x4d, 0x3c, 0x97, 0xf7, 0x91, 0x9c, 0x94, 0x3b, 0x6e,
    0x5d, 0x0a, 0x66, 0x23,
]);

/// The balance above which a sweep is considered.
pub const SWEEP_THRESHOLD: u64 = 10 * ZATOSHIS_PER_ZEC;

/// The amount to leave behind in the Treasury for operations.
pub const SWEEP_RESERVE: u64 = ZATOSHIS_PER_ZEC;

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

    let exclude_orchard: std::collections::BTreeSet<orchard::note::Rho> = std::collections::BTreeSet::new();

    // 2. Sapling Policy
    let sapling_balance: u64 = wallet
        .sapling_notes_for(TREASURY_ACCOUNT)
        .map(|n| n.note.value().inner())
        .sum();
    if sapling_balance > SWEEP_THRESHOLD {
        // Reserve enough to cover the fee; exact fee depends on selection, but a
        // fixed reserve guarantees the selected notes can pay it.
        let sweep_amount_u64 = sapling_balance.saturating_sub(SWEEP_RESERVE);
        if sweep_amount_u64 == 0 {
            return None;
        }
        let sweep_amount = Zatoshis::from_u64(sweep_amount_u64).unwrap();
        let exclude_sapling: std::collections::BTreeSet<incrementalmerkletree::Position> = std::collections::BTreeSet::new();
        if let Some((selected, _)) = crate::wallet::selection::select_sapling_funds(
            wallet,
            TREASURY_ACCOUNT,
            sweep_amount,
            &exclude_sapling,
        ) {
            let _fee = FeeRule::standard()
                .fee_required(
                    &zcash_protocol::consensus::MAIN_NETWORK,
                    current_height,
                    std::iter::empty::<InputSize>(),
                    [P2PKH_STANDARD_OUTPUT_SIZE].iter().copied(),
                    selected.len(),
                    // Sapling: the builder pads any transactional bundle with at least
                    // 2 outputs (MIN_SHIELDED_OUTPUTS). We send `selected.len()` inputs and
                    // 1 real change output, so the logical output count is the upstream-padded
                    // value, not the raw 1.
                    sapling::builder::BundleType::DEFAULT
                        .num_outputs(selected.len(), 1)
                        .ok()?,
                    0,
                    0,
                )
                .ok()?;

            return Some(SweepRequest::Sapling {
                notes: selected.into_iter().map(|n| n.position).collect(),
                amount: sweep_amount,
            });
        }
    }

    // 3. Orchard Policy
    let orchard_balance: u64 = wallet
        .orchard_notes_for(TREASURY_ACCOUNT)
        .map(|n| n.note.value().inner())
        .sum();
    if orchard_balance > SWEEP_THRESHOLD {
        let sweep_amount_u64 = orchard_balance.saturating_sub(SWEEP_RESERVE);
        if sweep_amount_u64 == 0 {
            return None;
        }
        let sweep_amount = Zatoshis::from_u64(sweep_amount_u64).unwrap();

        if let Some((selected, _)) =
            crate::wallet::selection::select_funds(wallet, TREASURY_ACCOUNT, sweep_amount, &exclude_orchard)
        {
            let _fee = FeeRule::standard()
                .fee_required(
                    &zcash_protocol::consensus::MAIN_NETWORK,
                    current_height,
                    std::iter::empty::<InputSize>(),
                    [P2PKH_STANDARD_OUTPUT_SIZE].iter().copied(),
                    0,
                    0,
                    0,
                    // Orchard: V3 default flags disable cross-address transfers, so each real
                    // spend and the change output occupy separate actions: N inputs + 1 change
                    // output, padded to the default minimum of 2.
                    orchard::builder::BundleType::DEFAULT
                        .num_actions(
                            orchard::bundle::BundleVersion::orchard_v3().default_flags(),
                            selected.len(),
                            1, // change output
                        )
                        .ok()?,
                )
                .ok()?;

            return Some(SweepRequest::Orchard {
                notes: selected.into_iter().map(|n| n.note.rho()).collect(),
                amount: sweep_amount,
            });
        }
    }
    None
}
