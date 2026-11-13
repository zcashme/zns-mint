//! The anchor transaction: the new mint's 40 claim anchors, and [`LANES`]
//! Treasury fee notes, so each block has that many mined notes to pay
//! claims with. Its height is the new birthday, H.

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::{FeeError, FeeRule};
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;
use zns_mint::mint::registry::ANCHOR_POOL_SIZE;
use zns_mint::mint::TREASURY_ACCOUNT;
use zns_mint::wallet::Wallet;
use zns_mint::{RegistryKeys, TreasuryKeys};

/// Claims per block: 28, for Zcash's launch on 28 October 2016. At most
/// the 40 anchors. `assemble::prepare` pays each claim from the largest
/// mined Treasury note, and each claim's change is mined by the next
/// round, so the fee notes keep at least this many notes to pay from.
pub const LANES: usize = 28;

/// Outputs: the anchors, the fee notes, and the Treasury's change.
const OUTPUTS: usize = ANCHOR_POOL_SIZE + LANES + 1;

/// ZIP-317 for an Ironwood-only transaction of `actions` logical actions.
pub fn fee<P: Parameters>(
    network: &P,
    fee_rule: &FeeRule,
    target_height: BlockHeight,
    actions: usize,
) -> Zatoshis {
    fee_rule
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            actions,
        )
        .expect("FATAL: ZIP-317 fee calculation failed")
}

/// Builds and signs the anchor transaction from the largest Treasury
/// Ironwood notes. `fee_note` is each fee note's value.
#[allow(clippy::too_many_arguments)]
pub fn build<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    fee_rule: &FeeRule,
    fee_note: Zatoshis,
    tip: BlockHeight,
) -> (Transaction, Zatoshis) {
    let target_height = tip + 1;
    let fee_notes_total = (0..LANES)
        .try_fold(Zatoshis::ZERO, |sum, _| sum + fee_note)
        .expect("fee notes fit the monetary range");

    let mut candidates = wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
    candidates.sort_by_key(|n| std::cmp::Reverse(n.note().value().inner()));

    let mut spends = Vec::new();
    let mut funding = Zatoshis::ZERO;
    let fee = loop {
        let f = fee(network, fee_rule, target_height, spends.len().max(OUTPUTS));
        if funding >= (fee_notes_total + f).expect("fee fits") {
            break f;
        }
        let candidate = candidates
            .get(spends.len())
            .expect("FATAL: Treasury Ironwood notes cannot fund the anchor transaction");
        funding = (funding
            + Zatoshis::from_u64(candidate.note().value().inner()).expect("note value"))
        .expect("Treasury balance fits the monetary range");
        let path = wallet
            .ironwood_witness(candidate.note_commitment_tree_position(), tip)
            .expect("FATAL: Ironwood tree error")
            .expect("FATAL: Treasury note has no witness at the tip");
        spends.push((*candidate.note(), orchard::tree::MerklePath::from(path)));
    };
    let change = ((funding - fee_notes_total).expect("covered") - fee).expect("covered");

    let anchor = wallet
        .ironwood_anchor(tip)
        .expect("FATAL: Ironwood tree error")
        .expect("FATAL: no Ironwood anchor at the tip");
    let registry_fvk = registry_keys.orchard_fvk();
    let treasury_fvk = treasury_keys.orchard_fvk();
    let mut builder = Builder::new(
        network.clone(),
        target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    for (note, path) in spends {
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), note, path)
            .expect("FATAL: anchor transaction spend");
    }
    let registry_ovk = Some(registry_fvk.to_ovk(orchard::keys::Scope::External));
    let registry_address = registry_fvk.address_at(0u32, orchard::keys::Scope::External);
    let treasury_ovk = Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal));
    let treasury_address = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);
    for _ in 0..ANCHOR_POOL_SIZE {
        builder
            .add_ironwood_output::<FeeError>(
                registry_ovk.clone(),
                registry_address,
                Zatoshis::ZERO,
                zcash_protocol::memo::MemoBytes::empty(),
            )
            .expect("FATAL: anchor output");
    }
    for _ in 0..LANES {
        builder
            .add_ironwood_output::<FeeError>(
                treasury_ovk.clone(),
                treasury_address,
                fee_note,
                zcash_protocol::memo::MemoBytes::empty(),
            )
            .expect("FATAL: fee note output");
    }
    if change > Zatoshis::ZERO {
        builder
            .add_ironwood_output::<FeeError>(
                treasury_ovk,
                treasury_address,
                change,
                zcash_protocol::memo::MemoBytes::empty(),
            )
            .expect("FATAL: change output");
    }
    let built = builder
        .build(
            &Default::default(),
            &[],
            &[treasury_keys.orchard_ask()],
            rand::rand_core::UnwrapErr(rand::rngs::SysRng),
            spend_prover,
            output_prover,
            fee_rule,
        )
        .expect("FATAL: anchor transaction build failed");
    (built.transaction().clone(), fee)
}
