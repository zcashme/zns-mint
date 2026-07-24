//! Registry fee-note replenishment transaction assembly.
//!
//! When the Registry's Ironwood fee-note pool drops below
//! `MIN_REGISTRY_FEE_NOTES`, the Treasury refills it by spending Treasury
//! Orchard notes and creating Ironwood outputs to the Registry's address.
//!
//! This is a mixed V6 transaction:
//! - **Orchard bundle** (Treasury authority): spends Treasury Orchard notes
//!   for the funding amount + fee, creates Orchard change back to Treasury.
//! - **Ironwood bundle** (output-only, no spend authority): creates
//!   `output_count` Ironwood notes of `output_value` each to the Registry's
//!   internal address.
//!
//! Value flows from the Orchard pool to the Ironwood pool. The Treasury pays
//! the transaction fee. The Registry receives spendable Ironwood fee notes.

use orchard::builder::BundleType;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::key::TreasuryKeys;
use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::registry::liquidity::RegistryFundingPlan;
use crate::wallet::{NoteLocator, Wallet};

/// The result of building a replenishment transaction.
pub struct ReplenishAssembly {
    pub txid: zcash_primitives::transaction::TxId,
    pub hex: String,
    pub reserved_notes: Vec<NoteLocator>,
}

/// Builds, proves, signs, and serializes a Treasury→Registry replenishment
/// transaction.
///
/// # Value flow
///
/// ```text
/// Orchard value balance  = treasury_spend - treasury_change
/// Ironwood value balance = 0 - (output_count * output_value)
/// Total fee              = orchard_fee
/// ```
///
/// The Treasury pays the network fee. The funding amount
/// (`output_count * output_value`) is transferred cross-pool from Orchard to
/// Ironwood.
#[allow(clippy::too_many_arguments)]
pub fn assemble_replenishment(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    plan: &RegistryFundingPlan,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &std::collections::BTreeSet<orchard::note::Rho>,
) -> Result<ReplenishAssembly, &'static str> {
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};
    use zcash_protocol::consensus::MAIN_NETWORK;

    let funding_total = plan.total_amount;

    // 1. Select Treasury Orchard notes to cover funding_total + fee.
    // We use an iterative approach: estimate the fee, select notes, re-estimate.
    let treasury_fvk =
        orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());
    let change_address = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);

    // Clone note data to avoid borrow conflicts.
    // Each entry: (note, position, value)
    let mut funding_notes: Vec<(orchard::note::Note, incrementalmerkletree::Position, u64)> =
        Vec::new();
    let mut total_selected = 0u64;
    let mut reserved_notes = Vec::new();
    let mut fee;

    loop {
        let num_spends = funding_notes.len();
        // Orchard: num_spends spends + 1 change output.
        // Ironwood: 0 spends + plan.output_count outputs.
        // Actions per pool: max(spends, outputs).
        let orchard_actions = std::cmp::max(num_spends, 1); // at least 1 for change
        let ironwood_actions = plan.output_count;

        fee = FeeRule::standard()
            .fee_required(
                &MAIN_NETWORK,
                target_height,
                std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
                std::iter::empty::<usize>(),
                0,
                0,
                orchard_actions,  // orchard_action_count
                ironwood_actions, // ironwood_action_count
            )
            .map(Zatoshis::into_u64)
            .map_err(|_| "ZIP-317 fee computation overflow")?;

        let needed = funding_total + fee;
        if total_selected >= needed {
            break;
        }

        let mut excluded_with_selected = excluded.clone();
        for (note, _, _) in &funding_notes {
            excluded_with_selected.insert(note.rho());
        }

        let candidate = wallet
            .orchard_notes_for(TREASURY_ACCOUNT)
            .filter(|n| !excluded_with_selected.contains(&n.note.rho()))
            .filter(|n| n.note.value().inner() > 0)
            .min_by_key(|n| n.note.value().inner());

        let Some(note_ref) = candidate else {
            return Err("insufficient Treasury notes for replenishment");
        };

        let val = note_ref.note.value().inner();
        total_selected += val;
        funding_notes.push((note_ref.note.clone(), note_ref.position, val));
    }

    let change_value = total_selected - funding_total - fee;

    // 2. Build the Orchard bundle (Treasury spend + change).
    let orchard_anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or("no orchard anchor at accepted anchor height")?;

    let orchard_version = orchard::bundle::BundleVersion::orchard_v3();
    let orchard_flags = orchard_version.default_flags();
    let mut orchard_builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        orchard_version,
        orchard_flags,
        orchard_anchor.into(),
    )
    .map_err(|_| "failed to create orchard builder")?;

    for (note, position, _) in &funding_notes {
        let merkle_path = wallet
            .orchard_witness(*position, anchor_height)
            .ok()
            .flatten()
            .ok_or("witness for treasury funding note not found")?;

        orchard_builder
            .add_spend(treasury_fvk.clone(), note.clone(), merkle_path.into())
            .map_err(|_| "failed to add treasury spend")?;

        reserved_notes.push(NoteLocator::orchard(TREASURY_ACCOUNT, note.rho()));
    }

    if change_value > 0 {
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6;
        orchard_builder
            .add_change_output(
                treasury_fvk.clone(),
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                change_address,
                orchard::value::NoteValue::from_raw(change_value),
                change_memo,
            )
            .map_err(|_| "failed to add orchard change output")?;
    }

    let (orchard_bundle, _) = orchard_builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build orchard bundle")?
        .ok_or("orchard builder produced no bundle")?;

    // 3. Build the Ironwood bundle (output-only: fee notes to Registry).
    let ironwood_anchor = wallet
        .latest_ironwood_anchor()
        .ok()
        .flatten()
        .ok_or("no ironwood anchor available")?;

    let registry_fvk = {
        // The Registry FVK is needed to derive the Registry's address.
        // We derive it from the Treasury's seed — but we don't have the seed
        // here. Instead, the caller should pass the Registry's FVK or address.
        //
        // Actually, the Wallet has the Registry's UFVK. We can get it from there.
        let registry_ufvk = wallet
            .ufvk_for(REGISTRY_ACCOUNT)
            .ok_or("Registry UFVK not found in wallet")?;
        registry_ufvk
            .orchard()
            .ok_or("Registry UFVK has no Orchard component")?
            .clone()
    };
    let registry_address = registry_fvk.address_at(0u32, orchard::keys::Scope::External);

    let ironwood_version = orchard::bundle::BundleVersion::ironwood_v3();
    let ironwood_flags = ironwood_version.default_flags();
    let mut ironwood_builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        ironwood_version,
        ironwood_flags,
        ironwood_anchor.into(),
    )
    .map_err(|_| "failed to create ironwood builder")?;

    for _ in 0..plan.output_count {
        let mut fee_memo = [0u8; 512];
        fee_memo[0] = 0xF6; // ZIP-302 empty memo
        ironwood_builder
            .add_output(
                Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
                registry_address,
                orchard::value::NoteValue::from_raw(plan.output_value),
                fee_memo,
            )
            .map_err(|_| "failed to add ironwood funding output")?;
    }

    let (ironwood_bundle, _) = ironwood_builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build ironwood bundle")?
        .ok_or("ironwood builder produced no bundle")?;

    // 4. Prove, sign, and serialize both bundles in one V6 transaction.
    // The Orchard bundle is signed by the Treasury; the Ironwood bundle is
    // output-only (no real spend key needed).
    use crate::registry::signing;
    let (txid, hex) = signing::assemble_v6_transaction(
        Some(orchard_bundle),
        Some(ironwood_bundle),
        Some(treasury_keys),
        None, // no Registry signer needed for output-only Ironwood
        None,
        target_height,
    )?;

    Ok(ReplenishAssembly {
        txid,
        hex,
        reserved_notes,
    })
}