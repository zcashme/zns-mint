//! Treasury auto-sweep transaction assembly.
//!
//! When the Treasury balance exceeds `SWEEP_THRESHOLD`, excess funds are swept
//! to a cold storage transparent address. The sweep is a V6 transaction with:
//!
//! - **Orchard bundle** (Treasury authority): spends Treasury Orchard notes,
//!   creates Orchard change back to Treasury.
//! - **Transparent output**: sends the sweep amount to the cold storage address.
//!
//! The Treasury pays the transaction fee from its Orchard balance. The sweep
//! amount is `treasury_balance - SWEEP_RESERVE`.

use orchard::builder::BundleType;
use transparent::address::TransparentAddress;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::key::TreasuryKeys;
use crate::mint::TREASURY_ACCOUNT;
use crate::registry::transaction::TransparentOutput;
use crate::wallet::{NoteLocator, Wallet};

/// Minimum Treasury balance (in zatoshis) to trigger a sweep.
/// 10,000,000 zatoshis = 0.1 ZEC.
const SWEEP_THRESHOLD: u64 = 10_000_000;

/// Amount to retain in the Treasury after a sweep (in zatoshis).
/// 1,000,000 zatoshis = 0.01 ZEC.
const SWEEP_RESERVE: u64 = 1_000_000;

/// Cold storage transparent address for auto-sweep.
///
/// TODO: set to the real deployment cold storage address before production.
/// This placeholder is the P2PKH address for hash `[0x42; 20]`, which is
/// deliberately not all-zeros (to avoid accidental sends to the null address).
const SWEEP_ADDRESS: TransparentAddress = TransparentAddress::PublicKeyHash([0x42; 20]);

/// The result of building a sweep transaction.
pub struct SweepAssembly {
    pub txid: zcash_primitives::transaction::TxId,
    pub hex: String,
    pub reserved_notes: Vec<NoteLocator>,
    pub sweep_amount: u64,
}

/// Returns the sweep amount if the Treasury balance exceeds the threshold.
///
/// Returns `None` if the balance is below the threshold or the sweep amount
/// would be zero.
pub fn sweep_policy(treasury_balance: u64) -> Option<u64> {
    if treasury_balance <= SWEEP_THRESHOLD {
        return None;
    }
    let sweep_amount = treasury_balance - SWEEP_RESERVE;
    if sweep_amount == 0 {
        return None;
    }
    Some(sweep_amount)
}

/// Builds, proves, signs, and serializes a Treasury auto-sweep transaction.
///
/// # Value flow
///
/// ```text
/// Orchard value balance  = treasury_spend - treasury_change
/// Transparent balance    = 0 - sweep_amount
/// Total fee              = orchard_fee
/// ```
///
/// The Treasury pays the network fee. The sweep amount goes to the cold
/// storage transparent address.
#[allow(clippy::too_many_arguments)]
pub fn assemble_sweep(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    sweep_amount: u64,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &std::collections::BTreeSet<orchard::note::Rho>,
) -> Result<SweepAssembly, &'static str> {
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};
    use zcash_protocol::consensus::MAIN_NETWORK;

    let treasury_fvk =
        orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());
    let change_address = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);

    // 1. Select Treasury Orchard notes to cover sweep_amount + fee.
    let mut funding_notes: Vec<(orchard::note::Note, incrementalmerkletree::Position, u64)> =
        Vec::new();
    let mut total_selected = 0u64;
    let mut reserved_notes = Vec::new();
    let mut fee;

    loop {
        let num_spends = funding_notes.len();
        // Orchard: num_spends spends + 1 change output.
        // Transparent: 1 output.
        let orchard_actions = std::cmp::max(num_spends, 1);

        fee = FeeRule::standard()
            .fee_required(
                &MAIN_NETWORK,
                target_height,
                std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
                std::iter::once(34), // 1 P2PKH output (34 bytes)
                0,
                0,
                orchard_actions, // orchard_action_count
                0,               // ironwood_action_count
            )
            .map(Zatoshis::into_u64)
            .map_err(|_| "ZIP-317 fee computation overflow")?;

        let needed = sweep_amount + fee;
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
            return Err("insufficient Treasury notes for sweep");
        };

        let val = note_ref.note.value().inner();
        total_selected += val;
        funding_notes.push((note_ref.note.clone(), note_ref.position, val));
    }

    let change_value = total_selected - sweep_amount - fee;

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
            .ok_or("witness for treasury sweep note not found")?;

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

    // 3. Transparent output to cold storage.
    let transparent_outputs = [TransparentOutput {
        address: SWEEP_ADDRESS,
        value: Zatoshis::from_u64(sweep_amount).map_err(|_| "sweep amount overflow")?,
    }];

    // 4. Prove, sign, and serialize.
    use crate::registry::signing;
    let (txid, hex) = signing::assemble_v6_transaction(
        Some(orchard_bundle),
        None,
        Some(treasury_keys),
        None,
        Some(&transparent_outputs),
        target_height,
    )?;

    Ok(SweepAssembly {
        txid,
        hex,
        reserved_notes,
        sweep_amount,
    })
}