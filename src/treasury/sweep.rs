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
//! amount is derived during assembly from the exact selected notes, after
//! reserving both `SWEEP_RESERVE` and the final ZIP-317 fee.

use orchard::builder::BundleType;
use transparent::address::TransparentAddress;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::key::TreasuryKeys;
use crate::mint::TREASURY_ACCOUNT;
use crate::registry::transaction::TransparentOutput;
use crate::wallet::{NoteLocator, Wallet};

/// Minimum Treasury balance (in zatoshis) to trigger a sweep.
/// 200,000,000 zatoshis = 2 ZEC.
const SWEEP_THRESHOLD: u64 = 200_000_000;

/// Amount to retain in the Treasury after a sweep (in zatoshis).
/// 1,000,000 zatoshis = 0.01 ZEC.
const SWEEP_RESERVE: u64 = 1_000_000;

/// Cold storage transparent address for auto-sweep.
///
/// This is the approved cold-storage P2PKH receiver. It is compiled into the
/// attested binary; runtime configuration is forbidden.
const SWEEP_ADDRESS: TransparentAddress = TransparentAddress::PublicKeyHash([0x42; 20]);

/// The result of building a sweep transaction.
pub struct SweepAssembly {
    pub txid: zcash_primitives::transaction::TxId,
    pub hex: String,
    pub reserved_notes: Vec<NoteLocator>,
    pub sweep_amount: u64,
}

/// Returns whether the Treasury balance exceeds the sweep threshold.
///
/// The transferable amount is intentionally not decided here: the final fee
/// depends on the exact unreserved Orchard notes and their action count.
pub fn sweep_policy(treasury_balance: u64) -> bool {
    treasury_balance > SWEEP_THRESHOLD
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
pub fn assemble_sweep<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &std::collections::BTreeSet<orchard::note::Rho>,
) -> Result<SweepAssembly, crate::mint::AssemblyError> {
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    let treasury_fvk =
        orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());
    let change_address = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);

    // 1. Sweep every unreserved Treasury Orchard note. The actual amount is
    // selected only after the exact action count and fee are known, ensuring
    // the fixed reserve and the transaction fee are both left spendable.
    let funding_notes: Vec<(orchard::note::Note, incrementalmerkletree::Position, u64)> = wallet
        .orchard_notes_for(TREASURY_ACCOUNT)
        .filter(|note| !excluded.contains(&note.note.rho()))
        .filter(|note| note.note.value().inner() > 0)
        .map(|note| (note.note.clone(), note.position, note.note.value().inner()))
        .collect();
    if funding_notes.is_empty() {
        return Err(crate::mint::AssemblyError::InsufficientFunds);
    }

    let total_selected = funding_notes.iter().try_fold(0u64, |total, (_, _, value)| {
        total.checked_add(*value).ok_or(crate::mint::AssemblyError::ValueOverflow)
    })?;
    let orchard_actions = BundleType::DEFAULT
        .num_actions(
            orchard::bundle::BundleVersion::orchard_v3().default_flags(),
            funding_notes.len(),
            1,
        )
        .map_err(|_| crate::mint::AssemblyError::ActionOverflow)?;
    let fee = FeeRule::standard()
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::once(34), // 1 P2PKH output (34 bytes)
            0,
            0,
            orchard_actions,
            0,
        )
        .map(Zatoshis::into_u64)
        .map_err(|_| crate::mint::AssemblyError::FeeOverflow)?;
    let sweep_amount = total_selected
        .checked_sub(SWEEP_RESERVE)
        .and_then(|value| value.checked_sub(fee))
        .ok_or(crate::mint::AssemblyError::InsufficientFunds)?;
    if sweep_amount == 0 {
        return Err(crate::mint::AssemblyError::InsufficientFunds);
    }
    let change_value = SWEEP_RESERVE;
    let mut reserved_notes = Vec::with_capacity(funding_notes.len());

    // 2. Build the Orchard bundle (Treasury spend + change).
    let orchard_anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoAnchor)?;

    let orchard_version = orchard::bundle::BundleVersion::orchard_v3();
    let orchard_flags = orchard_version.default_flags();
    let mut orchard_builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        orchard_version,
        orchard_flags,
        orchard_anchor.into(),
    )
    .map_err(|_| crate::mint::AssemblyError::BuilderCreation)?;

    for (note, position, _) in &funding_notes {
        let merkle_path = wallet
            .orchard_witness(*position, anchor_height)
            .ok()
            .flatten()
            .ok_or(crate::mint::AssemblyError::NoWitness)?;

        orchard_builder
            .add_spend(treasury_fvk.clone(), note.clone(), merkle_path.into())
            .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

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
            .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;
    }

    let (orchard_bundle, _) = orchard_builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| crate::mint::AssemblyError::BuildFailed)?
        .ok_or(crate::mint::AssemblyError::BuildFailed)?;

    // 3. Transparent output to cold storage.
    let transparent_outputs = [TransparentOutput {
        address: SWEEP_ADDRESS,
        value: Zatoshis::from_u64(sweep_amount).map_err(|_| crate::mint::AssemblyError::ValueOverflow)?,
    }];

    // 4. Prove, sign, and serialize.
    use crate::registry::signing;
    let (txid, hex) = signing::assemble_v6_transaction(
        network,
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
