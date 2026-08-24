//! Registry fee-note replenishment — the Treasury keeps the Registry's fee
//! pool stocked.
//!
//! When the Registry's unspent fee-note count drops below
//! [`MIN_REGISTRY_FEE_NOTES`](crate::registry::liquidity::MIN_REGISTRY_FEE_NOTES),
//! the Treasury refills it to
//! [`REGISTRY_FEE_POOL_TARGET`](crate::registry::liquidity::REGISTRY_FEE_POOL_TARGET)
//! with notes of
//! [`REGISTRY_FEE_NOTE_TARGET_VALUE`](crate::registry::liquidity::REGISTRY_FEE_NOTE_TARGET_VALUE),
//! by spending Treasury Ironwood notes and creating Ironwood outputs to the
//! Registry's address.
//!
//! This is one Ironwood bundle in a V6 transaction (Ironwood permits the
//! cross-address transfer; the Treasury and Registry are distinct addresses
//! under one seed). Value stays in the Ironwood pool. The Treasury pays the
//! transaction fee from its Ironwood balance.
//!
//! One call decides and settles: [`replenish_registry_fees`] reads the fee
//! pool from the wallet, derives heights, selects funding notes, builds,
//! proves, signs, and records the transaction in the wallet — returning only
//! its [`TxId`]. Repeat safety is the wallet's, exactly as in
//! [`crate::treasury::vault`]: storing the sent transaction records every
//! consumed note as spent, blocking re-selection until it confirms or
//! expires.

use std::num::NonZeroU32;

use orchard::builder::BundleType;
use shardtree::error::ShardTreeError;
use time::OffsetDateTime;
use zcash_client_backend::data_api::wallet::input_selection::{LockFilter, LockedInputPolicy};
use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::{
    InputSource, SentTransaction, TargetValue, WalletCommitmentTrees, WalletRead, WalletWrite,
};
use zcash_client_backend::wallet::NoteId;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::{ZatBalance, Zatoshis};
use zcash_protocol::ShieldedPool;

use crate::key::TreasuryKeys;
use crate::mint::{AssemblyError, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::registry::liquidity::{RegistryFeeLiquidity, RegistryFundingPlan};
use crate::wallet::Wallet;

/// Refills the Registry's fee-note pool from Treasury value.
///
/// Returns `Ok(None)` when the pool is at or above its floor (or the wallet
/// has not yet observed a chain tip), and `Ok(Some(txid))` when a refill was
/// built, signed, and recorded in the wallet. The caller broadcasts the
/// stored transaction by its [`TxId`] (`WalletRead::get_transaction`).
pub fn replenish_registry_fees<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
) -> Result<Option<TxId>, AssemblyError> {
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    // 1. Decide: the fee pool, counted through upstream metadata.
    let Some(plan) = RegistryFeeLiquidity::from_wallet(wallet).treasury_funding_plan() else {
        return Ok(None);
    };

    // 2. Heights are wallet facts, mirroring upstream `propose_transfer`.
    let (target, anchor_height) = wallet
        .get_target_and_anchor_heights(NonZeroU32::MIN)
        .ok()
        .flatten()
        .ok_or(AssemblyError::NoAnchor)?;
    let target_height = BlockHeight::from(target);

    // 3. Select Treasury funding notes to cover the plan plus fee. The fee
    //    depends on the spend count and the spend count depends on the fee,
    //    so selection iterates: call `select_spendable_notes` for the current
    //    requirement, recompute the fee for the resulting action count, and
    //    re-select for the larger requirement until it holds — the same
    //    convergence `GreedyInputSelector` performs internally, driven here
    //    through the public trait (our impl is oldest-first, crossing note
    //    included). Bounded by the note count; a non-covering final call
    //    reports `InsufficientFunds`.
    let mut selected: Vec<NoteId> = Vec::new();
    let mut selected_notes = Vec::new();
    let mut total_selected = Zatoshis::ZERO;
    let funding_total =
        Zatoshis::from_u64(plan.total_amount).map_err(|_| AssemblyError::ValueOverflow)?;
    let fee;

    loop {
        let requirement = (funding_total + fee_estimate(
            network,
            target_height,
            plan.output_count,
            selected_notes.len(),
        )?)
        .ok_or(AssemblyError::ValueOverflow)?;

        let batch = wallet
            .select_spendable_notes(
                TREASURY_ACCOUNT,
                TargetValue::AtLeast(requirement),
                &[ShieldedPool::Ironwood],
                target,
                ConfirmationsPolicy::MIN,
                &selected,
                LockFilter::Policy(&LockedInputPolicy::default()),
            )
            .map_err(|_| AssemblyError::InsufficientFunds)?;
        let batch_notes: Vec<_> = batch.ironwood().to_vec();
        if batch_notes.is_empty() {
            return Err(AssemblyError::InsufficientFunds);
        }

        let batch_total = batch
            .ironwood_value()
            .map_err(|_| AssemblyError::ValueOverflow)?;
        if total_selected == batch_total
            && selected_notes.len() == batch_notes.len()
            && !selected.is_empty()
        {
            // Converged: the same notes now satisfy a larger requirement.
            fee = FeeRule::standard()
                .fee_required(
                    network,
                    target_height,
                    std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
                    std::iter::empty::<usize>(),
                    0,
                    0,
                    0,
                    ironwood_actions(plan.output_count, batch_notes.len())?,
                )
                .map(Zatoshis::into_u64)
                .map_err(|_| AssemblyError::FeeOverflow)?;
            total_selected = batch_total;
            selected = batch_notes.iter().map(|n| *n.internal_note_id()).collect();
            selected_notes = batch_notes;
            break;
        }

        fee = FeeRule::standard()
            .fee_required(
                network,
                target_height,
                std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
                std::iter::empty::<usize>(),
                0,
                0,
                0,
                ironwood_actions(plan.output_count, batch_notes.len())?,
            )
            .map(Zatoshis::into_u64)
            .map_err(|_| AssemblyError::FeeOverflow)?;
        total_selected = batch_total;
        selected = batch_notes.iter().map(|n| *n.internal_note_id()).collect();
        selected_notes = batch_notes;

        let met = (total_selected - funding_total)
            .and_then(|v| v.checked_sub(Zatoshis::from_u64(fee).map_err(|_| AssemblyError::FeeOverflow)?))
            .is_some();
        if met {
            break;
        }
    }

    let change_value = (total_selected
        - funding_total)
    .and_then(|v| v.checked_sub(Zatoshis::from_u64(fee).map_err(|_| AssemblyError::FeeOverflow)?))
    .ok_or(AssemblyError::InsufficientFunds)?
    .into_u64();

    // 4. Anchor root and per-note witnesses, in one tree session.
    let (anchor, merkle_paths) = wallet
        .with_ironwood_tree_mut(|tree| {
            let root = tree.root_at_checkpoint_id(&anchor_height);
            let paths = selected_notes
                .iter()
                .map(|note| {
                    tree.witness_at_checkpoint_id_caching(
                        note.note_commitment_tree_position(),
                        &anchor_height,
                    )
                })
                .collect::<Result<Vec<_>, _>>();
            root.and_then(|root| paths.map(|paths| (root, paths)))
        })
        .map_err(|_: ShardTreeError<_>| AssemblyError::NoWitness)?
        .ok_or(AssemblyError::NoAnchor)?;
    let anchor: orchard::tree::Anchor = anchor.ok_or(AssemblyError::NoAnchor)?.into();

    // 5. Build the single Ironwood bundle: Treasury spends, Treasury change,
    //    Registry fee-note outputs.
    let treasury_fvk = treasury_keys.orchard_fvk();
    let change_address = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);

    let bundle_version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        bundle_version,
        bundle_version.default_flags(),
        anchor,
    )
    .map_err(|_| AssemblyError::BuilderCreation)?;

    for (note, path) in selected_notes.iter().zip(merkle_paths) {
        let merkle_path = path.ok_or(AssemblyError::NoWitness)?;
        builder
            .add_spend(treasury_fvk.clone(), note.note().clone(), merkle_path.into())
            .map_err(|_| AssemblyError::BuilderAdd)?;
    }

    // A 512-byte memo is mandatory for Ironwood outputs; the change note
    // carries the return-memo marker only.
    if change_value > 0 {
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6;
        builder
            .add_change_output(
                treasury_fvk.clone(),
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                change_address,
                orchard::value::NoteValue::from_raw(change_value),
                change_memo,
            )
            .map_err(|_| AssemblyError::BuilderAdd)?;
    }

    // The Registry's address arrives as viewing data from the wallet — the
    // Treasury holds no Registry keys (the capability lattice in `key.rs`).
    let registry_fvk = {
        let registry_ufvk = wallet
            .ufvk_for(REGISTRY_ACCOUNT)
            .ok_or(AssemblyError::UfvkNotFound)?;
        registry_ufvk
            .orchard()
            .ok_or(AssemblyError::UfvkNotFound)?
            .clone()
    };
    let registry_address = registry_fvk.address_at(0u32, orchard::keys::Scope::External);

    for _ in 0..plan.output_count {
        let mut fee_memo = [0u8; 512];
        fee_memo[0] = 0xF6; // ZIP-302 empty memo
        builder
            .add_output(
                // The Treasury is the sender: its OVK can recover the
                // outgoing plaintext. The Registry detects the notes by
                // trial decryption as recipient regardless.
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::External)),
                registry_address,
                orchard::value::NoteValue::from_raw(plan.output_value),
                fee_memo,
            )
            .map_err(|_| AssemblyError::BuilderAdd)?;
    }

    let (bundle, _bundle_meta) = builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| AssemblyError::BuildFailed)?
        .ok_or(AssemblyError::BuildFailed)?;

    // 6. Prove and sign. Only the Treasury signs: the bundle carries no
    //    Registry spend. Written against the signer's planned return of the
    //    built `Transaction` (step 7 records it in the wallet); the signer
    //    currently returns `(TxId, String)`, changed with the signing slice.
    let tx = crate::registry::signing::assemble_v6_transaction(
        network,
        Some(bundle),
        Some(treasury_keys),
        None,
        None,
        target_height,
    )?;
    let txid = tx.txid();

    // 7. Record the sent transaction: the wallet's spend record is the
    //    reservation view. Every output is shielded to a wallet account —
    //    the fee notes to the Registry, change back to the Treasury — so
    //    all are rediscovered by scanning; the record carries no sent
    //    outputs, only the spends that block re-selection.
    let sent = SentTransaction::new(
        &tx,
        OffsetDateTime::now_utc(),
        target,
        TREASURY_ACCOUNT,
        &[],
        Zatoshis::from_u64(fee).map_err(|_| AssemblyError::FeeOverflow)?,
        &[],
    );
    wallet
        .store_transactions_to_be_sent(&[sent])
        .map_err(|_| AssemblyError::InsufficientFunds)?;

    Ok(Some(txid))
}

/// Padded Ironwood action count for `outputs` fee notes, `spends` funding
/// notes, and one Treasury change output.
fn ironwood_actions(outputs: usize, spends: usize) -> Result<usize, AssemblyError> {
    BundleType::DEFAULT
        .num_actions(
            orchard::bundle::BundleVersion::ironwood_v3().default_flags(),
            spends,
            outputs + 1, // Treasury change
        )
        .map_err(|_| AssemblyError::ActionOverflow)
}

/// ZIP-317 fee for the shape, given a provisional spend count.
fn fee_estimate<P: Parameters>(
    network: &P,
    target_height: BlockHeight,
    outputs: usize,
    spends: usize,
) -> Result<Zatoshis, AssemblyError> {
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};
    FeeRule::standard()
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            ironwood_actions(outputs, spends)?,
        )
        .map_err(|_| AssemblyError::FeeOverflow)
}
