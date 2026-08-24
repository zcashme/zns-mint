//! Treasury vault deposits.
//!
//! When the Treasury's spendable Ironwood balance exceeds `SWEEP_THRESHOLD`,
//! the excess is swept to the project vault — a fixed transparent P2PKH
//! address owned by the project. The vault is transparent on purpose: vault
//! holdings are publicly auditable without any viewing key, and the attested
//! mint never holds long-term value.
//!
//! The deposit is a V6 transaction with:
//!
//! - **Ironwood bundle** (Treasury authority): spends every unspent Treasury
//!   Ironwood note and creates one Ironwood change note retaining
//!   `SWEEP_RESERVE`.
//! - **Transparent output**: sends the remainder to `VAULT_ADDRESS`.
//!
//! One call decides and settles: [`sweep_to_vault`] reads the balance and
//! heights from the wallet, selects the notes, derives the exact amount after
//! the ZIP-317 fee, builds, proves, signs, and records the transaction in the
//! wallet — returning only its [`TxId`]. Repeat safety is the wallet's:
//! storing the sent transaction records every consumed note as spent, and a
//! stored-but-unmined spend blocks re-selection until the transaction
//! confirms or its expiry height passes.

use std::num::NonZeroU32;

use orchard::builder::BundleType;
use shardtree::error::ShardTreeError;
use time::OffsetDateTime;
use transparent::address::TransparentAddress;
use zcash_address::ZcashAddress;
use zcash_client_backend::data_api::wallet::input_selection::{LockFilter, LockedInputPolicy};
use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::{
    InputSource, SentTransaction, SentTransactionOutput, WalletCommitmentTrees, WalletRead,
    WalletWrite,
};
use zcash_client_backend::wallet::Recipient;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::{ZatBalance, Zatoshis};
use zcash_protocol::{PoolType, ShieldedPool};

use crate::key::TreasuryKeys;
use crate::mint::{AssemblyError, TREASURY_ACCOUNT};
use crate::registry::transaction::TransparentOutput;
use crate::wallet::Wallet;

/// Minimum spendable Treasury balance (zatoshis) to trigger a deposit.
/// 200,000,000 zatoshis = 2 ZEC.
const SWEEP_THRESHOLD: u64 = 200_000_000;

/// Amount retained as Treasury change after a sweep (zatoshis).
/// 1,000,000 zatoshis = 0.01 ZEC.
const SWEEP_RESERVE: u64 = 1_000_000;

/// The project vault's P2PKH address.
///
/// Transparent on purpose: vault holdings are publicly auditable without any
/// viewing key, and the attested mint never holds long-term value. Compiled
/// into the attested binary; runtime configuration is forbidden. The current
/// bytes are a placeholder pending the vault's final approved address.
const VAULT_ADDRESS: TransparentAddress = TransparentAddress::PublicKeyHash([0x42; 20]);

/// Sweeps the Treasury's excess to the project vault.
///
/// Returns `Ok(None)` when the spendable Treasury Ironwood balance is at or
/// below [`SWEEP_THRESHOLD`] (or the wallet has not yet observed a chain
/// tip), and `Ok(Some(txid))` when a deposit was built, signed, and recorded
/// in the wallet. The caller broadcasts the stored transaction by its
/// [`TxId`] (`WalletRead::get_transaction`).
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
) -> Result<Option<TxId>, AssemblyError> {
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    // 1. Decide: nothing is due at or below the threshold. The trigger is
    //    the spendable balance — the value a deposit could actually move.
    //    (Wallet failures map to placeholder variants until `AssemblyError`
    //    grows a `Wallet` variant in the mint slice.)
    let Some(summary) = wallet
        .get_wallet_summary(ConfirmationsPolicy::new_symmetrical(
            NonZeroU32::MIN,
            false,
        ))
        .ok()
        .flatten()
    else {
        return Ok(None);
    };
    let treasury_balance = summary
        .account_balances()
        .get(&TREASURY_ACCOUNT)
        .map(|balance| balance.ironwood_balance().spendable_value().into_u64())
        .unwrap_or(0);
    if treasury_balance <= SWEEP_THRESHOLD {
        return Ok(None);
    }

    // 2. Heights are wallet facts, mirroring upstream `propose_transfer`:
    //    target for fee and expiry binding, anchor for witness binding.
    //    The mint spends at its fully-applied tip; reorg safety comes from
    //    the expiry/status lifecycle, not anchor depth.
    let (target, anchor_height) = wallet
        .get_target_and_anchor_heights(NonZeroU32::MIN)
        .ok()
        .flatten()
        .ok_or(AssemblyError::NoAnchor)?;
    let target_height = BlockHeight::from(target);

    // 3. Select every unspent Treasury Ironwood note, oldest-first. Lock
    //    state uses upstream's default exclude policy: a locked output never
    //    joins a vault deposit.
    let selected = wallet
        .select_unspent_notes(
            TREASURY_ACCOUNT,
            &[ShieldedPool::Ironwood],
            target,
            &[],
            LockFilter::Policy(&LockedInputPolicy::default()),
        )
        .map_err(|_| AssemblyError::NoteNotFound)?;
    let funding_notes: Vec<(orchard::note::Note, incrementalmerkletree::Position)> = selected
        .ironwood()
        .iter()
        .filter(|note| note.note().value().inner() > 0)
        .map(|note| (note.note().clone(), note.note_commitment_tree_position()))
        .collect();
    if funding_notes.is_empty() {
        return Err(AssemblyError::InsufficientFunds);
    }

    // 4. The exact deposit is derived from the selected notes: reserve and
    //    fee are retained, the remainder goes to the vault.
    let total_selected = funding_notes.iter().try_fold(0u64, |total, (note, _)| {
        total
            .checked_add(note.value().inner())
            .ok_or(AssemblyError::ValueOverflow)
    })?;
    let ironwood_actions = BundleType::DEFAULT
        .num_actions(
            orchard::bundle::BundleVersion::ironwood_v3().default_flags(),
            funding_notes.len(),
            1, // Treasury change
        )
        .map_err(|_| AssemblyError::ActionOverflow)?;
    let fee = FeeRule::standard()
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::once(34), // 1 P2PKH output (34 bytes)
            0,
            0,
            0,
            ironwood_actions,
        )
        .map(Zatoshis::into_u64)
        .map_err(|_| AssemblyError::FeeOverflow)?;
    let sweep_amount = total_selected
        .checked_sub(SWEEP_RESERVE)
        .and_then(|value| value.checked_sub(fee))
        .ok_or(AssemblyError::InsufficientFunds)?;
    if sweep_amount == 0 {
        return Err(AssemblyError::InsufficientFunds);
    }

    // 5. Anchor root and per-note witnesses, in one tree session — the
    //    upstream `create_proposed_transactions` pattern.
    let (anchor, merkle_paths) = wallet
        .with_ironwood_tree_mut(|tree| {
            let root = tree.root_at_checkpoint_id(&anchor_height);
            let paths = funding_notes
                .iter()
                .map(|(_, position)| {
                    tree.witness_at_checkpoint_id_caching(*position, &anchor_height)
                })
                .collect::<Result<Vec<_>, _>>();
            root.and_then(|root| paths.map(|paths| (root, paths)))
        })
        .map_err(|_: ShardTreeError<_>| AssemblyError::NoWitness)?
        .ok_or(AssemblyError::NoAnchor)?;
    let anchor: orchard::tree::Anchor = anchor.ok_or(AssemblyError::NoAnchor)?.into();

    // 6. Build the Ironwood bundle: every selected spend, plus the change
    //    note retaining the reserve.
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

    for ((note, _), path) in funding_notes.iter().zip(merkle_paths) {
        let merkle_path = path.ok_or(AssemblyError::NoWitness)?;
        builder
            .add_spend(treasury_fvk.clone(), note.clone(), merkle_path.into())
            .map_err(|_| AssemblyError::BuilderAdd)?;
    }

    // A 512-byte memo is mandatory for Ironwood outputs; the change note
    // carries the return-memo marker only. The scanner rediscovers this note
    // when the deposit mines — it is addressed to the Treasury's internal
    // address, so it needs no sent-output record.
    let mut change_memo = [0u8; 512];
    change_memo[0] = 0xF6;
    builder
        .add_change_output(
            treasury_fvk.clone(),
            Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
            change_address,
            orchard::value::NoteValue::from_raw(SWEEP_RESERVE),
            change_memo,
        )
        .map_err(|_| AssemblyError::BuilderAdd)?;

    let (bundle, _bundle_meta) = builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| AssemblyError::BuildFailed)?
        .ok_or(AssemblyError::BuildFailed)?;

    // 7. Prove and sign. Only the Treasury signs.
    //
    //    Written against the signer's planned return of the built
    //    `Transaction` (step 8 records it in the wallet; upstream's own
    //    `create_proposed_transactions` stores the tx it builds). The
    //    signer currently returns `(TxId, String)`; that change lands with
    //    the signing slice.
    let transparent_outputs = [TransparentOutput {
        address: VAULT_ADDRESS,
        value: Zatoshis::from_u64(sweep_amount).map_err(|_| AssemblyError::ValueOverflow)?,
    }];
    let tx = crate::registry::signing::assemble_v6_transaction(
        network,
        Some(bundle),
        Some(treasury_keys),
        None,
        Some(&transparent_outputs),
        target_height,
    )?;
    let txid = tx.txid();

    // 8. Record the sent transaction. This is what makes the deposit safe to
    //    repeat: the wallet records each spent note, blocking re-selection
    //    until the deposit confirms or its expiry height passes. Only the
    //    vault output is recorded as a sent output — the shielded change is
    //    rediscovered by scanning, like every received note.
    let sent_outputs = [SentTransactionOutput::from_parts(
        0,
        Recipient::External {
            recipient_address: ZcashAddress::from_transparent(network.coin_type(), VAULT_ADDRESS),
            output_pool: PoolType::TRANSPARENT,
        },
        Zatoshis::from_u64(sweep_amount).map_err(|_| AssemblyError::ValueOverflow)?,
        None,
    )];
    let sent = SentTransaction::new(
        &tx,
        OffsetDateTime::now_utc(),
        target,
        TREASURY_ACCOUNT,
        &sent_outputs,
        Zatoshis::from_u64(fee).map_err(|_| AssemblyError::FeeOverflow)?,
        &[],
    );
    wallet
        .store_transactions_to_be_sent(&[sent])
        .map_err(|_| AssemblyError::NoteNotFound)?;

    Ok(Some(txid))
}
