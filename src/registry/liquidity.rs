//! Registry fee-note classification and liquidity policy.
//!
//! Validated Name Notes are held in Registry state and never enter this
//! ordinary-note lane. These notes are ordinary value notes used to pay
//! ZIP-317 fees for Registry-origin transactions.

use std::num::NonZeroU32;

use zcash_client_backend::data_api::wallet::input_selection::{LockFilter, LockedInputPolicy};
use zcash_client_backend::data_api::{InputSource, NoteFilter, WalletRead};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;

use crate::mint::REGISTRY_ACCOUNT;
use crate::wallet::Wallet;

/// Target value for one Registry fee note.
///
/// A Name Note lifecycle bundle is two to five actions; ZIP-317 prices it at
/// 10,000–25,000 zatoshis padded (`MINIMUM_FEE` = 10,000 and 5,000 per
/// action past two grace actions, `zcash_primitives`
/// `transaction/fees/zip317.rs:19-40`). This value — five minimum fees —
/// lets one fee note cover one lifecycle op with headroom for fee drift and
/// per-note change overhead. Overshoot is safe: an unspent remainder returns
/// as Registry change, itself a fresh fee note.
pub const REGISTRY_FEE_NOTE_TARGET_VALUE: u64 = 50_000;

/// Unspent fee notes below which the Treasury refills the pool.
///
/// The floor is the burst the pool must absorb while one refill confirms:
/// each lifecycle op burns roughly half a fee note on average (the change
/// returns as a new note), and a refill needs one confirmation to land.
/// Twenty funded lifecycle ops of in-flight headroom.
pub const MIN_REGISTRY_FEE_NOTES: usize = 20;

/// Pool size a refill restores: twice the floor — comfortable steady state
/// without overshoot. (Supersedes a fixed batch of 100, which jumped the
/// pool to six times the floor for no recorded reason.)
pub const REGISTRY_FEE_POOL_TARGET: usize = 40;

/// Registry Ironwood note classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryNoteClass {
    /// An ordinary positive-value Registry note eligible for fee selection.
    Fee,
    /// A Registry note that is neither a valid Name Note nor useful fee value.
    Other,
}

/// Classifies an ordinary Registry note from its value.
///
/// Memo bytes have no authority to change an ordinary note's capability.
pub fn classify_registry_note_parts(value: u64) -> RegistryNoteClass {
    if value > 0 {
        RegistryNoteClass::Fee
    } else {
        RegistryNoteClass::Other
    }
}

/// Classifies a received Registry Ironwood note.
pub fn classify_registry_ironwood_note(
    note: &zcash_client_backend::wallet::ReceivedNote<
        zcash_client_backend::wallet::NoteId,
        orchard::note::Note,
    >,
) -> RegistryNoteClass {
    classify_registry_note_parts(note.note().value().inner())
}

/// Count of Registry fee notes rebuilt from wallet state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryFeeLiquidity {
    pub fee_note_count: usize,
}

impl RegistryFeeLiquidity {
    pub fn empty() -> Self {
        Self { fee_note_count: 0 }
    }

    /// Counts the pool's unspent fee notes from wallet state, through
    /// upstream `InputSource::get_account_metadata` with
    /// `NoteFilter::ExceedsMinValue(ZERO)` — strictly positive value, which
    /// excludes value-0 Name Notes by construction — under the same
    /// spendability rules (one confirmation, unspent, lock-excluded) that
    /// fee selection itself applies, so the count can never disagree with
    /// what a lifecycle op can actually draw on.
    ///
    /// Note *count* is the metric, not summed value: one fee note ≈ one
    /// lifecycle op, and change regenerates the pool while only the fee
    /// proper (10k–25k per op) grinds it down.
    pub fn from_wallet(wallet: &Wallet) -> Self {
        // Counting needs a target height; before the wallet has observed a
        // tip there is nothing scanned to count. An empty pool at boot is
        // the true pre-replenishment state, not an error.
        let Some((target, _anchor)) = wallet
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .ok()
            .flatten()
        else {
            return Self::empty();
        };

        let fee_note_count = wallet
            .get_account_metadata(
                REGISTRY_ACCOUNT,
                &NoteFilter::ExceedsMinValue(Zatoshis::ZERO),
                target,
                &[],
                LockFilter::Policy(&LockedInputPolicy::default()),
            )
            .ok()
            .and_then(|meta| meta.ironwood())
            .map(|pool| pool.note_count())
            .unwrap_or(0);
        Self { fee_note_count }
    }

    /// Returns the Treasury funding plan that restores the target fee pool.
    pub fn treasury_funding_plan(&self) -> Option<RegistryFundingPlan> {
        if self.fee_note_count >= MIN_REGISTRY_FEE_NOTES {
            return None;
        }

        let output_count = REGISTRY_FEE_POOL_TARGET - self.fee_note_count;
        Some(RegistryFundingPlan {
            output_count,
            output_value: REGISTRY_FEE_NOTE_TARGET_VALUE,
            total_amount: REGISTRY_FEE_NOTE_TARGET_VALUE * output_count as u64,
        })
    }
}

/// Desired output shape for a Treasury -> Registry funding transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryFundingPlan {
    pub output_count: usize,
    pub output_value: u64,
    pub total_amount: u64,
}
