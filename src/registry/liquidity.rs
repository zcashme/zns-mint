//! Registry fee-note classification and liquidity policy.
//!
//! Validated Name Notes are held in Registry state and never enter this
//! ordinary-note lane. These notes are ordinary value notes used to pay
//! ZIP-317 fees for Registry-origin transactions.

use crate::mint::REGISTRY_ACCOUNT;
use crate::wallet::{transaction::ReceivedIronwoodNote, Wallet};

/// Target value for one Registry fee note.
///
/// This is intentionally larger than the minimum current Name Note fee so a
/// single fee note can cover ordinary claim/update/release transactions with
/// room for fee-policy changes and change output overhead.
pub const REGISTRY_FEE_NOTE_TARGET_VALUE: u64 = 50_000;

/// If the Registry has fewer fee notes than this, Treasury should refill it.
pub const MIN_REGISTRY_FEE_NOTES: usize = 20;

/// Number of fee-note outputs created by one Treasury -> Registry refill.
pub const REGISTRY_FUNDING_BATCH_SIZE: usize = 100;

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

/// Classifies a decrypted Registry Ironwood note.
pub fn classify_registry_ironwood_note(note: &ReceivedIronwoodNote) -> RegistryNoteClass {
    classify_registry_note_parts(note.note.value().inner())
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

    pub fn from_wallet(wallet: &Wallet) -> Self {
        let mut snapshot = Self::empty();

        for note in wallet.ironwood_notes_for(REGISTRY_ACCOUNT) {
            if classify_registry_ironwood_note(note) == RegistryNoteClass::Fee {
                snapshot.fee_note_count += 1;
            }
        }

        snapshot
    }

    /// Returns the Treasury funding plan needed to restore the target fee pool.
    pub fn treasury_funding_plan(&self) -> Option<RegistryFundingPlan> {
        if self.fee_note_count >= MIN_REGISTRY_FEE_NOTES {
            return None;
        }

        Some(RegistryFundingPlan {
            output_count: REGISTRY_FUNDING_BATCH_SIZE,
            output_value: REGISTRY_FEE_NOTE_TARGET_VALUE,
            total_amount: REGISTRY_FEE_NOTE_TARGET_VALUE * REGISTRY_FUNDING_BATCH_SIZE as u64,
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
