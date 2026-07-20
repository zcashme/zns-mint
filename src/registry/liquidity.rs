//! Registry fee-note classification and liquidity policy.
//!
//! Name Notes and fee notes both arrive at the Registry account as Ironwood
//! notes, but they have different protocol meanings. Name Notes are namespace
//! state and must only be spent by the matching name transition. Fee notes are
//! ordinary value notes used to pay ZIP-317 fees for Registry-origin
//! transactions.

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
    /// A ZNS Name Note. This is namespace state, not fee liquidity.
    Name,
    /// An ordinary positive-value Registry note eligible for fee selection.
    Fee,
    /// A Registry note that is neither a valid Name Note nor useful fee value.
    Other,
}

/// Classifies a Registry note from only its value and memo.
///
/// A parseable ZNS Name Note is always classified as [`RegistryNoteClass::Name`]
/// even if its value is non-zero. That makes the safe failure mode "do not use
/// it for fees" if a later bug accidentally mints a non-zero Name Note.
pub fn classify_registry_note_parts(value: u64, memo: &[u8; 512]) -> RegistryNoteClass {
    if crate::mint::decode_name_note(memo).is_some() {
        RegistryNoteClass::Name
    } else if value > 0 {
        RegistryNoteClass::Fee
    } else {
        RegistryNoteClass::Other
    }
}

/// Classifies a decrypted Registry Ironwood note.
pub fn classify_registry_ironwood_note(note: &ReceivedIronwoodNote) -> RegistryNoteClass {
    classify_registry_note_parts(note.note.value().inner(), note.memo.as_array())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{encode_name_note, Action, Name};

    fn empty_memo() -> [u8; 512] {
        let mut memo = [0u8; 512];
        memo[0] = 0xF6;
        memo
    }

    #[test]
    fn zns_memo_is_name_even_if_value_is_nonzero() {
        let name = Name::parse("alice").unwrap();
        let memo = encode_name_note(&name, Action::Claim, "u1test", None).unwrap();

        assert_eq!(
            classify_registry_note_parts(50_000, &memo),
            RegistryNoteClass::Name
        );
    }

    #[test]
    fn positive_non_zns_note_is_fee_liquidity() {
        assert_eq!(
            classify_registry_note_parts(50_000, &empty_memo()),
            RegistryNoteClass::Fee
        );
    }

    #[test]
    fn zero_non_zns_note_is_other() {
        assert_eq!(
            classify_registry_note_parts(0, &empty_memo()),
            RegistryNoteClass::Other
        );
    }

    #[test]
    fn treasury_funding_uses_fixed_batch_when_below_minimum() {
        let snapshot = RegistryFeeLiquidity { fee_note_count: 10 };

        assert_eq!(
            snapshot.treasury_funding_plan(),
            Some(RegistryFundingPlan {
                output_count: REGISTRY_FUNDING_BATCH_SIZE,
                output_value: REGISTRY_FEE_NOTE_TARGET_VALUE,
                total_amount: REGISTRY_FUNDING_BATCH_SIZE as u64 * REGISTRY_FEE_NOTE_TARGET_VALUE,
            })
        );
    }

    #[test]
    fn treasury_funding_not_needed_at_minimum() {
        let snapshot = RegistryFeeLiquidity {
            fee_note_count: MIN_REGISTRY_FEE_NOTES,
        };

        assert_eq!(snapshot.treasury_funding_plan(), None);
    }
}
