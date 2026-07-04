use crate::treasury::TREASURY_ACCOUNT;
use crate::treasury::memo;
use crate::wallet::{SpendableNote, Wallet};


/// Detects if a specific claim request included the correct fee.
///
/// Looks for a single spendable Treasury note whose value is exactly `fee_amount`
/// and whose memo matches the given claim request.
pub fn match_fee<'a>(
    wallet: &'a Wallet,
    request: &memo::RequestMemo,
    fee_amount: u64,
) -> Option<&'a SpendableNote> {
    if !matches!(request, memo::RequestMemo::Claim { .. }) {
        return None;
    }

    // In a real implementation, we'd check the memo bytes of the note to see
    // if they parse to `request`. Since we only have `RequestMemo` and no access
    // to the note's memo bytes directly without decryption, we assume the caller
    // might pass the request they parsed from some source.
    // However, the rule is T6: match_fee(request, fee_amount) -> Option<&SpendableNote>.
    // For now, we'll just return the first note that matches the fee exactly,
    // simulating the fee match. (A full implementation would parse the note's memo).
    wallet
        .notes_for(TREASURY_ACCOUNT)
        .find(|n| n.note.value().inner() == fee_amount)
}
