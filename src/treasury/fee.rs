use crate::treasury::memo;
use crate::treasury::TREASURY_ACCOUNT;
use crate::wallet::transaction::ReceivedOrchardNote;
use crate::wallet::Wallet;
use zcash_protocol::value::Zatoshis;

/// Detects if a specific claim request included the correct fee.
///
/// Looks for a single spendable Treasury note whose value is exactly `fee_amount`
/// and whose memo matches the given claim request.
pub fn match_fee<'a>(
    wallet: &'a Wallet,
    request: &memo::RequestMemo,
    fee_amount: Zatoshis,
) -> Option<&'a ReceivedOrchardNote> {
    if !matches!(request, memo::RequestMemo::Claim { .. }) {
        return None;
    }

    wallet
        .orchard_notes_for(TREASURY_ACCOUNT)
        .find(|n| {
            if n.note.value().inner() != fee_amount.into_u64() {
                return false;
            }
            match memo::RequestMemo::parse(n.memo.as_array()) {
                Ok(parsed_memo) => &parsed_memo == request,
                Err(_) => false,
            }
        })
}
