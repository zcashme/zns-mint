use crate::treasury::memo;
use crate::treasury::TREASURY_ACCOUNT;
use crate::wallet::transaction::ReceivedOrchardNote;
use crate::wallet::Wallet;
use zcash_protocol::value::Zatoshis;

/// Detects if a specific claim request included at least the required payment.
///
/// Looks for a single spendable Treasury note whose value is at least
/// `min_amount` and whose memo matches the given claim request. The actual
/// refund amount and Treasury fee are computed later by the refund assembler;
/// this function only establishes that a suitable payment note exists.
pub fn match_fee<'a>(
    wallet: &'a Wallet,
    request: &memo::RequestMemo,
    min_amount: Zatoshis,
) -> Option<&'a ReceivedOrchardNote> {
    if !matches!(request, memo::RequestMemo::Claim { .. }) {
        return None;
    }

    wallet
        .orchard_notes_for(TREASURY_ACCOUNT)
        .find(|n| {
            if n.note.value().inner() < min_amount.into_u64() {
                return false;
            }
            match memo::RequestMemo::parse(n.memo.as_array()) {
                Ok(parsed_memo) => &parsed_memo == request,
                Err(_) => false,
            }
        })
}
