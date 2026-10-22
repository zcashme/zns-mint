//! Underpaid-claim refunds owed by the run loop.
//!
//! The payment note funds the refund, fee included. The queue is memory:
//! a restart forgets an unsent refund, and the next sweep may take the note.

use zcash_client_backend::wallet::NoteId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::mint::{Name, UnifiedAddress};
use crate::zcash::fee::single_action_fee;

/// How `paid` stands against the quote and the refund fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentAgainstQuote {
    /// `paid` is at least the quote.
    Covers,
    /// `paid` is short. This is `paid` minus the refund fee.
    Remainder(Zatoshis),
    /// `paid` is short and does not exceed the refund fee.
    BelowFee,
}

/// `Covers` when `paid` meets `price`. Otherwise the positive remainder
/// after the refund fee, or `BelowFee` when that remainder is zero.
pub fn payment_against_quote(
    paid: Zatoshis,
    price: Zatoshis,
    marginal: Zatoshis,
) -> PaymentAgainstQuote {
    if paid >= price {
        return PaymentAgainstQuote::Covers;
    }
    match refund_output(paid, marginal) {
        Some(output) => PaymentAgainstQuote::Remainder(output),
        None => PaymentAgainstQuote::BelowFee,
    }
}

/// `paid` minus the one-action fee, when that remainder is positive.
pub fn refund_output(paid: Zatoshis, marginal: Zatoshis) -> Option<Zatoshis> {
    let fee = single_action_fee(marginal)?;
    (paid - fee).filter(|output| *output > Zatoshis::ZERO)
}

/// One refund the Treasury still has to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refund {
    note: NoteId,
    recipient: UnifiedAddress,
    paid: Zatoshis,
    name: Name,
    height: BlockHeight,
}

impl Refund {
    pub fn new(
        note: NoteId,
        recipient: UnifiedAddress,
        paid: Zatoshis,
        name: Name,
        height: BlockHeight,
    ) -> Self {
        Self {
            note,
            recipient,
            paid,
            name,
            height,
        }
    }

    pub fn note(&self) -> NoteId {
        self.note
    }

    pub fn recipient(&self) -> &UnifiedAddress {
        &self.recipient
    }

    pub fn paid(&self) -> Zatoshis {
        self.paid
    }

    pub fn name(&self) -> &Name {
        &self.name
    }
}

/// Refunds owed, in admission order. A reorg drops those whose payment
/// block was orphaned. Sending, or finding the payment no longer covers
/// the fee, are the other removals.
#[derive(Clone, Debug, Default)]
pub struct RefundQueue {
    owed: Vec<Refund>,
}

impl RefundQueue {
    pub fn new() -> Self {
        Self { owed: Vec::new() }
    }

    /// Records `refund` unless that note is already owed.
    pub fn admit(&mut self, refund: Refund) {
        if self.owed.iter().any(|owed| owed.note == refund.note) {
            return;
        }
        self.owed.push(refund);
    }

    /// Every refund still owed, in admission order.
    pub fn due(&self) -> Vec<Refund> {
        self.owed.clone()
    }

    /// Names still waiting on a refund.
    pub fn names(&self) -> impl Iterator<Item = &Name> {
        self.owed.iter().map(|refund| &refund.name)
    }

    /// The refund was accepted by the node.
    pub fn sent(&mut self, note: NoteId) {
        self.owed.retain(|refund| refund.note != note);
    }

    /// The payment no longer covers a refund. The note may be swept.
    pub fn release(&mut self, note: NoteId) {
        self.owed.retain(|refund| refund.note != note);
    }

    /// Drops refunds whose payment was orphaned. The caller unlocks them.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) -> Vec<NoteId> {
        let mut dropped = Vec::new();
        self.owed.retain(|refund| {
            if refund.height <= ancestor {
                true
            } else {
                dropped.push(refund.note);
                false
            }
        });
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;

    fn zats(n: u64) -> Zatoshis {
        Zatoshis::const_from_u64(n)
    }

    #[test]
    fn an_underpaid_claim_refunds_the_payment_minus_the_fee() {
        let fee = single_action_fee(MARGINAL_FEE).unwrap();
        let paid = zats(50_000);
        assert_eq!(
            payment_against_quote(paid, zats(100_000), MARGINAL_FEE),
            PaymentAgainstQuote::Remainder((paid - fee).unwrap())
        );
    }

    #[test]
    fn a_payment_that_does_not_exceed_the_fee_is_kept() {
        let fee = single_action_fee(MARGINAL_FEE).unwrap();
        assert_eq!(
            payment_against_quote(fee, zats(100_000), MARGINAL_FEE),
            PaymentAgainstQuote::BelowFee
        );
        assert_eq!(
            payment_against_quote((fee - zats(1)).unwrap(), zats(100_000), MARGINAL_FEE),
            PaymentAgainstQuote::BelowFee
        );
    }

    #[test]
    fn a_fully_paid_claim_is_not_refunded() {
        let price = zats(100_000);
        assert_eq!(
            payment_against_quote(price, price, MARGINAL_FEE),
            PaymentAgainstQuote::Covers
        );
        assert_eq!(
            payment_against_quote(zats(100_001), price, MARGINAL_FEE),
            PaymentAgainstQuote::Covers
        );
    }
}
