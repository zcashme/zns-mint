//! Refunds due from the run loop.
//!
//! A refund is a Treasury payment, funded from Sapling or Ironwood, with
//! change in Ironwood, and the wallet's from there, like a sweep. Its amount
//! is fixed when it is admitted: the payment less `CHALLENGE_FEE`, so the
//! payer covers the fee. A refund is built on the tip pass after its
//! payment's block.

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::mint::{Name, UnifiedAddress};

/// Paid by every update, release, buy, list or delist request, and
/// withheld from every refund. Equivalent to `ACTION_FEE * 100`.
pub const CHALLENGE_FEE: Zatoshis = Zatoshis::const_from_u64(100_000);

/// `paid` minus `CHALLENGE_FEE`, when that remainder is positive.
fn refund_output(paid: Zatoshis) -> Option<Zatoshis> {
    (paid - CHALLENGE_FEE).filter(|output| *output > Zatoshis::ZERO)
}

/// One refund due: the payment it answers, where it goes, how much.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundRequest {
    payment: TxId,
    recipient: UnifiedAddress,
    /// What the Treasury pays back: the payment less the withheld fee.
    amount: Zatoshis,
    name: Name,
    height: BlockHeight,
    /// A sentence sent with the payment. Absent on a plain refund.
    note: Option<String>,
}

impl RefundRequest {
    /// The transaction that carried the payment.
    pub fn payment(&self) -> TxId {
        self.payment
    }

    pub fn recipient(&self) -> &UnifiedAddress {
        &self.recipient
    }

    pub fn amount(&self) -> Zatoshis {
        self.amount
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    /// The sentence that rides with this payment, when it has one.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// Refunds due, in admission order. A refund leaves when it is built and
/// accepted (`paid`) or when a reorg orphans its payment's block
/// (`truncate_to`); nothing else removes it.
#[derive(Clone, Debug, Default)]
pub struct RefundQueue {
    refunds_due: Vec<RefundRequest>,
}

impl RefundQueue {
    /// Owes `recipient` what `refundable` leaves after the withheld fee. A
    /// payment that leaves nothing is kept.
    pub fn admit(
        &mut self,
        txid: TxId,
        recipient: &UnifiedAddress,
        name: &Name,
        height: BlockHeight,
        refundable: Zatoshis,
    ) {
        self.admit_with_note(txid, recipient, name, height, refundable, None);
    }

    /// [`admit`](Self::admit), and `note` is paid back with the zatoshis.
    pub fn admit_with_note(
        &mut self,
        txid: TxId,
        recipient: &UnifiedAddress,
        name: &Name,
        height: BlockHeight,
        refundable: Zatoshis,
        note: Option<String>,
    ) {
        let Some(amount) = refund_output(refundable) else {
            // Nothing is queued. The sentence stays on this record.
            tracing::info!(
                %txid,
                name = %name.as_str(),
                refundable = refundable.into_u64(),
                note = note.as_deref(),
                "payment kept"
            );
            return;
        };
        tracing::info!(
            %txid,
            name = %name.as_str(),
            refundable = refundable.into_u64(),
            refund = amount.into_u64(),
            "payment refund"
        );
        self.refunds_due.push(RefundRequest {
            payment: txid,
            recipient: recipient.clone(),
            amount,
            name: name.clone(),
            height,
            note,
        });
    }

    /// The refunds whose payment is below `tip`, in admission order.
    pub fn due(&self, tip: BlockHeight) -> Vec<RefundRequest> {
        self.refunds_due
            .iter()
            .filter(|refund| refund.height < tip)
            .cloned()
            .collect()
    }

    /// Whether no refund is queued, due or not.
    pub fn is_empty(&self) -> bool {
        self.refunds_due.is_empty()
    }

    /// `built` is built and the node accepted it. One transaction can carry
    /// several refunds, so only the entry equal to `built` leaves.
    pub fn paid(&mut self, built: &RefundRequest) {
        if let Some(i) = self.refunds_due.iter().position(|refund| refund == built) {
            self.refunds_due.remove(i);
        }
    }

    /// Reorg: refunds whose payment's block was orphaned fall with it.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) {
        self.refunds_due.retain(|refund| refund.height <= ancestor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Name {
        Name::parse("alice").unwrap()
    }

    fn ua() -> UnifiedAddress {
        let ua = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";
        match zcash_keys::address::Address::decode(&zcash_protocol::consensus::MAIN_NETWORK, ua) {
            Some(zcash_keys::address::Address::Unified(ua)) => *ua,
            _ => panic!("test UA"),
        }
    }

    /// A tip far past every test payment.
    fn deep() -> BlockHeight {
        BlockHeight::from_u32(1_000)
    }

    fn admit(queue: &mut RefundQueue, payment: TxId, height: u32) {
        queue.admit(
            payment,
            &ua(),
            &alice(),
            BlockHeight::from_u32(height),
            Zatoshis::const_from_u64(1_000_000),
        )
    }

    #[test]
    fn a_payment_that_does_not_exceed_the_fee_is_kept() {
        let mut queue = RefundQueue::default();
        for refundable in [
            CHALLENGE_FEE,
            (CHALLENGE_FEE - Zatoshis::const_from_u64(1)).unwrap(),
        ] {
            queue.admit(
                TxId::from_bytes([1; 32]),
                &ua(),
                &alice(),
                BlockHeight::from_u32(10),
                refundable,
            );
        }
        assert!(queue.due(deep()).is_empty());

        let mut noted = RefundQueue::default();
        noted.admit_with_note(
            TxId::from_bytes([1; 32]),
            &ua(),
            &alice(),
            BlockHeight::from_u32(10),
            CHALLENGE_FEE,
            Some("ZNS:held:alice:1700000600".to_string()),
        );
        assert!(noted.is_empty());
    }

    #[test]
    fn a_refund_leaves_when_built_or_when_its_payment_is_orphaned() {
        let kept = TxId::from_bytes([1; 32]);
        let orphaned = TxId::from_bytes([2; 32]);
        let mut queue = RefundQueue::default();
        admit(&mut queue, kept, 10);
        admit(&mut queue, orphaned, 30);

        queue.truncate_to(BlockHeight::from_u32(20));
        let left: Vec<_> = queue
            .due(deep())
            .iter()
            .map(RefundRequest::payment)
            .collect();
        assert_eq!(left, vec![kept]);

        let built = queue.due(deep()).remove(0);
        queue.paid(&built);
        assert!(queue.due(deep()).is_empty());
    }

    #[test]
    fn a_built_refund_leaves_the_others_from_its_transaction() {
        let txid = TxId::from_bytes([1; 32]);
        let mut queue = RefundQueue::default();
        admit(&mut queue, txid, 10);
        queue.admit(
            txid,
            &ua(),
            &alice(),
            BlockHeight::from_u32(10),
            Zatoshis::const_from_u64(2_000_000),
        );

        let second = queue.due(deep()).remove(1);
        queue.paid(&second);
        let left = queue.due(deep());
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].amount(), Zatoshis::const_from_u64(900_000));
    }

    #[test]
    fn a_refund_is_due_on_the_tip_after_its_payment() {
        let payment = TxId::from_bytes([1; 32]);
        let mut queue = RefundQueue::default();
        admit(&mut queue, payment, 10);
        assert!(queue.due(BlockHeight::from_u32(10)).is_empty());
        assert_eq!(queue.due(BlockHeight::from_u32(11)).len(), 1);
    }
}
