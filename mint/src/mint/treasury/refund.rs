//! Refunds due from the run loop.
//!
//! A refund is a Treasury payment, funded from Sapling or Ironwood, with
//! change in Ironwood. Its amount is fixed when it is admitted: the payment
//! less `CHALLENGE_FEE`, so the payer covers the fee. A refund is built on
//! the tip pass after its payment's block.
//!
//! Once built and handed to Zebra, a refund is sent until it is mined or
//! its expiry height passes, whatever Zebra answered: Zebra resubmits a
//! transaction it refused, and drops one it accepted, so neither answer is
//! final. A sent refund is never built again while it can still be mined,
//! and one that expired unmined is built again.

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

/// Where a queued refund stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefundState {
    /// Not built yet, or its transaction expired unmined.
    Due,
    /// Its transaction `txid` went to Zebra and can be mined up to and
    /// including block `expiry`.
    Sent { txid: TxId, expiry: BlockHeight },
}

/// Refunds owed, in admission order. A refund leaves when its transaction
/// is mined (`settle`) or when a reorg orphans its payment's block
/// (`truncate_to`); nothing else removes it.
#[derive(Clone, Debug, Default)]
pub struct RefundQueue {
    refunds: Vec<(RefundRequest, RefundState)>,
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
        self.refunds.push((
            RefundRequest {
                payment: txid,
                recipient: recipient.clone(),
                amount,
                name: name.clone(),
                height,
                note,
            },
            RefundState::Due,
        ));
    }

    /// The refunds to build: due, with their payment below `tip`, in
    /// admission order.
    pub fn due(&self, tip: BlockHeight) -> Vec<RefundRequest> {
        self.refunds
            .iter()
            .filter(|(refund, state)| *state == RefundState::Due && refund.height < tip)
            .map(|(refund, _)| refund.clone())
            .collect()
    }

    /// The transactions of sent refunds, to hand to Zebra again: the same
    /// bytes, so a resend can never pay twice.
    pub fn sent_txids(&self) -> Vec<TxId> {
        self.refunds
            .iter()
            .filter_map(|(_, state)| match state {
                RefundState::Sent { txid, .. } => Some(*txid),
                RefundState::Due => None,
            })
            .collect()
    }

    /// Whether no refund is queued, due or sent.
    pub fn is_empty(&self) -> bool {
        self.refunds.is_empty()
    }

    /// `built` went to Zebra as transaction `txid`, valid up to and
    /// including block `expiry`, whatever Zebra answered. Two equal refunds
    /// can be owed, so only the first due entry equal to `built` is sent.
    pub fn sent(&mut self, built: &RefundRequest, txid: TxId, expiry: BlockHeight) {
        if let Some((_, state)) = self
            .refunds
            .iter_mut()
            .find(|(refund, state)| *state == RefundState::Due && refund == built)
        {
            *state = RefundState::Sent { txid, expiry };
        }
    }

    /// Settles each sent refund at the applied `tip`. A refund whose
    /// transaction `mined` leaves. One whose transaction can no longer be
    /// mined is due again: the last valid block is `expiry` itself (ZIP
    /// 203), so it returns when the tip reaches it, as the wallet frees the
    /// notes it spent. Expiry height zero means no expiry: such a refund
    /// stays sent until it is mined.
    pub fn settle(&mut self, tip: BlockHeight, mined: impl Fn(TxId) -> bool) {
        self.refunds.retain_mut(|(refund, state)| {
            let RefundState::Sent { txid, expiry } = *state else {
                return true;
            };
            if mined(txid) {
                tracing::info!(%txid, payment = %refund.payment, "refund mined");
                return false;
            }
            if u32::from(expiry) != 0 && tip >= expiry {
                tracing::warn!(
                    %txid,
                    payment = %refund.payment,
                    expiry = u32::from(expiry),
                    "refund expired unmined; due again"
                );
                *state = RefundState::Due;
            }
            true
        });
    }

    /// Reorg: refunds whose payment's block was orphaned fall with it.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) {
        self.refunds.retain(|(refund, _)| refund.height <= ancestor);
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

    const REFUND_TX: TxId = TxId::from_bytes([7; 32]);

    fn h(height: u32) -> BlockHeight {
        BlockHeight::from_u32(height)
    }

    /// Admits one refund at height 10 and sends it as `REFUND_TX`, valid
    /// through block 50.
    fn sent_queue() -> RefundQueue {
        let mut queue = RefundQueue::default();
        admit(&mut queue, TxId::from_bytes([1; 32]), 10);
        let built = queue.due(h(11)).remove(0);
        queue.sent(&built, REFUND_TX, h(50));
        queue
    }

    #[test]
    fn a_refund_whose_payment_is_orphaned_leaves_due_or_sent() {
        let kept = TxId::from_bytes([1; 32]);
        let orphaned = TxId::from_bytes([2; 32]);
        let mut queue = RefundQueue::default();
        admit(&mut queue, kept, 10);
        admit(&mut queue, orphaned, 30);
        let built = queue.due(deep()).remove(1);
        queue.sent(&built, REFUND_TX, h(70));

        queue.truncate_to(h(20));
        let left: Vec<_> = queue
            .due(deep())
            .iter()
            .map(RefundRequest::payment)
            .collect();
        assert_eq!(left, vec![kept]);
        assert!(queue.sent_txids().is_empty());
    }

    /// #625: a refund Zebra refused may still be mined, so it is not built
    /// again while its transaction is valid. It stays queued, so the vault
    /// sweep keeps waiting for it.
    #[test]
    fn a_sent_refund_is_not_built_again_before_its_expiry() {
        let mut queue = sent_queue();
        for tip in [h(11), h(30), h(49)] {
            queue.settle(tip, |_| false);
            assert!(queue.due(tip).is_empty(), "rebuilt at {tip:?}");
            assert_eq!(queue.sent_txids(), vec![REFUND_TX]);
        }
        assert!(!queue.is_empty());
    }

    /// #525: a refund whose transaction expired unmined is due again, at
    /// the tip where the wallet frees the notes it spent.
    #[test]
    fn a_sent_refund_that_expires_unmined_is_due_again() {
        let mut queue = sent_queue();
        queue.settle(h(50), |_| false);
        assert_eq!(queue.due(h(50)).len(), 1);
        assert!(queue.sent_txids().is_empty());
    }

    #[test]
    fn a_mined_refund_leaves_even_in_its_expiry_block() {
        let mut queue = sent_queue();
        queue.settle(h(50), |txid| txid == REFUND_TX);
        assert!(queue.is_empty());
    }

    #[test]
    fn a_refund_sent_without_expiry_waits_until_mined() {
        let mut queue = RefundQueue::default();
        admit(&mut queue, TxId::from_bytes([1; 32]), 10);
        let built = queue.due(h(11)).remove(0);
        queue.sent(&built, REFUND_TX, h(0));
        queue.settle(deep(), |_| false);
        assert!(queue.due(deep()).is_empty());
        assert_eq!(queue.sent_txids(), vec![REFUND_TX]);
    }

    #[test]
    fn two_equal_refunds_are_sent_one_at_a_time() {
        let payment = TxId::from_bytes([1; 32]);
        let mut queue = RefundQueue::default();
        admit(&mut queue, payment, 10);
        admit(&mut queue, payment, 10);

        let first = queue.due(deep()).remove(0);
        queue.sent(&first, REFUND_TX, h(50));
        assert_eq!(queue.due(deep()).len(), 1);
        assert_eq!(queue.sent_txids(), vec![REFUND_TX]);
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
