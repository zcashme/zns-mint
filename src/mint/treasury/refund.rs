//! Refunds owed by the run loop.
//!
//! A refund is a Treasury payment, funded from any Treasury notes once the
//! payment it returns is buried. Its amount is fixed when it is admitted:
//! the payment less any penalty and the withheld fee, `REFUND_FEE_ACTIONS`
//! at the node's rate, so the payer covers the fee. A wrong access code
//! also keeps 1% of the quote. The queue is memory: a restart forgets a
//! refund that has not been mined.

use std::num::NonZeroU64;

use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{Zatoshis, MAX_MONEY};

use crate::mint::{Name, UnifiedAddress};

/// Actions' worth of fee withheld from every refund. The Treasury never
/// adds to a refund's fee; a proposal that would charge more waits.
pub const REFUND_FEE_ACTIONS: usize = 10;

/// `paid` minus the withheld refund fee, when that remainder is positive.
pub fn refund_output(paid: Zatoshis, fee_rule: &FeeRule) -> Option<Zatoshis> {
    let fee = (fee_rule.marginal_fee() * REFUND_FEE_ACTIONS)?;
    (paid - fee).filter(|output| *output > Zatoshis::ZERO)
}

/// One percent of `price`, rounded down to a zat.
pub fn access_code_penalty(price: Zatoshis) -> Zatoshis {
    price / NonZeroU64::new(100).expect("100 is non-zero")
}

/// One refund the Treasury still has to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refund {
    payment: TxId,
    recipient: UnifiedAddress,
    /// What the Treasury pays back: the payment less any penalty and the
    /// withheld fee.
    amount: Zatoshis,
    name: Name,
    height: BlockHeight,
    /// The refund transaction, once the node has accepted one.
    sent: Option<TxId>,
}

impl Refund {
    fn new(
        payment: TxId,
        recipient: UnifiedAddress,
        amount: Zatoshis,
        name: Name,
        height: BlockHeight,
    ) -> Self {
        Self {
            payment,
            recipient,
            amount,
            name,
            height,
            sent: None,
        }
    }

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

    /// The height of the block that mined the payment.
    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn sent(&self) -> Option<TxId> {
        self.sent
    }
}

/// Refunds owed, in admission order. A reorg drops those whose payment
/// block was orphaned, and keeps a submitted transaction id so a replay
/// of that payment can restore it. A refund mined at or below the rewind
/// floor is removed.
#[derive(Clone, Debug, Default)]
pub struct RefundQueue {
    owed: Vec<Refund>,
    /// Submitted refunds whose payment was orphaned.
    orphaned: Vec<Refund>,
}

impl RefundQueue {
    pub fn new() -> Self {
        Self {
            owed: Vec::new(),
            orphaned: Vec::new(),
        }
    }

    /// Owes `recipient` what `paid` leaves after `penalty` and the withheld
    /// fee. A payment that leaves nothing is kept. Returns whether a refund
    /// is owed.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        fee_rule: &FeeRule,
        txid: TxId,
        recipient: &UnifiedAddress,
        name: &Name,
        height: BlockHeight,
        paid: Zatoshis,
        penalty: Zatoshis,
        reason: &'static str,
    ) -> bool {
        let Some(amount) = (paid - penalty).and_then(|net| refund_output(net, fee_rule)) else {
            tracing::info!(
                %txid,
                name = %name.as_str(),
                reason,
                paid = paid.into_u64(),
                penalty = penalty.into_u64(),
                "payment kept"
            );
            return false;
        };
        tracing::info!(
            %txid,
            name = %name.as_str(),
            reason,
            paid = paid.into_u64(),
            penalty = penalty.into_u64(),
            refund = amount.into_u64(),
            "payment refund"
        );
        self.record(Refund::new(
            txid,
            recipient.clone(),
            amount,
            name.clone(),
            height,
        ));
        true
    }

    /// Records `refund` unless that payment is already owed. A replay of an
    /// orphaned payment keeps the refund transaction that paid it back.
    fn record(&mut self, mut refund: Refund) {
        if self.owed.iter().any(|owed| owed.payment == refund.payment) {
            return;
        }
        if let Some(i) = self
            .orphaned
            .iter()
            .position(|old| old.payment == refund.payment)
        {
            refund.sent = self.orphaned.remove(i).sent;
        }
        self.owed.push(refund);
    }

    /// Every refund still owed, in admission order.
    pub fn due(&self) -> Vec<Refund> {
        self.owed.clone()
    }

    /// What the refunds not yet sent will pay out. The sweep leaves this
    /// in the Treasury. An overflow holds back everything.
    pub fn owed_total(&self) -> Zatoshis {
        self.owed
            .iter()
            .filter(|refund| refund.sent.is_none())
            .map(|refund| refund.amount)
            .sum::<Option<Zatoshis>>()
            .unwrap_or(Zatoshis::const_from_u64(MAX_MONEY))
    }

    /// Names still waiting on a refund. A mined refund transaction is omitted.
    pub fn names<'a>(
        &'a self,
        mined: impl Fn(TxId) -> bool + 'a,
    ) -> impl Iterator<Item = &'a Name> + 'a {
        self.owed
            .iter()
            .filter(move |refund| match refund.sent {
                Some(txid) => !mined(txid),
                None => true,
            })
            .map(|refund| &refund.name)
    }

    /// Records the refund transaction the node accepted. The entry stays.
    pub fn mark_sent(&mut self, payment: TxId, txid: TxId) {
        if let Some(refund) = self
            .owed
            .iter_mut()
            .find(|refund| refund.payment == payment)
        {
            refund.sent = Some(txid);
        }
    }

    /// Forgets a refund transaction that expired unmined. The entry stays.
    pub fn clear_sent(&mut self, payment: TxId) {
        if let Some(refund) = self
            .owed
            .iter_mut()
            .find(|refund| refund.payment == payment)
        {
            refund.sent = None;
        }
    }

    /// Drops refunds whose transaction was mined at or below `floor`, and
    /// returns their payments.
    pub fn prune_buried(
        &mut self,
        floor: BlockHeight,
        mined_at: impl Fn(TxId) -> Option<BlockHeight>,
    ) -> Vec<TxId> {
        let mut dropped = Vec::new();
        self.owed.retain(|refund| {
            let buried = refund
                .sent
                .is_some_and(|txid| mined_at(txid).is_some_and(|height| height <= floor));
            if buried {
                dropped.push(refund.payment);
            }
            !buried
        });
        dropped
    }

    /// Drops stashed refund transactions for which `done` is true.
    pub fn prune_orphaned(&mut self, done: impl Fn(TxId) -> bool) {
        self.orphaned
            .retain(|refund| refund.sent.is_none_or(|txid| !done(txid)));
    }

    /// Drops refunds whose payment was orphaned. A submitted transaction
    /// id is kept for a replay of that payment. Returns the dropped payments.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) -> Vec<TxId> {
        let mut dropped = Vec::new();
        let mut still_owed = Vec::new();
        for refund in self.owed.drain(..) {
            if refund.height <= ancestor {
                still_owed.push(refund);
            } else {
                dropped.push(refund.payment);
                if refund.sent.is_some() {
                    self.orphaned.retain(|old| old.payment != refund.payment);
                    self.orphaned.push(refund);
                }
            }
        }
        self.owed = still_owed;
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;

    /// The standard rate's withheld fee: 50,000 zats.
    fn withheld() -> Zatoshis {
        (MARGINAL_FEE * REFUND_FEE_ACTIONS).unwrap()
    }

    fn zats(n: u64) -> Zatoshis {
        Zatoshis::const_from_u64(n)
    }

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

    fn owed(payment: TxId, height: u32) -> Refund {
        Refund::new(
            payment,
            ua(),
            zats(50_000),
            alice(),
            BlockHeight::from_u32(height),
        )
    }

    #[test]
    fn an_admitted_refund_is_the_payment_less_the_penalty_and_the_fee() {
        let standard = FeeRule::standard();
        let txid = TxId::from_bytes([1; 32]);
        let mut queue = RefundQueue::new();
        assert!(queue.admit(
            &standard,
            txid,
            &ua(),
            &alice(),
            BlockHeight::from_u32(10),
            zats(80_000),
            Zatoshis::ZERO,
            "underpaid",
        ));
        assert_eq!(queue.owed_total(), (zats(80_000) - withheld()).unwrap());
        assert_eq!(queue.due()[0].amount(), zats(30_000));

        let mut queue = RefundQueue::new();
        let price = zats(100_000);
        let penalty = access_code_penalty(price);
        assert!(queue.admit(
            &standard,
            txid,
            &ua(),
            &alice(),
            BlockHeight::from_u32(10),
            price,
            penalty,
            "wrong access code",
        ));
        assert_eq!(queue.due()[0].amount(), zats(49_000));
    }

    #[test]
    fn a_payment_that_does_not_exceed_the_fee_is_kept() {
        let standard = FeeRule::standard();
        let mut queue = RefundQueue::new();
        for paid in [withheld(), (withheld() - zats(1)).unwrap()] {
            assert!(!queue.admit(
                &standard,
                TxId::from_bytes([1; 32]),
                &ua(),
                &alice(),
                BlockHeight::from_u32(10),
                paid,
                Zatoshis::ZERO,
                "underpaid",
            ));
        }
        assert!(queue.due().is_empty());
    }

    #[test]
    fn a_wrong_access_code_keeps_one_percent_then_the_fee() {
        let price = zats(100_000);
        let penalty = zats(1_000);
        let fee = withheld();
        let paid = price;
        assert_eq!(access_code_penalty(price), penalty);
        let net = (paid - penalty).unwrap();
        assert_eq!(refund_output(net, &FeeRule::standard()), net - fee);
    }

    #[test]
    fn a_payment_that_does_not_cover_the_penalty_and_the_fee_is_kept() {
        let price = zats(100_000);
        let penalty = access_code_penalty(price);
        let fee = withheld();
        let covers_the_penalty = (penalty + fee).unwrap();
        assert_eq!(
            refund_output(
                (covers_the_penalty - penalty).unwrap(),
                &FeeRule::standard()
            ),
            None
        );
        assert!((penalty - zats(1) - penalty).is_none());
    }

    #[test]
    fn a_lower_node_rate_refunds_a_payment_the_standard_rate_keeps() {
        let paid = zats(20_000);
        let node = crate::zcash::fees::fee_rule(zats(1_000));
        assert_eq!(refund_output(paid, &node), Some(zats(10_000)));
        assert_eq!(refund_output(paid, &FeeRule::standard()), None);
    }

    #[test]
    fn a_submitted_refund_stays_until_its_transaction_is_cleared() {
        let payment = TxId::from_bytes([1; 32]);
        let mut queue = RefundQueue::new();
        queue.record(owed(payment, 10));
        assert_eq!(queue.owed_total(), zats(50_000));
        let txid = TxId::from_bytes([2; 32]);
        queue.mark_sent(payment, txid);
        assert_eq!(queue.owed_total(), Zatoshis::ZERO);
        assert_eq!(queue.due().len(), 1);
        assert_eq!(queue.due()[0].sent(), Some(txid));
        assert_eq!(queue.names(|_| false).count(), 1);
        assert_eq!(queue.names(|_| true).count(), 0);
        queue.clear_sent(payment);
        assert_eq!(queue.due()[0].sent(), None);
        assert_eq!(queue.names(|_| true).count(), 1);
        assert_eq!(queue.owed_total(), zats(50_000));
    }

    #[test]
    fn a_mined_refund_leaves_once_it_is_at_or_below_the_rewind_floor() {
        let buried = TxId::from_bytes([1; 32]);
        let recent = TxId::from_bytes([3; 32]);
        let unsent = TxId::from_bytes([4; 32]);
        let mut queue = RefundQueue::new();
        for (payment, height) in [(buried, 10), (recent, 30), (unsent, 30)] {
            queue.record(owed(payment, height));
        }
        let buried_tx = TxId::from_bytes([2; 32]);
        let recent_tx = TxId::from_bytes([5; 32]);
        queue.mark_sent(buried, buried_tx);
        queue.mark_sent(recent, recent_tx);
        let floor = BlockHeight::from_u32(20);
        let dropped = queue.prune_buried(floor, |txid| {
            if txid == buried_tx {
                Some(BlockHeight::from_u32(20))
            } else if txid == recent_tx {
                Some(BlockHeight::from_u32(21))
            } else {
                None
            }
        });
        assert_eq!(dropped, vec![buried]);
        let left: Vec<_> = queue
            .due()
            .into_iter()
            .map(|refund| refund.payment())
            .collect();
        assert_eq!(left, vec![recent, unsent]);
    }

    #[test]
    fn a_replayed_payment_keeps_the_refund_transaction() {
        let payment = TxId::from_bytes([1; 32]);
        let mut queue = RefundQueue::new();
        queue.record(owed(payment, 30));
        let txid = TxId::from_bytes([2; 32]);
        queue.mark_sent(payment, txid);
        assert_eq!(queue.truncate_to(BlockHeight::from_u32(20)), vec![payment]);
        assert!(queue.due().is_empty());
        queue.record(owed(payment, 40));
        assert_eq!(queue.due()[0].sent(), Some(txid));
        queue.prune_orphaned(|_| true);
        assert_eq!(queue.due()[0].sent(), Some(txid));
    }
}
