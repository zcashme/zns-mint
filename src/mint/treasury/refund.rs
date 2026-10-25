//! Refunds due from the run loop.
//!
//! A refund is a Treasury payment, built once from any Treasury notes and
//! the wallet's from there, like a sweep. Its amount is fixed when it is
//! admitted: the payment less any penalty and the withheld fee,
//! `REFUND_FEE_ACTIONS` at the node's rate, so the payer covers the fee.
//! A wrong access code also keeps 1% of the quote. A refund is built on
//! the tip pass after its payment's block.

use std::num::NonZeroU64;

use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::mint::{Name, UnifiedAddress};

/// Actions' worth of fee withheld from every refund.
const REFUND_FEE_ACTIONS: usize = 10;

/// `paid` minus the withheld refund fee, when that remainder is positive.
fn refund_output(paid: Zatoshis, fee_rule: &FeeRule) -> Option<Zatoshis> {
    let fee = (fee_rule.marginal_fee() * REFUND_FEE_ACTIONS)?;
    (paid - fee).filter(|output| *output > Zatoshis::ZERO)
}

/// One percent of `price`, rounded down to a zat.
pub fn access_code_penalty(price: Zatoshis) -> Zatoshis {
    price / NonZeroU64::new(100).expect("100 is non-zero")
}

/// One refund due: the payment it answers, where it goes, how much.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundRequest {
    payment: TxId,
    recipient: UnifiedAddress,
    /// What the Treasury pays back: the payment less any penalty and the
    /// withheld fee.
    amount: Zatoshis,
    name: Name,
    height: BlockHeight,
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
}

/// Refunds due, in admission order. A refund leaves when it is built
/// (`paid`) or when a reorg orphans its payment's block (`truncate_to`);
/// nothing else removes it.
#[derive(Clone, Debug, Default)]
pub struct RefundQueue {
    refunds_due: Vec<RefundRequest>,
}

impl RefundQueue {
    /// Owes `recipient` what `paid` leaves after `penalty` and the withheld
    /// fee. A payment that leaves nothing is kept.
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
    ) {
        let Some(amount) = (paid - penalty).and_then(|net| refund_output(net, fee_rule)) else {
            tracing::info!(
                %txid,
                name = %name.as_str(),
                reason,
                paid = paid.into_u64(),
                penalty = penalty.into_u64(),
                "payment kept"
            );
            return;
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
        self.refunds_due.push(RefundRequest {
            payment: txid,
            recipient: recipient.clone(),
            amount,
            name: name.clone(),
            height,
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

    /// `built` is built. One transaction can carry several refunds, so
    /// only the entry equal to `built` leaves.
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

    /// A tip far past every test payment.
    fn deep() -> BlockHeight {
        BlockHeight::from_u32(1_000)
    }

    /// Owes 50,000 zats for a 100,000-zat payment at `height`.
    fn admit(queue: &mut RefundQueue, payment: TxId, height: u32) {
        queue.admit(
            &FeeRule::standard(),
            payment,
            &ua(),
            &alice(),
            BlockHeight::from_u32(height),
            zats(100_000),
            Zatoshis::ZERO,
            "underpaid",
        )
    }

    #[test]
    fn an_admitted_refund_is_the_payment_less_the_penalty_and_the_fee() {
        let txid = TxId::from_bytes([1; 32]);
        let mut queue = RefundQueue::default();
        admit(&mut queue, txid, 10);
        assert_eq!(queue.due(deep())[0].amount(), zats(50_000));

        let mut queue = RefundQueue::default();
        let price = zats(100_000);
        let penalty = access_code_penalty(price);
        queue.admit(
            &FeeRule::standard(),
            txid,
            &ua(),
            &alice(),
            BlockHeight::from_u32(10),
            price,
            penalty,
            "wrong access code",
        );
        assert_eq!(queue.due(deep())[0].amount(), zats(49_000));
    }

    #[test]
    fn a_payment_that_does_not_exceed_the_fee_is_kept() {
        let standard = FeeRule::standard();
        let mut queue = RefundQueue::default();
        for paid in [withheld(), (withheld() - zats(1)).unwrap()] {
            queue.admit(
                &standard,
                TxId::from_bytes([1; 32]),
                &ua(),
                &alice(),
                BlockHeight::from_u32(10),
                paid,
                Zatoshis::ZERO,
                "underpaid",
            );
        }
        let penalty = access_code_penalty(zats(100_000));
        queue.admit(
            &standard,
            TxId::from_bytes([1; 32]),
            &ua(),
            &alice(),
            BlockHeight::from_u32(10),
            (penalty + withheld()).unwrap(),
            penalty,
            "wrong access code",
        );
        assert!(queue.due(deep()).is_empty());
    }

    #[test]
    fn a_lower_node_rate_refunds_a_payment_the_standard_rate_keeps() {
        let paid = zats(20_000);
        let node = crate::zcash::fees::fee_rule(zats(1_000));
        assert_eq!(refund_output(paid, &node), Some(zats(10_000)));
        assert_eq!(refund_output(paid, &FeeRule::standard()), None);
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
            &FeeRule::standard(),
            txid,
            &ua(),
            &alice(),
            BlockHeight::from_u32(10),
            zats(200_000),
            Zatoshis::ZERO,
            "underpaid",
        );

        let second = queue.due(deep()).remove(1);
        queue.paid(&second);
        let left = queue.due(deep());
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].amount(), zats(50_000));
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
