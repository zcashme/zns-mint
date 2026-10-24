//! Refunds owed by the run loop.
//!
//! A refund is a Treasury payment, built once from any Treasury notes and
//! the wallet's from there, like a sweep. Its amount is fixed when it is
//! admitted: the payment less any penalty and the withheld fee,
//! `REFUND_FEE_ACTIONS` at the node's rate, so the payer covers the fee.
//! A wrong access code also keeps 1% of the quote. The queue is memory: a
//! restart forgets a refund that has not been built.

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

/// One refund the Treasury still has to build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refund {
    payment: TxId,
    recipient: UnifiedAddress,
    /// What the Treasury pays back: the payment less any penalty and the
    /// withheld fee.
    amount: Zatoshis,
    name: Name,
    height: BlockHeight,
}

impl Refund {
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

/// Refunds owed, in admission order. An entry leaves when its refund is
/// built (`paid`) or when a reorg orphans its payment's block
/// (`truncate_to`); nothing else removes it.
#[derive(Clone, Debug, Default)]
pub struct RefundQueue {
    owed: Vec<Refund>,
}

impl RefundQueue {
    pub fn new() -> Self {
        Self { owed: Vec::new() }
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
        self.owed.push(Refund {
            payment: txid,
            recipient: recipient.clone(),
            amount,
            name: name.clone(),
            height,
        });
        true
    }

    /// Every refund still owed, in admission order.
    pub fn due(&self) -> Vec<Refund> {
        self.owed.clone()
    }

    /// The refund for `payment` is built. The only removal besides reorg
    /// truncation.
    pub fn paid(&mut self, payment: TxId) {
        self.owed.retain(|refund| refund.payment != payment);
    }

    /// What the refunds owed will pay out. The sweep leaves this in the
    /// Treasury. An overflow holds back everything.
    pub fn owed_total(&self) -> Zatoshis {
        self.owed
            .iter()
            .map(|refund| refund.amount)
            .sum::<Option<Zatoshis>>()
            .unwrap_or(Zatoshis::const_from_u64(MAX_MONEY))
    }

    /// Reorg: entries whose payment's block was orphaned fall with it.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) {
        self.owed.retain(|refund| refund.height <= ancestor);
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

    /// Owes 50,000 zats for a 100,000-zat payment at `height`.
    fn admit(queue: &mut RefundQueue, payment: TxId, height: u32) -> bool {
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
        let mut queue = RefundQueue::new();
        assert!(admit(&mut queue, txid, 10));
        assert_eq!(queue.owed_total(), (zats(100_000) - withheld()).unwrap());
        assert_eq!(queue.due()[0].amount(), zats(50_000));

        let mut queue = RefundQueue::new();
        let price = zats(100_000);
        let penalty = access_code_penalty(price);
        assert!(queue.admit(
            &FeeRule::standard(),
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
    fn a_refund_leaves_when_built_or_when_its_payment_is_orphaned() {
        let kept = TxId::from_bytes([1; 32]);
        let orphaned = TxId::from_bytes([2; 32]);
        let mut queue = RefundQueue::new();
        assert!(admit(&mut queue, kept, 10));
        assert!(admit(&mut queue, orphaned, 30));
        assert_eq!(queue.owed_total(), zats(100_000));

        queue.truncate_to(BlockHeight::from_u32(20));
        let left: Vec<_> = queue.due().iter().map(Refund::payment).collect();
        assert_eq!(left, vec![kept]);
        assert_eq!(queue.owed_total(), zats(50_000));

        queue.paid(kept);
        assert!(queue.due().is_empty());
        assert_eq!(queue.owed_total(), Zatoshis::ZERO);
    }
}
