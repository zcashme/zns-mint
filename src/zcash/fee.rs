//! The ZIP 317 fee rule at a marginal rate.

use zcash_primitives::transaction::fees::zip317::{self, FeeRule};
use zcash_protocol::value::Zatoshis;

/// ZIP 317 fee rule at `marginal`. Grace actions and transparent sizes stay
/// the ZIP 317 constants. A marginal rate below the constant is what the
/// node reports when it accepts the lower schedule.
pub(crate) fn fee_rule(marginal: Zatoshis) -> FeeRule {
    FeeRule::non_standard(
        marginal,
        zip317::GRACE_ACTIONS,
        zip317::P2PKH_STANDARD_INPUT_SIZE,
        zip317::P2PKH_STANDARD_OUTPUT_SIZE,
    )
    .expect("ZIP 317 standard input and output sizes are non-zero")
}

/// Fee for a refund: one shielded spend and one shielded output.
///
/// That shape is one logical action. Grace actions raise it to the
/// ZIP 317 minimum, two actions at the marginal rate.
pub(crate) fn single_action_fee(marginal: Zatoshis) -> Option<Zatoshis> {
    use zcash_primitives::transaction::fees::FeeRule as _;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork};

    fee_rule(marginal)
        .fee_required(
            &MainNetwork,
            BlockHeight::from_u32(1),
            std::iter::empty(),
            std::iter::empty(),
            0,
            0,
            0,
            1,
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use zcash_primitives::transaction::fees::FeeRule as _;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork};

    use super::*;

    #[test]
    fn two_grace_actions_cost_twice_the_reported_rate() {
        let fee = fee_rule(Zatoshis::const_from_u64(1_000))
            .fee_required(
                &MainNetwork,
                BlockHeight::from_u32(1),
                std::iter::empty(),
                std::iter::empty(),
                0,
                0,
                0,
                0,
            )
            .expect("fee");
        assert_eq!(fee, Zatoshis::const_from_u64(2_000));
    }
}
