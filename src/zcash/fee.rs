//! The node's ZIP 317 marginal fee.
//!
//! `getstandardfee` returns the rate wallets should pay per logical action.
//! Outgoing transactions and dust selection use that rate. The ZIP 317
//! constant stands until the node answers, including a node with no method.

use zcash_primitives::transaction::fees::zip317::{self, FeeRule};
use zcash_protocol::value::Zatoshis;

use super::{CanonicalBlockSource, JsonRpc, TransportError};

/// The rate `getstandardfee` reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardFee {
    /// Zatoshis per logical action.
    pub marginal: Zatoshis,
    /// Estimator version. The rate is what transaction construction uses.
    pub version: u32,
}

#[derive(Debug, serde::Deserialize)]
struct StandardFeeResponse {
    standard_fee: u64,
    version: u32,
}

impl CanonicalBlockSource {
    /// The node's recommended marginal fee for this tip.
    pub async fn standard_fee(&self) -> Result<StandardFee, TransportError> {
        self.rpc.standard_fee().await
    }
}

impl JsonRpc {
    /// The node's recommended marginal fee. A node with no `getstandardfee`
    /// method answers with the ZIP 317 constant.
    pub(crate) async fn standard_fee(&self) -> Result<StandardFee, TransportError> {
        match self
            .send_request::<_, StandardFeeResponse>("getstandardfee", [(); 0])
            .await
        {
            Ok(Some(response)) => parse_standard_fee(response.standard_fee, response.version),
            Ok(None) => Err(TransportError::BadNodeData("getstandardfee")),
            Err(TransportError::Rpc(rpc)) if rpc.is_method_missing() => Ok(StandardFee {
                marginal: zip317::MARGINAL_FEE,
                version: 0,
            }),
            Err(error) => Err(error),
        }
    }
}

/// A positive in-range `standard_fee`. Zero and a value above `MAX_MONEY`
/// are refused.
pub(crate) fn parse_standard_fee(
    standard_fee: u64,
    version: u32,
) -> Result<StandardFee, TransportError> {
    let marginal = Zatoshis::from_u64(standard_fee)
        .map_err(|_| TransportError::BadNodeData("getstandardfee"))?;
    if marginal.into_u64() == 0 {
        return Err(TransportError::BadNodeData("getstandardfee"));
    }
    Ok(StandardFee { marginal, version })
}

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

#[cfg(test)]
mod tests {
    use zcash_primitives::transaction::fees::FeeRule as _;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork};

    use super::*;

    #[test]
    fn a_zero_standard_fee_is_refused() {
        assert!(parse_standard_fee(0, 1).is_err());
    }

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
