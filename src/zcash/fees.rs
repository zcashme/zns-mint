//! Node-recommended marginal fees, interpreted using the estimator's version.

use serde::Deserialize;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_protocol::value::Zatoshis;

use super::{CanonicalBlockSource, TransportError};

/// Zebra / Zakura `getstandardfee`: zatoshis per logical action, not per transaction.
#[derive(Debug, Deserialize)]
struct StandardFee {
    standard_fee: u64,
    version: u32,
}

impl StandardFee {
    fn into_rule(self) -> Result<FeeRule, TransportError> {
        if self.version != 0 {
            return Err(TransportError::BadNodeData(
                "unsupported fee estimator version",
            ));
        }
        let marginal_fee = Zatoshis::from_u64(self.standard_fee)
            .ok()
            .filter(|fee| *fee > Zatoshis::ZERO)
            .ok_or(TransportError::BadNodeData("invalid standard fee"))?;
        Ok(fee_rule(marginal_fee))
    }
}

/// ZIP 317 at `marginal_fee` per logical action. Version 0 retains ZIP-317
/// action accounting and grace actions.
pub fn fee_rule(marginal_fee: Zatoshis) -> FeeRule {
    let standard = FeeRule::standard();
    FeeRule::non_standard(
        marginal_fee,
        standard.grace_actions(),
        standard.p2pkh_standard_input_size(),
        standard.p2pkh_standard_output_size(),
    )
    .expect("upstream ZIP-317 sizes are nonzero")
}

impl CanonicalBlockSource {
    /// Fetches the current fee recommendation; failures never substitute a fixed rate.
    pub async fn standard_fee(&self) -> Result<FeeRule, TransportError> {
        self.rpc
            .send_request::<_, StandardFee>("getstandardfee", [(); 0])
            .await?
            .ok_or(TransportError::BadNodeData("getstandardfee returned null"))?
            .into_rule()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_primitives::transaction::fees::{transparent::InputSize, FeeRule as _};
    use zcash_protocol::consensus::{BlockHeight, TEST_NETWORK};

    #[test]
    fn rpc_rate_is_per_action_and_preserves_the_minimum() {
        let response: StandardFee =
            serde_json::from_str(r#"{"standard_fee":12345,"version":0}"#).unwrap();
        let rule = response.into_rule().unwrap();
        for (actions, expected) in [(0, 24_690), (2, 24_690), (3, 37_035), (7, 86_415)] {
            let fee = rule
                .fee_required(
                    &TEST_NETWORK,
                    BlockHeight::from_u32(4_465_026),
                    std::iter::empty::<InputSize>(),
                    std::iter::empty(),
                    0,
                    0,
                    0,
                    actions,
                )
                .unwrap();
            assert_eq!(fee.into_u64(), expected);
        }
    }

    #[test]
    fn unusable_rates_and_unknown_versions_are_rejected() {
        for (standard_fee, version) in [(0, 0), (u64::MAX, 0), (5000, 1)] {
            assert!(StandardFee {
                standard_fee,
                version
            }
            .into_rule()
            .is_err());
        }
        assert!(serde_json::from_str::<StandardFee>(r#"{"standard_fee":5000}"#).is_err());
        assert!(serde_json::from_str::<StandardFee>(r#"{"standard_fee":-1,"version":0}"#).is_err());
    }
}
