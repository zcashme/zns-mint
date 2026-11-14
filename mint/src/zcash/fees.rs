//! The fee rate for every transaction the mint builds.

use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_protocol::value::Zatoshis;

/// Zatoshis per logical action. Zebra 7.0.0's mempool accepts it;
/// its `getstandardfee` reports it only from Mainnet height 3,590,000.
const MARGINAL_FEE: Zatoshis = Zatoshis::const_from_u64(1_000);

/// ZIP 317 at [`MARGINAL_FEE`] per logical action, with ZIP 317's grace
/// actions and transparent sizes.
pub fn fee_rule() -> FeeRule {
    let standard = FeeRule::standard();
    FeeRule::non_standard(
        MARGINAL_FEE,
        standard.grace_actions(),
        standard.p2pkh_standard_input_size(),
        standard.p2pkh_standard_output_size(),
    )
    .expect("upstream ZIP-317 sizes are nonzero")
}
