//! Consensus helpers for transaction authoring.
//!
//! NU6.2 changed the Orchard Action circuit (GHSA-jfw5-j458-pfv6). Proofs must
//! be produced with the proving key for the era of the chain tip the transaction
//! is built against — the same split `zebra-consensus` uses in `verifier_for`.

use orchard::circuit::OrchardCircuitVersion;
use zcash_protocol::consensus::BranchId;

/// Orchard circuit version for transactions authored under `branch_id`.
///
/// `branch_id` should come from [`BranchId::for_height`] at the spend/sweep tip.
/// NU5..=NU6.1 Orchard bundles use the historical insecure circuit; NU6.2+ use
/// the fixed circuit ([`OrchardCircuitVersion::FixedPostNu6_2`]).
pub fn orchard_circuit_version(branch_id: BranchId) -> OrchardCircuitVersion {
    use BranchId::*;
    match branch_id {
        Nu6_2 => OrchardCircuitVersion::FixedPostNu6_2,
        #[cfg(zcash_unstable = "nu7")]
        Nu7 => OrchardCircuitVersion::FixedPostNu6_2,
        #[cfg(zcash_unstable = "zfuture")]
        ZFuture => OrchardCircuitVersion::FixedPostNu6_2,
        Nu5 | Nu6 | Nu6_1 => OrchardCircuitVersion::InsecurePreNu6_2,
        // Orchard did not exist before NU5; kept for an exhaustive match only.
        Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy => {
            OrchardCircuitVersion::InsecurePreNu6_2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::{BlockHeight, Network};

    #[test]
    fn testnet_post_nu6_2_uses_fixed_circuit() {
        let branch = BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(4_069_676));
        assert_eq!(branch, BranchId::Nu6_2);
        assert_eq!(
            orchard_circuit_version(branch),
            OrchardCircuitVersion::FixedPostNu6_2
        );
    }

    #[test]
    fn testnet_pre_nu6_2_orchard_uses_insecure_circuit() {
        let branch = BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(4_051_999));
        assert_eq!(branch, BranchId::Nu6_1);
        assert_eq!(
            orchard_circuit_version(branch),
            OrchardCircuitVersion::InsecurePreNu6_2
        );
    }
}