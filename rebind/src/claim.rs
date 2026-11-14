//! One bound claim per live name, carrying its newest UA and expiry, built
//! by the new mint's own `assemble::prepare`.

use std::collections::BTreeMap;

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zns_mint::mint::note::assemble::{self, PrepareError};
use zns_mint::mint::registry::Registry;
use zns_mint::mint::{Expiry, Name, NameNote, REGISTRY_ACCOUNT};
use zns_mint::wallet::Wallet;
use zns_mint::zcash::CanonicalBlockSource;
use zns_mint::{RegistryKeys, TreasuryKeys};

/// The claim that moves a live record: same name, same UA, same expiry,
/// no predecessor. Both formats share the name and expiry grammar.
pub fn of(record: &crate::registry::NameRecord) -> NameNote {
    let expiry = String::from_utf8(record.expires_at.field_bytes()).expect("expiry is ASCII");
    NameNote::Claim {
        name: Name::parse(record.name.as_str()).expect("FATAL: live name fails the name grammar"),
        ua: record.ua.clone(),
        expires_at: Expiry::parse(&expiry).expect("FATAL: live expiry fails the expiry grammar"),
    }
}

/// Whether the new law holds `claim`'s name with its exact UA and expiry.
pub fn held(fresh: &Registry, claim: &NameNote) -> bool {
    fresh.record(claim.name()).is_some_and(|record| {
        record.note.ua() == claim.ua() && record.note.expires_at() == claim.expires_at()
    })
}

/// One round, one block: up to [`crate::anchor::LANES`] claims, each on a
/// spendable anchor. A name with a claim built waits until that claim
/// confirms or expires, even if the node refused it.
#[allow(clippy::too_many_arguments)]
pub async fn round<P: Parameters + Send + 'static>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    fee_rule: &FeeRule,
    source: &CanonicalBlockSource,
    fresh: &Registry,
    claims: &[NameNote],
    in_flight: &mut BTreeMap<Name, BlockHeight>,
) {
    let tip = wallet.tip().block_height();
    let target_height = tip + 1;
    in_flight.retain(|_, expiry| *expiry > tip);
    let waiting: Vec<_> = claims
        .iter()
        .filter(|claim| !held(fresh, claim) && !in_flight.contains_key(claim.name()))
        .take(crate::anchor::LANES)
        .collect();
    for claim in waiting {
        let Some(anchor) = fresh.spendable_claim_anchor(|nf| {
            wallet
                .unspent_ironwood_note_by_nullifier(REGISTRY_ACCOUNT, nf, TargetHeight::from(tip))
                .is_some()
        }) else {
            return;
        };
        let (transaction, fee) = match assemble::prepare(
            network,
            wallet,
            treasury_keys,
            registry_keys,
            spend_prover,
            output_prover,
            fee_rule,
            claim.clone(),
            anchor,
            tip,
            target_height,
        ) {
            Ok(built) => built,
            Err(PrepareError::FeeUnfunded) => return,
            Err(error) => {
                tracing::error!(%error, name = claim.name().as_str(), "rebind: claim not built");
                continue;
            }
        };
        // In flight whatever submit answers: a claim mined during a retry
        // is answered "already in chain".
        wallet.record_sent(&transaction, target_height, fee);
        in_flight.insert(claim.name().clone(), transaction.expiry_height());
        if !source.submit(&transaction, "rebind claim").await {
            tracing::error!(
                name = claim.name().as_str(),
                txid = %transaction.txid(),
                "rebind: the node refused a claim"
            );
        }
    }
}
