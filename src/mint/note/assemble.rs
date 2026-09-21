//! The write path: one prepare function resolves the law's NameNote
//! against the wallet and stages, proves, signs, and records the
//! transaction.

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use super::NameNote;
use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// Builds and records a Name Note transaction for any action.
/// `authority_nf` is the claim anchor or the predecessor; Treasury fee
/// notes cover the fee. Returns `None` while the authority is unavailable
/// or the fee is unfunded; the caller retries next tip.
#[allow(clippy::too_many_arguments)]
pub fn prepare<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    note: NameNote,
    authority_nf: orchard::note::Nullifier,
    tip: BlockHeight,
    target_height: BlockHeight,
) -> Option<Transaction> {
    let authority = wallet.unspent_ironwood_note_by_nullifier(
        REGISTRY_ACCOUNT,
        authority_nf,
        TargetHeight::from(tip),
    )?;

    let excluded = [*authority.internal_note_id()];
    let fixed_spends = 1;
    let fixed_outputs = if note.action().is_claim() {
        3 // NameNote + successor anchor + change
    } else {
        2 // NameNote + change
    };

    // Treasury funding: largest first, so fewest notes fund the fee.
    let mut candidates = wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
    candidates.retain(|n| !excluded.contains(n.internal_note_id()));
    candidates.sort_by_key(|n| std::cmp::Reverse(n.note().value().inner()));

    let mut fee_notes = Vec::new();
    let mut fee_funding = Zatoshis::ZERO;
    let transaction_fee = loop {
        let action_count = (fixed_spends + fee_notes.len()).max(fixed_outputs).max(2);
        let f = fee(network, target_height, action_count);
        if fee_funding >= f {
            break f;
        }
        let candidate = candidates.get(fee_notes.len())?;
        fee_funding = (fee_funding + zatoshis(candidate))
            .expect("Treasury balance fits in the Zcash monetary range");
        fee_notes.push((
            *candidate.note(),
            wallet
                .witness(candidate, tip)
                .expect("FATAL: owned note has no witness at the applied tip"),
        ));
    };

    // Change = every Treasury input value − the fee.
    let treasury_change =
        (fee_funding - transaction_fee).expect("selection guarantees fee coverage");

    let anchor = wallet.anchor_at(tip);
    let authority_note = *authority.note();
    let authority_path = wallet
        .witness(&authority, tip)
        .expect("FATAL: owned note has no witness at the applied tip");

    let registry_fvk = registry_keys.orchard_fvk();
    let treasury_fvk = treasury_keys.orchard_fvk();

    let mut builder = Builder::new(
        network.clone(),
        target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );

    // Authority spend: claims spend the anchor as an ordinary ironwood
    // spend; updates and releases spend the predecessor as a ZNS spend
    // with its content-derived commitment openings.
    if note.action().is_claim() {
        builder
            .add_ironwood_spend::<FeeError>(registry_fvk.clone(), authority_note, authority_path)
            .expect("FATAL: valid Registry claim anchor rejected by the builder");
    } else {
        let (rcm, psi) = predecessor_opening(network, wallet, &authority);
        builder
            .add_zns_spend::<FeeError>(
                registry_fvk.clone(),
                authority_note,
                authority_path,
                rcm,
                psi,
            )
            .expect("FATAL: valid Registry predecessor rejected by the builder");
    }

    // Fee notes.
    for (note, path) in fee_notes {
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), note, path)
            .expect("FATAL: valid Treasury fee note rejected by the builder");
    }

    // The successor Name Note: a zero-value ZNS output whose commitment is
    // derived from the transition content.
    let memo = note.encode(network);
    let rcm = note.rcm(network);
    let psi = note.psi(network);
    let opening = orchard::note::NoteCommitTrapdoor::from_inner(rcm);
    builder
        .add_zns_output::<FeeError>(
            Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
            registry_fvk.address_at(0u32, orchard::keys::Scope::External),
            Zatoshis::ZERO,
            memo,
            opening,
            psi,
        )
        .expect("FATAL: valid Name Note rejected by the builder");

    // Claims also stage a successor anchor: an ordinary zero-value Registry
    // output that authorizes the next claim.
    if note.action().is_claim() {
        builder
            .add_ironwood_output::<FeeError>(
                Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
                registry_fvk.address_at(0u32, orchard::keys::Scope::External),
                Zatoshis::ZERO,
                zcash_protocol::memo::MemoBytes::empty(),
            )
            .expect("FATAL: valid successor anchor rejected by the builder");
    }

    // Treasury change.
    if treasury_change > Zatoshis::ZERO {
        builder
            .add_ironwood_output::<FeeError>(
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                treasury_change,
                zcash_protocol::memo::MemoBytes::empty(),
            )
            .expect("FATAL: valid Treasury change rejected by the builder");
    }

    let built = builder
        .build(
            &Default::default(),
            &[],
            &[
                orchard::keys::SpendAuthorizingKey::from(treasury_keys.orchard_spending_key()),
                orchard::keys::SpendAuthorizingKey::from(registry_keys.orchard_spending_key()),
            ],
            rand::rngs::OsRng,
            spend_prover,
            output_prover,
            &StandardFeeRule::Zip317,
        )
        .expect("FATAL: transaction proving or signing failed");
    let transaction = built.transaction().clone();
    wallet.record_sent(&transaction, target_height, transaction_fee);
    Some(transaction)
}

fn zatoshis(note: &ReceivedNote<NoteId, orchard::note::Note>) -> Zatoshis {
    Zatoshis::from_u64(note.note().value().inner())
        .expect("note values fit in the Zcash monetary range")
}

fn predecessor_opening<P: Parameters>(
    network: &P,
    wallet: &Wallet<P>,
    note: &ReceivedNote<NoteId, orchard::note::Note>,
) -> (
    orchard::note::NoteCommitTrapdoor,
    pasta_curves::pallas::Base,
) {
    let memo = wallet
        .get_memo(*note.internal_note_id())
        .expect("FATAL: predecessor memo lookup failed");
    let payload = match memo {
        Some(zcash_protocol::memo::Memo::Future(bytes)) => {
            NameNote::decode(network, bytes.as_array())
        }
        _ => None,
    }
    .expect("FATAL: predecessor memo does not open its Name Note");
    (
        orchard::note::NoteCommitTrapdoor::from_inner(payload.rcm(network)),
        payload.psi(network),
    )
}

fn fee<P: Parameters>(
    network: &P,
    target_height: BlockHeight,
    ironwood_actions: usize,
) -> Zatoshis {
    StandardFeeRule::Zip317
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            ironwood_actions,
        )
        .expect("FATAL: ZIP-317 fee is not representable")
}
