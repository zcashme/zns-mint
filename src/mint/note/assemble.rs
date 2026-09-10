//! The write path: one prepare function resolves the law's NameNote
//! against the wallet — the authority note, the funding note, Treasury fee
//! notes — and stages, proves, signs, and records the full transaction.

use zcash_client_backend::data_api::locking::{LockOwner, OutputLockStore as _};
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::wallet::{NoteId, OutputRef, ReceivedNote};
use zcash_primitives::transaction::builder::{
    BuildConfig, Builder, BundlePadding, DEFAULT_TX_EXPIRY_DELTA,
};
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use super::NameNote;
use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::{Action, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// Why a transaction could not be prepared. Every variant is transient —
/// prepare re-fires each tip and succeeds once the world allows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareError {
    /// The claim anchor or predecessor note is not selectable: a rival
    /// transaction holds it until expiry, or consumed it on chain.
    AuthorityUnavailable,
    /// The Treasury could not fund the fee from eligible notes.
    InsufficientFunds,
}

/// Builds and records a Name Note transaction for any action — claim,
/// update, or release. Resolves the authority note (anchor or predecessor)
/// by nullifier, selects Treasury fee notes, locks every input, stages the
/// ZNS outputs, proves, signs with both authorities, and records.
///
/// `authority_nf` is the claim anchor (claim) or the predecessor (update,
/// release). `funding` is the inbound payment (claim), the echo (update,
/// echo-path release), or `None` (lifecycle release).
///
/// Returns `None` when the authority is unavailable or the Treasury cannot
/// fund the fee; the lane retries next tip.
#[allow(clippy::too_many_arguments)]
pub fn prepare<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    note: NameNote,
    authority_nf: orchard::note::Nullifier,
    funding: Option<&ReceivedNote<NoteId, orchard::note::Note>>,
    tip: BlockHeight,
    target_height: BlockHeight,
) -> Option<Transaction> {
    let authority = wallet.unspent_ironwood_note_by_nullifier(
        REGISTRY_ACCOUNT,
        authority_nf,
        TargetHeight::from(tip),
    )?;

    // The funding note (payment or echo) is a fixed spend alongside the
    // authority; the fee loop selects from the rest.
    let mut excluded = vec![*authority.internal_note_id()];
    if let Some(funding) = funding {
        excluded.push(*funding.internal_note_id());
    }
    let fixed_spends = 1 + usize::from(funding.is_some());
    let fixed_outputs = match note.action() {
        Action::Claim => 3, // NameNote + successor anchor + change
        _ => 2,             // NameNote + change
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
            candidate.note().clone(),
            wallet
                .witness(candidate, tip)
                .expect("FATAL: owned note has no witness at the applied tip"),
        ));
    };

    // Change = every Treasury input value − the fee.
    let funding_value = funding.map(zatoshis).unwrap_or(Zatoshis::ZERO);
    let treasury_change = (funding_value + fee_funding)
        .and_then(|total| total - transaction_fee)
        .expect("selection guarantees fee coverage");

    // Lock every selected input until the transaction expires.
    let locked_refs = std::iter::once(OutputRef::from(*authority.internal_note_id()))
        .chain(funding.iter().map(|f| OutputRef::from(*f.internal_note_id())))
        .chain(
            candidates
                .iter()
                .take(fee_notes.len())
                .map(|n| OutputRef::from(*n.internal_note_id())),
        )
        .collect::<Vec<_>>();
    wallet
        .lock_outputs(
            &locked_refs,
            LockOwner::random(&mut rand::rngs::OsRng),
            target_height + DEFAULT_TX_EXPIRY_DELTA,
        )
        .expect("FATAL: wallet rejected the input lock");

    let anchor = wallet.anchor_at(tip);
    let authority_note = authority.note().clone();
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
    match note.action() {
        Action::Claim => {
            builder
                .add_ironwood_spend::<FeeError>(
                    registry_fvk.clone(),
                    authority_note,
                    authority_path,
                )
                .expect("FATAL: valid Registry claim anchor rejected by the builder");
        }
        _ => {
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
    }

    // The funding note (payment or echo) is a fixed Treasury spend.
    if let Some(funding) = funding {
        let funding_note = funding.note().clone();
        let funding_path = wallet
            .witness(funding, tip)
            .expect("FATAL: owned note has no witness at the applied tip");
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), funding_note, funding_path)
            .expect("FATAL: valid Treasury funding note rejected by the builder");
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
    if note.action() == Action::Claim {
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
            &mut rand::rngs::OsRng,
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
    wallet: &Wallet,
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
