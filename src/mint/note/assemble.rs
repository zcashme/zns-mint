//! The write path: one prepare function resolves the law's NameNote
//! against the wallet and stages, proves, signs, and records the
//! transaction.

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_primitives::transaction::builder::{self, BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use super::NameNote;
use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::{TreeError, Wallet, WalletError};

/// Why a Name Note transaction was not built. The caller retries next tip.
/// Only [`PrepareError::FeeUnfunded`] means the Treasury could not cover
/// the fee; the other variants are a different fact.
#[derive(Debug)]
pub enum PrepareError {
    /// The claim anchor or predecessor is not spendable at this tip.
    AuthorityUnavailable,
    /// Treasury notes cannot cover the ZIP-317 fee.
    FeeUnfunded,
    /// The note is in the wallet and has no witness at the applied tip.
    WitnessUnavailable,
    /// The applied tip has no Ironwood anchor.
    AnchorUnavailable,
    /// An update or release predecessor memo does not open its Name Note.
    PredecessorClosed,
    /// A note-commitment tree operation failed.
    Tree(TreeError),
    /// The ZIP-317 fee rule could not calculate the required fee.
    Fee(FeeError),
    /// The wallet could not retrieve the predecessor memo.
    Memo(WalletError),
    /// The transaction builder or prover rejected the transaction.
    Builder(builder::Error<FeeError>),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorityUnavailable => write!(f, "authority note is not spendable"),
            Self::FeeUnfunded => write!(f, "Treasury cannot cover the fee"),
            Self::WitnessUnavailable => write!(f, "owned note has no witness at the applied tip"),
            Self::AnchorUnavailable => write!(f, "no Ironwood anchor at the applied tip"),
            Self::PredecessorClosed => write!(f, "predecessor memo does not open its Name Note"),
            Self::Tree(error) => write!(f, "note commitment tree error: {error}"),
            Self::Fee(error) => write!(f, "ZIP-317 fee calculation failed: {error}"),
            Self::Memo(error) => write!(f, "predecessor memo lookup failed: {error}"),
            Self::Builder(error) => write!(f, "Name Note transaction build failed: {error}"),
        }
    }
}

impl std::error::Error for PrepareError {}

/// Builds and records a Name Note transaction for any action.
/// `authority_nf` is the claim anchor or the predecessor; Treasury fee
/// notes cover the fee.
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
) -> Result<Transaction, PrepareError> {
    let authority = wallet
        .unspent_ironwood_note_by_nullifier(REGISTRY_ACCOUNT, authority_nf, TargetHeight::from(tip))
        .ok_or(PrepareError::AuthorityUnavailable)?;

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
        let f = fee(network, target_height, action_count)?;
        if fee_funding >= f {
            break f;
        }
        let Some(candidate) = candidates.get(fee_notes.len()) else {
            return Err(PrepareError::FeeUnfunded);
        };
        fee_funding = (fee_funding + zatoshis(candidate))
            .expect("Treasury balance fits in the Zcash monetary range");
        fee_notes.push((*candidate.note(), witness_at(wallet, candidate, tip)?));
    };

    // Change = every Treasury input value − the fee. The loop above
    // only breaks once funding covers the fee.
    let treasury_change = (fee_funding - transaction_fee).expect("fee funding covers the fee");

    let anchor = wallet
        .ironwood_anchor(tip)
        .map_err(PrepareError::Tree)?
        .ok_or(PrepareError::AnchorUnavailable)?;
    let authority_note = *authority.note();
    let authority_path = witness_at(wallet, &authority, tip)?;

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
            .map_err(PrepareError::Builder)?;
    } else {
        let (rcm, psi) = predecessor_opening(network, wallet, &authority)?;
        builder
            .add_zns_spend::<FeeError>(
                registry_fvk.clone(),
                authority_note,
                authority_path,
                rcm,
                psi,
            )
            .map_err(PrepareError::Builder)?;
    }

    // Fee notes.
    for (note, path) in fee_notes {
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), note, path)
            .map_err(PrepareError::Builder)?;
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
        .map_err(PrepareError::Builder)?;

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
            .map_err(PrepareError::Builder)?;
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
            .map_err(PrepareError::Builder)?;
    }

    let built = builder
        .build(
            &Default::default(),
            &[],
            &[treasury_keys.orchard_ask(), registry_keys.orchard_ask()],
            rand::rngs::OsRng,
            spend_prover,
            output_prover,
            &StandardFeeRule::Zip317,
        )
        .map_err(PrepareError::Builder)?;
    let transaction = built.transaction().clone();
    wallet.record_sent(&transaction, target_height, transaction_fee);
    Ok(transaction)
}

fn witness_at<P: Parameters>(
    wallet: &mut Wallet<P>,
    note: &ReceivedNote<NoteId, orchard::note::Note>,
    tip: BlockHeight,
) -> Result<orchard::tree::MerklePath, PrepareError> {
    let path = wallet
        .ironwood_witness(note.note_commitment_tree_position(), tip)
        .map_err(PrepareError::Tree)?
        .ok_or(PrepareError::WitnessUnavailable)?;
    Ok(orchard::tree::MerklePath::from(path))
}

fn zatoshis(note: &ReceivedNote<NoteId, orchard::note::Note>) -> Zatoshis {
    Zatoshis::from_u64(note.note().value().inner())
        .expect("note values fit in the Zcash monetary range")
}

fn predecessor_opening<P: Parameters>(
    network: &P,
    wallet: &Wallet<P>,
    note: &ReceivedNote<NoteId, orchard::note::Note>,
) -> Result<
    (
        orchard::note::NoteCommitTrapdoor,
        pasta_curves::pallas::Base,
    ),
    PrepareError,
> {
    let memo = wallet
        .get_memo(*note.internal_note_id())
        .map_err(PrepareError::Memo)?;
    let payload = match memo {
        Some(zcash_protocol::memo::Memo::Future(bytes)) => {
            NameNote::decode(network, bytes.as_array())
        }
        _ => None,
    }
    .ok_or(PrepareError::PredecessorClosed)?;
    Ok((
        orchard::note::NoteCommitTrapdoor::from_inner(payload.rcm(network)),
        payload.psi(network),
    ))
}

fn fee<P: Parameters>(
    network: &P,
    target_height: BlockHeight,
    ironwood_actions: usize,
) -> Result<Zatoshis, PrepareError> {
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
        .map_err(PrepareError::Fee)
}
