//! The write path: per transaction shape, a prepare/create pair — prepare
//! resolves the law's inputs, create proves, signs, and records.

use zcash_client_backend::data_api::locking::{LockOwner, OutputLockStore as _};
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::wallet::{NoteId, OutputRef, ReceivedNote};
use zcash_primitives::transaction::builder::Error as BuildError;
use zcash_primitives::transaction::builder::{
    BuildConfig, Builder, BundlePadding, DEFAULT_TX_EXPIRY_DELTA,
};
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::Memo;
use zcash_protocol::value::Zatoshis;

use super::NameNote;
use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
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

/// Stages a claim's two inseparable zero-value Registry outputs: the ZNS Name
/// Note and the ordinary successor anchor that authorizes the next claim.
pub fn claim<P: Parameters>(
    builder: &mut Builder<P, ()>,
    registry_keys: &RegistryKeys,
    claim: NameNote,
) -> Result<(), BuildError<FeeError>> {
    let NameNote::Claim { .. } = claim else {
        panic!("assemble::claim requires a claim NameNote");
    };

    let memo = claim.encode(builder.params());
    let rcm = claim.rcm(builder.params());
    let psi = claim.psi(builder.params());
    let opening = orchard::note::NoteCommitTrapdoor::from_inner(rcm);

    let registry_fvk = registry_keys.orchard_fvk();
    builder.add_zns_output(
        Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
        registry_fvk.address_at(0u32, orchard::keys::Scope::External),
        Zatoshis::ZERO,
        memo,
        opening,
        psi,
    )?;
    builder.add_ironwood_output::<FeeError>(
        Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
        registry_fvk.address_at(0u32, orchard::keys::Scope::External),
        Zatoshis::ZERO,
        zcash_protocol::memo::MemoBytes::empty(),
    )?;

    Ok(())
}

/// Stages an update's successor Registry Name Note onto `builder`.
pub fn update<P: Parameters>(
    builder: &mut Builder<P, ()>,
    registry_keys: &RegistryKeys,
    update: NameNote,
) -> Result<(), BuildError<FeeError>> {
    let NameNote::Update { .. } = update else {
        panic!("assemble::update requires an update NameNote");
    };

    let memo = update.encode(builder.params());
    let rcm = update.rcm(builder.params());
    let psi = update.psi(builder.params());
    let opening = orchard::note::NoteCommitTrapdoor::from_inner(rcm);

    let registry_fvk = registry_keys.orchard_fvk();
    builder.add_zns_output(
        Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
        registry_fvk.address_at(0u32, orchard::keys::Scope::External),
        Zatoshis::ZERO,
        memo,
        opening,
        psi,
    )?;

    Ok(())
}

/// Stages a release's unbind Registry Name Note onto `builder`.
pub fn release<P: Parameters>(
    builder: &mut Builder<P, ()>,
    registry_keys: &RegistryKeys,
    release: NameNote,
) -> Result<(), BuildError<FeeError>> {
    let NameNote::Release { .. } = release else {
        panic!("assemble::release requires a release NameNote");
    };

    let memo = release.encode(builder.params());
    let rcm = release.rcm(builder.params());
    let psi = release.psi(builder.params());
    let opening = orchard::note::NoteCommitTrapdoor::from_inner(rcm);

    let registry_fvk = registry_keys.orchard_fvk();
    builder.add_zns_output(
        Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
        registry_fvk.address_at(0u32, orchard::keys::Scope::External),
        Zatoshis::ZERO,
        memo,
        opening,
        psi,
    )?;

    Ok(())
}

/// Prepares a claim transaction: resolves the law's NameNote against the
/// wallet — the exact claim anchor, the inbound payment, Treasury fee notes
/// — and stages the full transaction. Locks the selected inputs until the
/// transaction expires. `Err` means "awaits Treasury funds": re-fire next
/// tip.
#[allow(clippy::too_many_arguments)]
pub fn claim_prepare<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    claim_request: NameNote,
    claim_anchor: orchard::note::Nullifier,
    payment: &ReceivedNote<NoteId, orchard::note::Note>,
    tip: BlockHeight,
) -> Result<(Builder<P, ()>, Zatoshis), PrepareError> {
    assert_eq!(claim_request.action(), crate::mint::Action::Claim);
    let target_height = BlockHeight::from_u32(u32::from(tip) + 1);

    let claim_anchor_note = wallet
        .unspent_ironwood_note_by_nullifier(REGISTRY_ACCOUNT, claim_anchor, TargetHeight::from(tip))
        .ok_or(PrepareError::AuthorityUnavailable)?;
    let excluded = [
        *payment.internal_note_id(),
        *claim_anchor_note.internal_note_id(),
    ];

    // Treasury funding policy: empty-memo notes only — messages are not
    // money — largest first, so fewest notes fund the fee.
    let mut candidates = wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
    candidates.retain(|note| {
        matches!(
            wallet.get_memo(*note.internal_note_id()),
            Ok(None) | Ok(Some(Memo::Empty))
        )
    });
    candidates.retain(|note| !excluded.contains(note.internal_note_id()));
    candidates.sort_by_key(|note| std::cmp::Reverse(note.note().value().inner()));

    let mut fee_notes = Vec::new();
    let mut fee_funding = Zatoshis::ZERO;
    let transaction_fee = loop {
        let transaction_fee = fee(network, target_height, 2 + fee_notes.len());
        if fee_funding >= transaction_fee {
            break transaction_fee;
        }
        let candidate = candidates
            .get(fee_notes.len())
            .ok_or(PrepareError::InsufficientFunds)?;
        fee_funding = (fee_funding + zatoshis(candidate))
            .expect("Treasury balance fits in the Zcash monetary range");
        fee_notes.push(prepare(wallet, candidate, tip));
    };
    let treasury_change = (zatoshis(payment) + fee_funding)
        .and_then(|total| total - transaction_fee)
        .expect("separate Treasury fee selection preserves the full claim payment");

    // Reserve every selected input until the transaction expires: a rival
    // prepare cannot select them while this one is in flight.
    let locked_refs = std::iter::once(OutputRef::from(*payment.internal_note_id()))
        .chain(std::iter::once(OutputRef::from(
            *claim_anchor_note.internal_note_id(),
        )))
        .chain(
            candidates
                .iter()
                .take(fee_notes.len())
                .map(|note| OutputRef::from(*note.internal_note_id())),
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
    let payment_path = wallet
        .witness(payment, tip)
        .expect("FATAL: owned note has no witness at the applied tip");
    let payment_note = payment.note().clone();
    let claim_anchor_path = wallet
        .witness(&claim_anchor_note, tip)
        .expect("FATAL: owned note has no witness at the applied tip");
    let claim_anchor_note = claim_anchor_note.note().clone();
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

    builder
        .add_ironwood_spend::<FeeError>(registry_fvk.clone(), claim_anchor_note, claim_anchor_path)
        .expect("FATAL: valid Registry claim anchor rejected by the builder");
    builder
        .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), payment_note, payment_path)
        .expect("FATAL: valid Treasury payment rejected by the builder");
    for (note, path) in fee_notes {
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), note, path)
            .expect("FATAL: valid Treasury fee note rejected by the builder");
    }
    claim(&mut builder, registry_keys, claim_request)
        .expect("FATAL: valid registration rejected by the builder");
    builder
        .add_ironwood_output::<FeeError>(
            Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
            treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            treasury_change,
            zcash_protocol::memo::MemoBytes::empty(),
        )
        .expect("FATAL: valid Treasury change rejected by the builder");

    Ok((builder, transaction_fee))
}

/// Creates a prepared claim transaction: proves, signs with both
/// authorities. Pure — values in, transaction out; recording the intent is
/// the caller's step. Infallible once preparation succeeded.
pub fn create_claim<P: Parameters>(
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    builder: Builder<P, ()>,
) -> Transaction {
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
        .expect("FATAL: registration proving or signing failed");
    built.transaction().clone()
}

/// Builds and records an update or release. The exact current Registry note
/// is spent and replaced by one zero-valued successor. Treasury notes fund
/// the fee; an OTP echo can be required as the first such input so the
/// inbound authorization is consumed by the resulting transaction.
#[allow(clippy::too_many_arguments)]
pub fn transition<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    transition_note: NameNote,
    predecessor_nullifier: orchard::note::Nullifier,
    required_fee_note: Option<&ReceivedNote<NoteId, orchard::note::Note>>,
    tip: BlockHeight,
    target_height: BlockHeight,
) -> Option<Transaction> {
    assert!(matches!(
        transition_note.action(),
        crate::mint::Action::Update | crate::mint::Action::Release
    ));

    let predecessor = wallet.unspent_ironwood_note_by_nullifier(
        REGISTRY_ACCOUNT,
        predecessor_nullifier,
        TargetHeight::from(tip),
    )?;
    let excluded = [*predecessor.internal_note_id()];
    let (fee_notes, funding, transaction_fee) = select_fee_notes(
        network,
        wallet,
        tip,
        target_height,
        required_fee_note,
        &excluded,
        1,
        2,
    )?;
    let treasury_change =
        (funding - transaction_fee).expect("Treasury selection guarantees exact fee coverage");
    let anchor = wallet.anchor_at(tip);
    let predecessor_note = predecessor.note().clone();
    let predecessor_path = wallet
        .witness(&predecessor, tip)
        .expect("FATAL: owned note has no witness at the applied tip");
    let (predecessor_rcm, predecessor_psi) = predecessor_opening(network, wallet, &predecessor);

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

    builder
        .add_zns_spend::<FeeError>(
            registry_fvk,
            predecessor_note,
            predecessor_path,
            predecessor_rcm,
            predecessor_psi,
        )
        .expect("FATAL: valid Registry predecessor rejected by the builder");
    match transition_note.action() {
        crate::mint::Action::Update => update(&mut builder, registry_keys, transition_note)
            .expect("FATAL: valid update rejected by the builder"),
        crate::mint::Action::Release => release(&mut builder, registry_keys, transition_note)
            .expect("FATAL: valid release rejected by the builder"),
        crate::mint::Action::Claim => unreachable!("transition cannot be a claim"),
    }
    for (note, path) in fee_notes {
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), note, path)
            .expect("FATAL: valid Treasury fee note rejected by the builder");
    }
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
        .expect("FATAL: transition proving or signing failed");
    let transaction = built.transaction().clone();
    wallet.record_sent(&transaction, target_height, transaction_fee);
    Some(transaction)
}


fn zatoshis(note: &ReceivedNote<NoteId, orchard::note::Note>) -> Zatoshis {
    Zatoshis::from_u64(note.note().value().inner())
        .expect("note values fit in the Zcash monetary range")
}

fn prepare(
    wallet: &mut Wallet,
    note: &ReceivedNote<NoteId, orchard::note::Note>,
    tip: BlockHeight,
) -> (orchard::note::Note, orchard::tree::MerklePath) {
    let path = wallet
        .witness(note, tip)
        .expect("FATAL: owned note has no witness at the applied tip");
    (note.note().clone(), path)
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

fn select_fee_notes<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    tip: BlockHeight,
    target_height: BlockHeight,
    required: Option<&ReceivedNote<NoteId, orchard::note::Note>>,
    excluded: &[NoteId],
    fixed_spends: usize,
    fixed_outputs: usize,
) -> Option<(
    Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
    Zatoshis,
    Zatoshis,
)> {
    let required_id = required.map(|note| *note.internal_note_id());
    // Treasury funding policy: empty-memo notes only — messages are not
    // money — largest first, so fewest notes fund the fee.
    let mut candidates = wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
    candidates.retain(|note| {
        matches!(
            wallet.get_memo(*note.internal_note_id()),
            Ok(None) | Ok(Some(Memo::Empty))
        )
    });
    candidates.retain(|note| {
        Some(*note.internal_note_id()) != required_id && !excluded.contains(note.internal_note_id())
    });

    let mut selected = Vec::new();
    let mut funding = Zatoshis::ZERO;
    if let Some(note) = required {
        funding = zatoshis(note);
        selected.push(prepare(wallet, note, tip));
    }

    let mut candidate_index = 0;
    loop {
        let action_count = (fixed_spends + selected.len()).max(fixed_outputs).max(2);
        let transaction_fee = fee(network, target_height, action_count);
        if funding >= transaction_fee {
            return Some((selected, funding, transaction_fee));
        }
        let candidate = candidates.get(candidate_index)?;
        candidate_index += 1;
        funding = (funding + zatoshis(candidate))
            .expect("Treasury balance fits in the Zcash monetary range");
        selected.push(prepare(wallet, candidate, tip));
    }
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
