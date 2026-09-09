//! The write path: one function per action — `claim`, `update`, `release` —
//! each stages its zero-value Registry Name Note onto a caller-owned builder.
//! Final assembly (build → prove → sign) returns when the orchestrator exists.

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{SentTransaction, WalletRead as _, WalletWrite as _};
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_primitives::transaction::builder::Error as BuildError;
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

use crate::mint::TRANSACTION_EXPIRY_BUFFER;

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

/// Builds and records one registration. The claim message is consumed as
/// the transaction's trigger. Separate Treasury notes cover the network fee,
/// and all remaining Treasury value returns to the Treasury account. The
/// Registry output is always zero-valued.
#[allow(clippy::too_many_arguments)]
pub fn register<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    claim_note: NameNote,
    claim_anchor: orchard::note::Nullifier,
    payment: &ReceivedNote<NoteId, orchard::note::Note>,
    price: Zatoshis,
    tip: BlockHeight,
    target_height: BlockHeight,
) -> Option<Transaction> {
    assert_eq!(claim_note.action(), crate::mint::Action::Claim);

    let payment_value = zatoshis(payment);
    if payment_value < price {
        return None;
    }

    let claim_anchor = wallet.unspent_ironwood_note_by_nullifier(
        REGISTRY_ACCOUNT,
        claim_anchor,
        TargetHeight::from(tip),
    )?;
    let excluded = [
        *payment.internal_note_id(),
        *claim_anchor.internal_note_id(),
    ];
    let (fee_notes, fee_funding, transaction_fee) =
        select_fee_notes(network, wallet, tip, target_height, None, &excluded, 2, 3)?;
    let treasury_change = (payment_value + fee_funding)
        .and_then(|total| total - transaction_fee)
        .expect("separate Treasury fee selection preserves the full claim payment");

    let anchor = anchor(wallet, tip);
    let (payment_note, payment_path) = prepare(wallet, payment, tip);
    let (claim_anchor_note, claim_anchor_path) = prepare(wallet, &claim_anchor, tip);
    let treasury_fvk = treasury_keys.orchard_fvk();
    let registry_fvk = registry_keys.orchard_fvk();

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
    )
    .with_expiry_height(expiry(target_height));

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
    claim(&mut builder, registry_keys, claim_note)
        .expect("FATAL: valid registration rejected by the builder");
    builder
        .add_ironwood_output::<FeeError>(
            Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
            treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            treasury_change,
            zcash_protocol::memo::MemoBytes::empty(),
        )
        .expect("FATAL: valid Treasury change rejected by the builder");

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
            &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
        )
        .expect("FATAL: registration proving or signing failed");
    let transaction = built.transaction().clone();
    record(wallet, &transaction, target_height, transaction_fee);
    Some(transaction)
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
    let anchor = anchor(wallet, tip);
    let (predecessor_note, predecessor_path) = prepare(wallet, &predecessor, tip);
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
    )
    .with_expiry_height(expiry(target_height));

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
            &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
        )
        .expect("FATAL: transition proving or signing failed");
    let transaction = built.transaction().clone();
    record(wallet, &transaction, target_height, transaction_fee);
    Some(transaction)
}

/// Builds and records the controller challenge for one update or release
/// message. When `request` is present, that exact inbound Treasury note is
/// consumed; lifecycle challenges have no inbound trigger. Empty-memo
/// Treasury notes supply the relay value and network fee, and every remainder
/// returns to the Treasury account.
#[allow(clippy::too_many_arguments)]
pub fn challenge<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    request: Option<&ReceivedNote<NoteId, orchard::note::Note>>,
    controller: &zcash_keys::address::UnifiedAddress,
    memo: [u8; 512],
    relay_value: Zatoshis,
    tip: BlockHeight,
    target_height: BlockHeight,
) -> Option<Transaction> {
    let request_value = request.map(zatoshis).unwrap_or(Zatoshis::ZERO);
    let request_id = request.map(|note| *note.internal_note_id());
    let mut fee_notes = Vec::new();
    let mut funding = request_value;
    let candidates = crate::mint::treasury::fee_note_candidates(wallet, tip)
        .into_iter()
        .filter(|note| Some(*note.internal_note_id()) != request_id)
        .collect::<Vec<_>>();
    let mut candidate_index = 0;

    let transaction_fee = loop {
        let action_count = (usize::from(request.is_some()) + fee_notes.len()).max(2);
        let fee = fee(network, target_height, action_count);
        let required = (relay_value + fee).expect("relay value plus fee fits monetary range");
        if funding >= required {
            break fee;
        }
        let candidate = candidates.get(candidate_index)?;
        candidate_index += 1;
        funding = (funding + zatoshis(candidate))
            .expect("Treasury balance fits in the Zcash monetary range");
        fee_notes.push(prepare(wallet, candidate, tip));
    };
    let treasury_change = (funding - relay_value)
        .and_then(|remaining| remaining - transaction_fee)
        .expect("selection guarantees relay value and fee coverage");

    let anchor = anchor(wallet, tip);
    let prepared_request = request.map(|note| prepare(wallet, note, tip));
    let treasury_fvk = treasury_keys.orchard_fvk();
    let controller = controller.orchard().copied()?;
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
    )
    .with_expiry_height(expiry(target_height));

    if let Some((request_note, request_path)) = prepared_request {
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), request_note, request_path)
            .expect("FATAL: valid Treasury request rejected by the builder");
    }
    for (note, path) in fee_notes {
        builder
            .add_ironwood_spend::<FeeError>(treasury_fvk.clone(), note, path)
            .expect("FATAL: valid Treasury relay funding rejected by the builder");
    }
    builder
        .add_ironwood_output::<FeeError>(
            Some(treasury_fvk.to_ovk(orchard::keys::Scope::External)),
            controller,
            relay_value,
            zcash_protocol::memo::MemoBytes::from_bytes(&memo)
                .expect("a 512-byte protocol memo is valid"),
        )
        .expect("FATAL: valid controller challenge rejected by the builder");
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
            &[orchard::keys::SpendAuthorizingKey::from(
                treasury_keys.orchard_spending_key(),
            )],
            &mut rand::rngs::OsRng,
            spend_prover,
            output_prover,
            &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
        )
        .expect("FATAL: controller challenge proving or signing failed");
    let transaction = built.transaction().clone();
    record(wallet, &transaction, target_height, transaction_fee);
    Some(transaction)
}

fn zatoshis(note: &ReceivedNote<NoteId, orchard::note::Note>) -> Zatoshis {
    Zatoshis::from_u64(note.note().value().inner())
        .expect("note values fit in the Zcash monetary range")
}

fn anchor(wallet: &mut Wallet, tip: BlockHeight) -> orchard::tree::Anchor {
    wallet
        .ironwood_anchor(tip)
        .expect("FATAL: Ironwood tree access failed")
        .expect("FATAL: wallet has no Ironwood anchor at its applied tip")
}

fn prepare(
    wallet: &mut Wallet,
    note: &ReceivedNote<NoteId, orchard::note::Note>,
    tip: BlockHeight,
) -> (orchard::note::Note, orchard::tree::MerklePath) {
    let path = wallet
        .ironwood_witness(note.note_commitment_tree_position(), tip)
        .expect("FATAL: Ironwood tree access failed")
        .expect("FATAL: owned note has no witness at the applied tip");
    (note.note().clone(), orchard::tree::MerklePath::from(path))
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
    let mut candidates = crate::mint::treasury::fee_note_candidates(wallet, tip);
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
    zcash_primitives::transaction::fees::zip317::FeeRule::standard()
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

fn expiry(target_height: BlockHeight) -> BlockHeight {
    BlockHeight::from_u32(
        u32::from(target_height)
            .checked_add(TRANSACTION_EXPIRY_BUFFER)
            .expect("target height plus expiry buffer fits u32"),
    )
}

fn record(
    wallet: &mut Wallet,
    transaction: &Transaction,
    target_height: BlockHeight,
    transaction_fee: Zatoshis,
) {
    let sent = SentTransaction::new(
        transaction,
        time::OffsetDateTime::now_utc(),
        TargetHeight::from(target_height),
        TREASURY_ACCOUNT,
        &[],
        transaction_fee,
        &[],
    );
    wallet
        .store_transactions_to_be_sent(&[sent])
        .expect("FATAL: wallet rejected a locally built transaction");
}
