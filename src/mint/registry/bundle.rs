//! The Ironwood bundle composer for Name Notes
//!

use orchard::builder::{BuildError, BundleType, UnauthorizedBundle};
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::key::{RegistryKeys, TreasuryKeys};

/// A spend prepared for composition: the note and its witness under the
/// bundle's anchor. The settle layer fetches both from the wallet.
#[derive(Clone)]
pub(crate) struct PreparedSpend {
    pub(crate) note: orchard::note::Note,
    pub(crate) path: orchard::tree::MerklePath,
}

/// A builder for the branch-derived Ironwood bundle version at the target
/// height, anchored at `anchor`. Mirrors the finalizer's own derivation:
/// the truth lives in the chain, not in a constant here.
fn ironwood_builder<P: Parameters>(
    network: &P,
    anchor: orchard::tree::Anchor,
    target_height: BlockHeight,
) -> Result<orchard::builder::Builder, BuildError> {
    let branch_id = BranchId::for_height(network, target_height);
    let bundle_version = bundle_version_for_branch(branch_id, orchard::ValuePool::Ironwood)
        .expect("Ironwood exists only from NU6.3; the mint targets NU6.3+");
    orchard::builder::Builder::new(
        BundleType::DEFAULT,
        bundle_version,
        bundle_version.default_flags(),
        anchor,
    )
}

/// Builds the claim bundle: the payment note is spent, the name note is
/// minted to the Registry, and the settle layer's computed refund and
/// change values become ordinary outputs. The ZIP-317 fee is the bundle's
/// balance gap — the settle layer has already accounted for it in
/// `change`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_claim_bundle<P: Parameters>(
    network: &P,
    anchor: orchard::tree::Anchor,
    claim_memo: [u8; 512],
    claim_opening: (orchard::note::NoteCommitTrapdoor, pasta_curves::pallas::Base),
    payment: PreparedSpend,
    refund: Option<(orchard::Address, Zatoshis)>,
    change: Option<Zatoshis>,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    target_height: BlockHeight,
) -> Result<UnauthorizedBundle<ZatBalance>, BuildError> {
    let treasury_fvk = treasury_keys.orchard_fvk();
    let registry_fvk = registry_keys.orchard_fvk();

    let mut builder = ironwood_builder(network, anchor, target_height)?;
    builder
        .add_spend(treasury_fvk.clone(), payment.note, payment.path)
        .expect("fixed anchor with a matching witness; spends enabled");

    builder
        .add_zns_output(
            Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
            registry_fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::ZERO,
            claim_memo,
            claim_opening.0,
            claim_opening.1,
        )
        .expect("default flags enable outputs and cross-address transfers");

    if let Some((payer, value)) = refund {
        builder
            .add_output(
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::External)),
                payer,
                orchard::value::NoteValue::from_raw(value.into_u64()),
                *zcash_protocol::memo::MemoBytes::empty().as_array(),
            )
            .expect("default flags enable outputs and cross-address transfers");
    }

    if let Some(value) = change {
        builder
            .add_change_output(
                treasury_fvk.clone(),
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                orchard::value::NoteValue::from_raw(value.into_u64()),
                *zcash_protocol::memo::MemoBytes::empty().as_array(),
            )
            .expect("the Treasury FVK owns its internal change address");
    }

    let (bundle, _) = builder
        .build::<ZatBalance>(&mut rand::rngs::OsRng)?
        .expect("a bundle with spends and outputs is never empty");
    Ok(bundle)
}

/// Builds an update bundle: rebinds and/or extends the registration. The
/// expiry is carried forward from the live record — a property of the
/// authorized transition, not of this composition.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_update_bundle<P: Parameters>(
    network: &P,
    anchor: orchard::tree::Anchor,
    transition_memo: [u8; 512],
    transition_opening: (orchard::note::NoteCommitTrapdoor, pasta_curves::pallas::Base),
    predecessor: PreparedSpend,
    predecessor_opening: (orchard::note::NoteCommitTrapdoor, pasta_curves::pallas::Base),
    fee_notes: &[PreparedSpend],
    change: Option<Zatoshis>,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    target_height: BlockHeight,
) -> Result<UnauthorizedBundle<ZatBalance>, BuildError> {
    let treasury_fvk = treasury_keys.orchard_fvk();
    let registry_fvk = registry_keys.orchard_fvk();

    let mut builder = ironwood_builder(network, anchor, target_height)?;

    builder
        .add_zns_spend(
            registry_fvk.clone(),
            predecessor.note,
            predecessor.path,
            predecessor_opening.0,
            predecessor_opening.1,
        )
        .expect("registry FVK owns the predecessor; witness roots to the anchor");

    builder
        .add_zns_output(
            Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
            registry_fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::ZERO,
            transition_memo,
            transition_opening.0,
            transition_opening.1,
        )
        .expect("default flags enable outputs and cross-address transfers");

    for note in fee_notes {
        builder
            .add_spend(treasury_fvk.clone(), note.note.clone(), note.path.clone())
            .expect("fixed anchor with a matching witness; spends enabled");
    }

    if let Some(value) = change {
        builder
            .add_change_output(
                treasury_fvk.clone(),
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                orchard::value::NoteValue::from_raw(value.into_u64()),
                *zcash_protocol::memo::MemoBytes::empty().as_array(),
            )
            .expect("the Treasury FVK owns its internal change address");
    }

    let (bundle, _) = builder
        .build::<ZatBalance>(&mut rand::rngs::OsRng)?
        .expect("a bundle with spends and outputs is never empty");
    Ok(bundle)
}

/// Builds a release bundle: terminates the registration and mints the
/// tombstone — same composition as an update, different authorized note.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_release_bundle<P: Parameters>(
    network: &P,
    anchor: orchard::tree::Anchor,
    transition_memo: [u8; 512],
    transition_opening: (orchard::note::NoteCommitTrapdoor, pasta_curves::pallas::Base),
    predecessor: PreparedSpend,
    predecessor_opening: (orchard::note::NoteCommitTrapdoor, pasta_curves::pallas::Base),
    fee_notes: &[PreparedSpend],
    change: Option<Zatoshis>,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    target_height: BlockHeight,
) -> Result<UnauthorizedBundle<ZatBalance>, BuildError> {
    let treasury_fvk = treasury_keys.orchard_fvk();
    let registry_fvk = registry_keys.orchard_fvk();

    let mut builder = ironwood_builder(network, anchor, target_height)?;

    builder
        .add_zns_spend(
            registry_fvk.clone(),
            predecessor.note,
            predecessor.path,
            predecessor_opening.0,
            predecessor_opening.1,
        )
        .expect("registry FVK owns the predecessor; witness roots to the anchor");

    builder
        .add_zns_output(
            Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
            registry_fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::ZERO,
            transition_memo,
            transition_opening.0,
            transition_opening.1,
        )
        .expect("default flags enable outputs and cross-address transfers");

    for note in fee_notes {
        builder
            .add_spend(treasury_fvk.clone(), note.note.clone(), note.path.clone())
            .expect("fixed anchor with a matching witness; spends enabled");
    }

    if let Some(value) = change {
        builder
            .add_change_output(
                treasury_fvk.clone(),
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                orchard::value::NoteValue::from_raw(value.into_u64()),
                *zcash_protocol::memo::MemoBytes::empty().as_array(),
            )
            .expect("the Treasury FVK owns its internal change address");
    }

    let (bundle, _) = builder
        .build::<ZatBalance>(&mut rand::rngs::OsRng)?
        .expect("a bundle with spends and outputs is never empty");
    Ok(bundle)
}

/// Builds a claim refund: the rejected payment is consumed and the settle
/// layer's computed refund goes to the payer; the remainder is the
/// Treasury's. No Registry authority participates — a refund mints no name
/// note and spends no name note.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_refund_bundle<P: Parameters>(
    network: &P,
    anchor: orchard::tree::Anchor,
    payment: PreparedSpend,
    refund: Option<(orchard::Address, Zatoshis)>,
    change: Option<Zatoshis>,
    fee_notes: &[PreparedSpend],
    treasury_keys: &TreasuryKeys,
    target_height: BlockHeight,
) -> Result<UnauthorizedBundle<ZatBalance>, BuildError> {
    let treasury_fvk = treasury_keys.orchard_fvk();

    let mut builder = ironwood_builder(network, anchor, target_height)?;
    builder
        .add_spend(treasury_fvk.clone(), payment.note, payment.path)
        .expect("fixed anchor with a matching witness; spends enabled");

    for note in fee_notes {
        builder
            .add_spend(treasury_fvk.clone(), note.note.clone(), note.path.clone())
            .expect("fixed anchor with a matching witness; spends enabled");
    }

    if let Some((payer, value)) = refund {
        builder
            .add_output(
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::External)),
                payer,
                orchard::value::NoteValue::from_raw(value.into_u64()),
                *zcash_protocol::memo::MemoBytes::empty().as_array(),
            )
            .expect("default flags enable outputs and cross-address transfers");
    }

    if let Some(value) = change {
        builder
            .add_change_output(
                treasury_fvk.clone(),
                Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                orchard::value::NoteValue::from_raw(value.into_u64()),
                *zcash_protocol::memo::MemoBytes::empty().as_array(),
            )
            .expect("the Treasury FVK owns its internal change address");
    }

    let (bundle, _) = builder
        .build::<ZatBalance>(&mut rand::rngs::OsRng)?
        .expect("a bundle with spends is never empty");
    Ok(bundle)
}
