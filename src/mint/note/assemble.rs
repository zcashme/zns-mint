//! The write path: one function per action — `claim`, `update`, `release` —
//! each stages its zero-value Registry Name Note onto a caller-owned builder.
//! Final assembly (build → prove → sign) returns when the orchestrator exists.

use zcash_primitives::transaction::builder::Builder;
use zcash_primitives::transaction::builder::Error as BuildError;
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::value::Zatoshis;

use super::NameNote;
use crate::key::RegistryKeys;

/// Stages a claim's zero-value Registry Name Note onto `builder`.
///
/// # Panics
/// If `claim` is not a [`NameNote::Claim`].
pub fn claim<P: Parameters>(
    builder: &mut Builder<P, ()>,
    registry_keys: &RegistryKeys,
    claim: NameNote,
) -> Result<(), BuildError<FeeError>> {
    let NameNote::Claim { .. } = claim else {
        panic!("assemble::claim requires a claim NameNote");
    };

    let memo = claim
        .encode(builder.params())
        .expect("a valid name note encodes into 512 bytes");
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

    Ok(())
}

/// Stages an update's successor Registry Name Note onto `builder`.
///
/// # Panics
/// If `update` is not a [`NameNote::Update`].
pub fn update<P: Parameters>(
    builder: &mut Builder<P, ()>,
    registry_keys: &RegistryKeys,
    update: NameNote,
) -> Result<(), BuildError<FeeError>> {
    let NameNote::Update { .. } = update else {
        panic!("assemble::update requires an update NameNote");
    };

    let memo = update
        .encode(builder.params())
        .expect("a valid name note encodes into 512 bytes");
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
///
/// # Panics
/// If `release` is not a [`NameNote::Release`].
pub fn release<P: Parameters>(
    builder: &mut Builder<P, ()>,
    registry_keys: &RegistryKeys,
    release: NameNote,
) -> Result<(), BuildError<FeeError>> {
    let NameNote::Release { .. } = release else {
        panic!("assemble::release requires a release NameNote");
    };

    let memo = release
        .encode(builder.params())
        .expect("a valid name note encodes into 512 bytes");
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
