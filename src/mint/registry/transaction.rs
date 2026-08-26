//! Transaction building: constructs an unproven Ironwood bundle from a
//! [`NameNoteRequest`], spending the previous Name Note (if update/release),
//! minting the new one, and self-funding the ZIP-317 fee.
//!
//! Name Notes live in the Ironwood pool (`BundleVersion::ironwood_v3`).
//! Both the Name Note and the fee-funding notes are Ironwood notes — the
//! Treasury funds the Registry via Ironwood, so a single Ironwood bundle
//! carries everything: ZNS spend, ZNS output, funding spends, and change.

use crate::key::RegistryKeys;
use crate::mint::registry::authorize::NameNoteRequest;
use crate::mint::registry::Registry;
use crate::mint::Action;
use crate::wallet::NoteLocator;
use std::collections::BTreeSet;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_protocol::consensus::{BlockHeight, Parameters};

// ---------------------------------------------------------------------------
// Fee input planning
// ---------------------------------------------------------------------------

/// Exact ordinary Registry notes selected to fund one lifecycle transaction.
///
/// Fields are private so transaction assembly cannot be redirected to a
/// different wallet note after planning.
#[derive(Clone, PartialEq, Eq)]
pub struct RegistryFeeInputs {
    locators: BTreeSet<NoteLocator>,
}

impl std::fmt::Debug for RegistryFeeInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryFeeInputs")
            .field("count", &self.locators.len())
            .finish()
    }
}

impl RegistryFeeInputs {
    pub fn locators(&self) -> &BTreeSet<NoteLocator> {
        &self.locators
    }
}

fn registry_fee<P: Parameters>(
    network: &P,
    target_height: BlockHeight,
    lifecycle_spends: usize,
    funding_spends: usize,
    extra_outputs: usize,
    has_change: bool,
) -> u64 {
    use orchard::builder::BundleType;
    use orchard::bundle::BundleVersion;

    let version = BundleVersion::ironwood_v3();
    let total_spends = lifecycle_spends + funding_spends;
    let total_outputs = 1 + extra_outputs + usize::from(has_change);
    let actions = BundleType::DEFAULT
        .num_actions(version.default_flags(), total_spends, total_outputs)
        .expect("action count fits in bundle granularity");
    FeeRule::standard()
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            actions,
        )
        .expect("ZIP-317 fee for realistic action count is representable")
        .into_u64()
}

/// Selects the exact ordinary Registry notes required to fund `request` at
/// `target_height`, excluding every locator held by another Live operation.
pub fn select_registry_fee_inputs<P: Parameters>(
    network: &P,
    wallet: &crate::wallet::Wallet,
    request: &NameNoteRequest,
    target_height: BlockHeight,
    excluded: &BTreeSet<NoteLocator>,
    extra_outputs: usize,
) -> Result<RegistryFeeInputs, crate::mint::AssemblyError> {
    let lifecycle_spends = usize::from(request.action() != Action::Claim);
    let mut candidates: Vec<_> = wallet
        .ironwood_notes_for(crate::mint::REGISTRY_ACCOUNT)
        .filter(|note| {
            crate::mint::registry::liquidity::classify_registry_note_parts(
                note.note.value().inner(),
            ) == crate::mint::registry::liquidity::RegistryNoteClass::Fee
        })
        .map(|note| {
            (
                NoteLocator::ironwood(crate::mint::REGISTRY_ACCOUNT, note.note.rho()),
                note.note.value().inner(),
            )
        })
        .filter(|(locator, _)| !excluded.contains(locator))
        .collect();
    candidates.sort_by_key(|(_, value)| *value);

    let mut locators = BTreeSet::new();
    let mut total = 0u64;
    for funding_spends in 0..=candidates.len() {
        let fee_without_change = registry_fee(
            network,
            target_height,
            lifecycle_spends,
            funding_spends,
            extra_outputs,
            false,
        );
        if total == fee_without_change {
            return Ok(RegistryFeeInputs { locators });
        }

        let fee_with_change = registry_fee(
            network,
            target_height,
            lifecycle_spends,
            funding_spends,
            extra_outputs,
            true,
        );
        if total > fee_without_change && total >= fee_with_change {
            return Ok(RegistryFeeInputs { locators });
        }

        let Some((locator, value)) = candidates.get(funding_spends) else {
            break;
        };
        total += *value;
        locators.insert(*locator);
    }

    Err(crate::mint::AssemblyError::InsufficientFunds)
}

// ---------------------------------------------------------------------------
// Bundle construction
// ---------------------------------------------------------------------------

/// Assembles an unproven Ironwood bundle to execute a ZNS request.
///
/// Spends the previous Name Note (if update/release) via the validated-note
/// builder boundary, mints the new Name Note via `add_zns_output`, and
/// self-funds the ZIP-317 fee using the Registry's own Ironwood ZEC reserves.
///
/// The bundle's value balance is asserted to equal its computed fee: the net
/// balance is exactly what the Registry fee notes contribute beyond their
/// change.
#[allow(clippy::too_many_arguments)]
pub fn build_transaction<P: Parameters>(
    network: &P,
    wallet: &mut crate::wallet::Wallet,
    registry: &Registry,
    registry_keys: &RegistryKeys,
    request: NameNoteRequest,
    fee_inputs: &RegistryFeeInputs,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
) -> Result<
    orchard::Bundle<
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
        zcash_protocol::value::ZatBalance,
    >,
    crate::mint::AssemblyError,
> {
    use orchard::builder::BundleType;
    use orchard::bundle::BundleVersion;
    use rand::rngs::OsRng;

    // 1. Get the Ironwood anchor at the fully-applied chain height.
    let anchor = wallet
        .ironwood_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoAnchor)?;

    // 2. Initialize the Ironwood Builder
    let bundle_version = BundleVersion::ironwood_v3();
    let flags = bundle_version.default_flags();

    let mut builder =
        orchard::builder::Builder::new(BundleType::DEFAULT, bundle_version, flags, anchor.into())
            .expect("ironwood_v3 builder with valid anchor and default flags");

    let fvk = orchard::keys::FullViewingKey::from(registry_keys.orchard_spending_key());
    let address = fvk.address_at(0u32, orchard::keys::Scope::External);
    let name = request.name();

    // The typed transition this transaction commits (§3.2): every field
    // below — the spend check, the memo, and the opening — derives from it.
    let transition = match &request {
        NameNoteRequest::Claim(b) => crate::mint::NameNote::Claim {
            name: b.name.clone(),
            ua: b.ua.clone(),
            expires_at: b.expires_at,
        },
        NameNoteRequest::Update(b) => crate::mint::NameNote::Update {
            name: b.name.clone(),
            ua: b.new_ua.clone(),
            expires_at: b.expires_at,
            prev: b.prev_commitment,
        },
        NameNoteRequest::Release(b) => crate::mint::NameNote::Release {
            name: b.name.clone(),
            ua: b.ua.clone(),
            prev: b.prev_commitment,
        },
    };
    let (action, prev_commitment) = (transition.action(), transition.prev_rcm());

    if action == Action::Claim
        && registry
            .record(name)
            .is_some_and(|record| record.action != Action::Release)
    {
        return Err(crate::mint::AssemblyError::NameUnavailable);
    }

    // 3. Spend previous Name Note if updating or releasing
    //
    // The previous Name Note is the exact validated Registry record. We look
    // it up from the wallet by `rho` — the wallet indexes notes by `rho`,
    // and one lookup gives us the note, its Merkle position, and its memo
    // (from which we recompute the ZNS opening `(rcm, psi)`).
    if action == Action::Update || action == Action::Release {
        let record = registry
            .record(name)
            .ok_or(crate::mint::AssemblyError::NoteNotFound)?;
        if record.commitment
            != prev_commitment.ok_or(crate::mint::AssemblyError::PredecessorMismatch)?
        {
            return Err(crate::mint::AssemblyError::PredecessorMismatch);
        }

        // Extract note data from the wallet (immutable borrow ends here).
        let (note, position, memo_bytes) = {
            let w = wallet
                .ironwood_note(crate::wallet::NoteLocator::ironwood(
                    crate::mint::REGISTRY_ACCOUNT,
                    record.rho,
                ))
                .ok_or(crate::mint::AssemblyError::NoteNotFound)?;
            (w.note.clone(), w.position, w.memo)
        };

        let merkle_path = wallet
            .ironwood_witness(position, anchor_height)
            .ok()
            .flatten()
            .ok_or(crate::mint::AssemblyError::NoWitness)?;

        let prev_transition = crate::mint::decode_name_note(network, &memo_bytes)
            .expect("previous Name Note memo decodes (validated at scan time)");
        let (rcm, psi) = prev_transition.opening(network);
        builder
            .add_zns_spend(
                fvk.clone(),
                note,
                merkle_path.into(),
                orchard::note::NoteCommitTrapdoor::from_inner(rcm),
                psi,
            )
            .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;
    }

    // 4. Create new ZNS output — the opening and memo derive from the same
    // typed transition, so the commitment and memo cannot disagree.
    let (new_rcm, new_psi) = transition.opening(network);

    let memo = transition
        .encode(network)
        .expect("typed NameNote encodes within 512-byte memo");

    let value = orchard::value::NoteValue::from_raw(0);

    builder
        .add_zns_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            address,
            value,
            memo,
            orchard::note::NoteCommitTrapdoor::from_inner(new_rcm),
            new_psi,
        )
        .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

    // 5. Resolve only the exact fee notes retained in the caller's plan.
    let committed_spends = builder.spends().len();
    let mut funding_notes = Vec::with_capacity(fee_inputs.locators.len());
    let mut total_funded = 0u64;
    for locator in &fee_inputs.locators {
        let note = wallet
            .ironwood_note(*locator)
            .ok_or(crate::mint::AssemblyError::NoteNotFound)?;
        if note.account_id != crate::mint::REGISTRY_ACCOUNT
            || crate::mint::registry::liquidity::classify_registry_note_parts(
                note.note.value().inner(),
            ) != crate::mint::registry::liquidity::RegistryNoteClass::Fee
        {
            return Err(crate::mint::AssemblyError::WrongAccount);
        }
        total_funded += note.note.value().inner();
        funding_notes.push(note.clone());
    }

    let funding_spends = funding_notes.len();
    let extra_outputs = 0;
    let fee_without_change = registry_fee(
        network,
        target_height,
        committed_spends,
        funding_spends,
        extra_outputs,
        false,
    );
    let (fee, change) = if total_funded == fee_without_change {
        (fee_without_change, 0)
    } else {
        let fee_with_change = registry_fee(
            network,
            target_height,
            committed_spends,
            funding_spends,
            extra_outputs,
            true,
        );
        if total_funded < fee_with_change {
            return Err(crate::mint::AssemblyError::InsufficientValue);
        }
        (fee_with_change, total_funded - fee_with_change)
    };

    // Add the selected funding notes as standard Ironwood spends.
    for prev_note in &funding_notes {
        let merkle_path = wallet
            .ironwood_witness(prev_note.position, anchor_height)
            .ok()
            .flatten()
            .ok_or(crate::mint::AssemblyError::NoWitness)?;

        builder
            .add_spend(fvk.clone(), prev_note.note, merkle_path.into())
            .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;
    }

    if change > 0 {
        let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);

        // ZIP-302 empty memo: 0xF6 followed by 511 zeros.
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6;

        builder
            .add_output(
                Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
                change_address,
                orchard::value::NoteValue::from_raw(change),
                change_memo,
            )
            .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;
    }

    // 7. Build and verify value balance
    let (bundle, _meta) = builder
        .build::<zcash_protocol::value::ZatBalance>(&mut OsRng)
        .map_err(|_| crate::mint::AssemblyError::BuildFailed)?
        .ok_or(crate::mint::AssemblyError::BuildFailed)?;

    // The net balance is exactly what the Registry fee notes contribute
    // beyond the Registry change — the aggregate fee.
    let actual_fee: i64 = bundle.value_balance().into();
    let intended_balance = i64::try_from(fee).expect("fee fits in i64");
    assert_eq!(
        actual_fee, intended_balance,
        "bundle value balance {} != intended balance {} — transaction is misbalanced",
        actual_fee, intended_balance,
    );

    // Note: the full cryptographic self-verification (proof + commitment) is
    // performed by `verify_proof` in `crate::mint::signer::assemble_v6_transaction`.
    // The ZNS payload (rcm, ψ) → cmx path cannot be independently recomputed
    // outside the orchard circuit (it requires the fork's Sinsemilla hash),
    // so `verify_proof` is the authoritative check.

    Ok(bundle)
}

/// Assembles, proves, signs, and serializes a transition transaction (update or release)
/// from a typed [`NameNoteRequest`].
///
/// This is the complete Registry transition path: selects fee notes, builds the
/// Ironwood bundle, and signs it into a broadcastable V6 transaction.
#[allow(clippy::too_many_arguments)]
pub fn execute_transition<P: Parameters>(
    network: &P,
    wallet: &mut crate::wallet::Wallet,
    registry: &Registry,
    registry_keys: &RegistryKeys,
    request: NameNoteRequest,
    excluded: &BTreeSet<NoteLocator>,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
) -> Result<
    (
        zcash_primitives::transaction::TxId,
        String,
        Vec<NoteLocator>,
    ),
    crate::mint::AssemblyError,
> {
    let fee_inputs =
        select_registry_fee_inputs(network, wallet, &request, target_height, excluded, 0)?;
    let bundle = build_transaction(
        network,
        wallet,
        registry,
        registry_keys,
        request,
        &fee_inputs,
        anchor_height,
        target_height,
    )?;
    let tx = crate::mint::signer::assemble_v6_transaction(
        network,
        bundle,
        None,
        Some(registry_keys),
        None,
        target_height,
    )?;
    Ok((
        tx.txid(),
        crate::mint::signer::serialize_tx(&tx)?,
        fee_inputs.locators().iter().copied().collect(),
    ))
}
