//! Transaction building: constructs an unproven Ironwood bundle from a
//! [`NameNoteRequest`], spending the previous Name Note (if update/release),
//! minting the new one, and self-funding the ZIP-317 fee.
//!
//! Name Notes live in the Ironwood pool (`BundleVersion::ironwood_v3`).
//! Both the Name Note and the fee-funding notes are Ironwood notes — the
//! Treasury funds the Registry via Ironwood, so a single Ironwood bundle
//! carries everything: ZNS spend, ZNS output, funding spends, and change.

use crate::key::RegistryKeys;
use crate::mint::Action;
use crate::registry::authorize::NameNoteRequest;
use crate::registry::state::Registry;
use crate::wallet::NoteLocator;
use std::collections::BTreeSet;
use transparent::address::TransparentAddress;
use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

// ---------------------------------------------------------------------------
// Transparent output type
// ---------------------------------------------------------------------------

/// A transparent output for a v6 transaction (e.g. the cold-storage destination
/// of a Treasury auto-sweep). The Treasury UA omits the transparent receiver,
/// so transparent *inputs* are never needed — only outputs.
///
/// Carries a [`TransparentAddress`] (the upstream type) rather than raw script
/// bytes, so [`transparent::builder::TransparentBuilder::add_output`] can be
/// used directly — no `zcash_script` dependency needed.
#[derive(Clone, Debug)]
pub struct TransparentOutput {
    pub address: TransparentAddress,
    pub value: Zatoshis,
}

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

fn registry_fee(
    target_height: BlockHeight,
    lifecycle_spends: usize,
    funding_spends: usize,
    has_change: bool,
) -> Result<u64, &'static str> {
    use orchard::builder::BundleType;
    use orchard::bundle::BundleVersion;

    let version = BundleVersion::ironwood_v3();
    let actions = BundleType::DEFAULT
        .num_actions(
            version.default_flags(),
            lifecycle_spends + funding_spends,
            1 + usize::from(has_change),
        )
        .map_err(|_| "Registry action count overflow")?;
    FeeRule::standard()
        .fee_required(
            &zcash_protocol::consensus::MAIN_NETWORK,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            actions,
        )
        .map(Zatoshis::into_u64)
        .map_err(|_| "Registry ZIP-317 fee computation overflow")
}

/// Selects the exact ordinary Registry notes required to fund `request` at
/// `target_height`, excluding every locator held by another Live operation.
pub fn select_registry_fee_inputs(
    wallet: &crate::wallet::Wallet,
    request: &NameNoteRequest,
    target_height: BlockHeight,
    excluded: &BTreeSet<NoteLocator>,
) -> Result<RegistryFeeInputs, &'static str> {
    let lifecycle_spends = usize::from(request.action() != Action::Claim);
    let mut candidates: Vec<_> = wallet
        .ironwood_notes_for(crate::mint::REGISTRY_ACCOUNT)
        .filter(|note| {
            crate::registry::liquidity::classify_registry_ironwood_note(note)
                == crate::registry::liquidity::RegistryNoteClass::Fee
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
        let fee_without_change =
            registry_fee(target_height, lifecycle_spends, funding_spends, false)?;
        if total == fee_without_change {
            return Ok(RegistryFeeInputs { locators });
        }

        let fee_with_change = registry_fee(target_height, lifecycle_spends, funding_spends, true)?;
        if total > fee_without_change && total >= fee_with_change {
            return Ok(RegistryFeeInputs { locators });
        }

        let Some((locator, value)) = candidates.get(funding_spends) else {
            break;
        };
        total = total
            .checked_add(*value)
            .ok_or("Registry fee input value overflow")?;
        locators.insert(*locator);
    }

    Err("insufficient available Registry fee notes")
}

// ---------------------------------------------------------------------------
// Bundle construction
// ---------------------------------------------------------------------------

/// Assembles an unproven Ironwood bundle to execute a ZNS request.
///
/// Spends the previous Name Note (if update/release) via the validated-note
/// builder boundary,
/// mints the new Name Note via `add_zns_output`, and self-funds the ZIP-317
/// fee using the Registry's own Ironwood ZEC reserves.
///
/// The bundle's value balance is asserted to equal the computed fee before
/// returning — a misbalanced transaction must not reach the signing path.
#[allow(clippy::too_many_arguments)]
pub fn build_transaction(
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
    &'static str,
> {
    use orchard::builder::BundleType;
    use orchard::bundle::BundleVersion;
    use rand::rngs::OsRng;

    // 1. Get the Ironwood anchor at the fully-applied chain height.
    let anchor = wallet
        .ironwood_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or("no ironwood anchor at accepted anchor height")?;

    // 2. Initialize the Ironwood Builder
    let bundle_version = BundleVersion::ironwood_v3();
    let flags = bundle_version.default_flags();

    let mut builder =
        orchard::builder::Builder::new(BundleType::DEFAULT, bundle_version, flags, anchor.into())
            .map_err(|_| "failed to create builder")?;

    let fvk = orchard::keys::FullViewingKey::from(registry_keys.orchard_spending_key());
    let address = fvk.address_at(0u32, orchard::keys::Scope::External);
    let name = request.name();

    let (action, ua_str, prev_commitment) = match &request {
        NameNoteRequest::Claim(b) => (Action::Claim, b.ua.as_str(), None),
        NameNoteRequest::Update(b) => (Action::Update, b.new_ua.as_str(), Some(b.prev_commitment)),
        NameNoteRequest::Release(b) => (Action::Release, "", Some(b.prev_commitment)),
    };

    if action == Action::Claim
        && registry
            .tip(name)
            .is_some_and(|tip| tip.action != Action::Release)
    {
        return Err("claim name became unavailable before assembly");
    }

    // 3. Spend previous Name Note if updating or releasing
    //
    // The previous Name Note is the exact validated Registry tip. It is not an
    // ordinary wallet note and is never selected by parsing arbitrary memos.
    if action == Action::Update || action == Action::Release {
        let tip = registry.tip(name).ok_or("tip not found in registry")?;
        if tip.commitment != prev_commitment.ok_or("request has no predecessor commitment")? {
            return Err("request predecessor does not match Registry tip");
        }
        let previous = tip
            .received()
            .ok_or("Registry tip has no validated Name Note")?;

        let merkle_path = wallet
            .ironwood_witness(previous.locator().position, anchor_height)
            .ok()
            .flatten()
            .ok_or("witness for previous note not found")?;

        builder
            .add_validated_zns_spend(
                fvk.clone(),
                previous.validated().clone(),
                merkle_path.into(),
            )
            .map_err(|_| "failed to add validated zns spend")?;
    }

    // 4. Create new ZNS output
    let (new_rcm, new_psi) = crate::mint::zns_psi_rcm(name, action, ua_str, prev_commitment);

    let memo = crate::mint::encode_name_note(name, action, ua_str, prev_commitment)
        .ok_or("failed to encode name note memo")?;

    let value = orchard::value::NoteValue::from_raw(0);

    builder
        .add_zns_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            address,
            value,
            memo,
            new_rcm,
            new_psi,
        )
        .map_err(|_| "failed to add zns output")?;

    // 5. Resolve only the exact fee notes retained in the caller's plan.
    let committed_spends = builder.spends().len();
    let mut funding_notes = Vec::with_capacity(fee_inputs.locators.len());
    let mut total_funded = 0u64;
    for locator in &fee_inputs.locators {
        let note = wallet
            .ironwood_note(*locator)
            .ok_or("selected Registry fee note no longer exists")?;
        if note.account_id != crate::mint::REGISTRY_ACCOUNT
            || crate::registry::liquidity::classify_registry_ironwood_note(note)
                != crate::registry::liquidity::RegistryNoteClass::Fee
        {
            return Err("selected input is not an ordinary Registry fee note");
        }
        total_funded = total_funded
            .checked_add(note.note.value().inner())
            .ok_or("Registry fee input value overflow")?;
        funding_notes.push(note.clone());
    }

    let funding_spends = funding_notes.len();
    let fee_without_change = registry_fee(target_height, committed_spends, funding_spends, false)?;
    let (fee, change) = if total_funded == fee_without_change {
        (fee_without_change, 0)
    } else {
        let fee_with_change = registry_fee(target_height, committed_spends, funding_spends, true)?;
        if total_funded < fee_with_change {
            return Err("selected Registry fee notes are insufficient for final shape");
        }
        (fee_with_change, total_funded - fee_with_change)
    };

    // Add the selected funding notes as standard Ironwood spends.
    for prev_note in &funding_notes {
        let merkle_path = wallet
            .ironwood_witness(prev_note.position, anchor_height)
            .ok()
            .flatten()
            .ok_or("witness for funding note not found")?;

        builder
            .add_spend(fvk.clone(), prev_note.note, merkle_path.into())
            .map_err(|_| "failed to add fee spend")?;
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
            .map_err(|_| "failed to add change output")?;
    }

    // 6. Build and verify value balance
    let (bundle, _meta) = builder
        .build::<zcash_protocol::value::ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build transaction")?
        .ok_or("builder produced no bundle")?;

    // Assert the bundle's value balance equals the intended fee. The Ironwood
    // value balance is (sum of spend values) - (sum of output values). For a
    // correctly balanced transaction, this equals the fee the network will
    // charge. A mismatch means the transaction is misbalanced or the fee was
    // computed wrong — either way it must not be broadcast.
    let actual_fee: i64 = bundle.value_balance().into();
    assert_eq!(
        actual_fee, fee as i64,
        "bundle value balance {} != intended fee {} — transaction is misbalanced",
        actual_fee, fee,
    );

    // Note: the full cryptographic self-verification (proof + commitment) is
    // performed by `verify_proof` in `signing::assemble_and_sign_transaction`.
    // The ZNS payload (rcm, ψ) → cmx path cannot be independently recomputed
    // outside the orchard circuit (it requires the fork's Sinsemilla hash),
    // so `verify_proof` is the authoritative check.

    Ok(bundle)
}
