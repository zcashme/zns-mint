//! Atomic claim transaction assembly.
//!
//! An atomic claim is one V6 transaction that settles the user's name payment
//! and creates the value-0 Name Note in a single indivisible operation:
//!
//! - **Orchard bundle** (Treasury authority): spends the user's payment note
//!   received at the Treasury address and creates a Treasury-controlled change
//!   output equal to the fixed claim price. Its remaining positive value
//!   balance moves to Ironwood for the excess-refund output.
//!
//! - **Ironwood bundle** (Registry authority): creates the new Name Note
//!   (value 0), returns the excess to the claimed Unified Address's Orchard
//!   receiver, spends Registry fee notes, and creates Registry change. The
//!   Registry funds the complete transaction's aggregate ZIP-317 fee.
//!
//! Both bundles share one V6 sighash via [`assemble_v6_transaction`]. The
//! Orchard bundle is signed with the Treasury spending key; the Ironwood
//! bundle is signed with the Registry spending key.
//!
//! # Value flow
//!
//! ```text
//! Orchard value balance  = payment_value - price   (spend, Treasury change)
//! Ironwood value balance  = fee_note_value
//!                         - refund_value
//!                         - change_value
//! Total fee              = payment_value
//!                         - price
//!                         + fee_note_value
//!                         - refund_value
//!                         - change_value
//!                        = ironwood_fee
//! ```
//!
//! where `refund_value = payment_value - price` and `change_value =
//! fee_note_value - ironwood_fee`.

use orchard::builder::{BundleType, InProgress, Unauthorized, Unproven};
use orchard::bundle::BundleVersion;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::ZatBalance;

use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::{Name, UnifiedAddress};
use crate::registry::Registry;
use crate::registry::transaction::{self, RegistryFeeInputs};
use crate::registry::signing;
use crate::wallet::{NoteLocator, Wallet};

/// The result of assembling an atomic claim: both unproven bundles and the
/// refund value, ready for [`signing::assemble_v6_transaction`].
pub struct ClaimAssembly {
    pub orchard_bundle:
        Option<orchard::Bundle<InProgress<Unproven, Unauthorized>, ZatBalance>>,
    pub ironwood_bundle:
        orchard::Bundle<InProgress<Unproven, Unauthorized>, ZatBalance>,
    pub refund_value: u64,
    pub payment_locator: NoteLocator,
}

/// Builds the Orchard (Treasury) side of the atomic claim: spends the payment
/// note and returns exactly `price` to Treasury-owned change.
///
/// Orchard V3 forbids cross-address outputs, so the excess becomes this
/// bundle's positive value balance and is settled by the paired Ironwood
/// refund output.
fn build_treasury_orchard_bundle(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    payment_locator: NoteLocator,
    price: u64,
    anchor_height: BlockHeight,
) -> Result<
    (
        orchard::Bundle<InProgress<Unproven, Unauthorized>, ZatBalance>,
        u64,
    ),
    crate::mint::AssemblyError,
> {
    use rand::rngs::OsRng;

    let anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoAnchor)?;

    let bundle_version = BundleVersion::orchard_v3();
    let flags = bundle_version.default_flags();
    let mut builder =
        orchard::builder::Builder::new(BundleType::DEFAULT, bundle_version, flags, anchor.into())
            .map_err(|_| crate::mint::AssemblyError::BuilderCreation)?;

    let fvk = orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());

    let (note, position, payment_value) = {
        let note = wallet
            .orchard_note(payment_locator)
            .ok_or(crate::mint::AssemblyError::NoteNotFound)?;
        if note.account_id != crate::mint::TREASURY_ACCOUNT {
            return Err(crate::mint::AssemblyError::WrongAccount);
        }
        (note.note.clone(), note.position, note.note.value().inner())
    };

    if payment_value < price {
        return Err(crate::mint::AssemblyError::InsufficientValue);
    }

    let merkle_path = wallet
        .orchard_witness(position, anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoWitness)?;

    builder
        .add_spend(fvk.clone(), note, merkle_path.into())
        .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

    let treasury_change = fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let mut change_memo = [0u8; 512];
    change_memo[0] = 0xF6; // ZIP-302 empty memo
    builder
        .add_change_output(
            fvk.clone(),
            Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
            treasury_change,
            orchard::value::NoteValue::from_raw(price),
            change_memo,
        )
        .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

    let (bundle, _meta) = builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| crate::mint::AssemblyError::BuildFailed)?
        .ok_or(crate::mint::AssemblyError::BuildFailed)?;

    Ok((bundle, payment_value))
}

/// Assembles the complete atomic claim transaction: both Orchard and Ironwood
/// bundles, proven, signed, and serialized into broadcastable hex.
///
/// # Parameters
///
/// - `wallet`: the canonical wallet (mutated for witness lookup)
/// - `registry`: the canonical name-chain state
/// - `treasury_keys`: Treasury spending key (signs the Orchard bundle)
/// - `registry_keys`: Registry spending key (signs the Ironwood bundle)
/// - `name`: the canonical name to claim
/// - `ua`: the unified address to bind the name to
/// - `payment_locator`: the exact Treasury Orchard note carrying the payment
/// - `fee_inputs`: the exact Registry fee notes selected for funding
/// - `price`: the claim price in zatoshis (Treasury retains this)
/// - `anchor_height`: the fully-applied cursor height for witness binding
/// - `target_height`: the next mineable height for fee and expiry binding
#[allow(clippy::too_many_arguments)]
pub fn assemble_atomic_claim(
    wallet: &mut Wallet,
    registry: &Registry,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    name: Name,
    ua: UnifiedAddress,
    payment_locator: NoteLocator,
    fee_inputs: &RegistryFeeInputs,
    price: u64,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
) -> Result<(zcash_primitives::transaction::TxId, String, u64), crate::mint::AssemblyError> {
    // 1. Build the Treasury Orchard bundle (payment spend, one-ZEC change).
    let (orchard_bundle, payment_value) = build_treasury_orchard_bundle(
        wallet,
        treasury_keys,
        payment_locator,
        price,
        anchor_height,
    )?;

    let refund_value = payment_value - price;

    // 2. Build the Registry Ironwood bundle (Name Note + refund + fee + change).
    //
    // Ironwood allows the cross-address transfer required to return excess to
    // the claimed UA. A claim without an Orchard receiver is not settleable.
    let refund_address = crate::treasury::relay::extract_orchard_address(ua.as_str())
        .ok_or(crate::mint::AssemblyError::NoOrchardReceiver)?;

    let ironwood_bundle = transaction::build_transaction(
        wallet,
        registry,
        registry_keys,
        crate::registry::authorize::NameNoteRequest::Claim(
            crate::registry::authorize::ClaimRequest { name, ua },
        ),
        fee_inputs,
        anchor_height,
        target_height,
        Some((refund_address, refund_value)),
        2,
    )?;

    // 3. Prove, sign, and serialize both bundles in one V6 transaction.
    let (txid, hex) = signing::assemble_v6_transaction(
        Some(orchard_bundle),
        Some(ironwood_bundle),
        Some(treasury_keys),
        Some(registry_keys),
        None,
        target_height,
    )?;

    Ok((txid, hex, refund_value))
}

/// Assembles, proves, signs, and serializes a complete atomic claim transaction.
///
/// This is the complete claim path: selects Registry fee notes, then calls
/// [`assemble_atomic_claim`] to build both the Treasury Orchard bundle
/// (payment spend + change) and the Registry Ironwood bundle (Name Note +
/// refund + fee + change), and signs them into one broadcastable V6 transaction.
#[allow(clippy::too_many_arguments)]
pub fn execute_claim(
    wallet: &mut Wallet,
    registry: &Registry,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    name: Name,
    ua: UnifiedAddress,
    payment_locator: NoteLocator,
    excluded: &std::collections::BTreeSet<NoteLocator>,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
) -> Result<(zcash_primitives::transaction::TxId, String, Vec<NoteLocator>), crate::mint::AssemblyError> {
    let claim_req = crate::registry::authorize::NameNoteRequest::Claim(
        crate::registry::authorize::ClaimRequest {
            name: name.clone(),
            ua: ua.clone(),
        },
    );
    let fee_inputs = crate::registry::transaction::select_registry_fee_inputs(
        wallet,
        &claim_req,
        target_height,
        excluded,
        1,
        2,
    )?;
    let (txid, hex, _) = assemble_atomic_claim(
        wallet,
        registry,
        treasury_keys,
        registry_keys,
        name.clone(),
        ua.clone(),
        payment_locator,
        &fee_inputs,
        crate::mint::CLAIM_PRICE,
        anchor_height,
        target_height,
    )?;
    let mut reserved: Vec<NoteLocator> = fee_inputs.locators().iter().copied().collect();
    reserved.push(payment_locator);
    Ok((txid, hex, reserved))
}

/// Validates a claim request, reserves the name, and assembles the transaction.
/// Returns `None` if the request is invalid or the name is already locked.
#[allow(clippy::too_many_arguments)]
pub fn process_claim(
    name: crate::mint::Name,
    ua: &str,
    locator: NoteLocator,
    value: u64,
    confirmed_height: BlockHeight,
    cursor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &std::collections::BTreeSet<NoteLocator>,
    wallet: &mut Wallet,
    registry: &Registry,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    ops: &mut crate::mint::OperationalState,
    seen_claims: &mut std::collections::BTreeSet<crate::mint::Name>,
) -> Option<crate::mint::RequestOutcome> {
    use crate::mint::{Action, SubmissionKind, CLAIM_PRICE, RequestOutcome};

    if seen_claims.contains(&name) {
        return None;
    }
    let available = match registry.tip(&name) {
        None => true,
        Some(t) => t.action == Action::Release,
    };
    if !available {
        return None;
    }
    if value < CLAIM_PRICE {
        crate::metrics::inc_request_invalid("insufficient_payment");
        return None;
    }
    if registry
        .tip(&name)
        .is_some_and(|tip| confirmed_height <= tip.confirmed_height)
    {
        crate::metrics::inc_request_invalid("stale_payment");
        return None;
    }
    crate::metrics::inc_request_received("claim");
    seen_claims.insert(name.clone());

    let tip_commitment = registry.tip(&name).map(|tip| tip.commitment);
    let lock = ops.reserve_name(&name, tip_commitment)?;
    let name_binding = lock.binding();
    let result = execute_claim(
        wallet,
        registry,
        treasury_keys,
        registry_keys,
        name,
        crate::mint::UnifiedAddress::from_string(ua.to_string()),
        locator,
        excluded,
        cursor_height,
        target_height,
    )
    .map(|(txid, hex, notes)| (SubmissionKind::Claim, txid, hex, notes));

    Some(RequestOutcome {
        result,
        name_lock: Some(lock),
        name_binding: Some(name_binding),
        relay_challenge: None,
    })
}
