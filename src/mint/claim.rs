//! Atomic claim transaction assembly.
//!
//! An atomic claim is one V6 transaction whose single Ironwood bundle settles
//! the user's name payment and creates the value-0 Name Note in one
//! indivisible operation:
//!
//! - **Treasury authority, in the same bundle**: spends the user's payment
//!   note (an Ironwood note received at the Treasury address) and retains the
//!   fixed claim price as a Treasury change note.
//! - **Registry authority, in the same bundle**: creates the new Name Note
//!   (value 0), returns the excess to the claimed Unified Address's Orchard
//!   receiver, spends Registry fee notes, and creates Registry change.
//!
//! A V6 transaction carries exactly one `ironwood_bundle`, so both accounts
//! settle in it; per-action authority is resolved by spending key at signing
//! time. The bundle is signed by both the Treasury and Registry keys under one
//! shared V6 sighash.
//!
//! # Value flow
//!
//! ```text
//! Bundle value balance = payment_value + fee_note_value
//!                        - price                    (Treasury change)
//!                        - 0                        (Name Note)
//!                        - refund_value             (excess to claimant)
//!                        - registry_change
//! Total fee             = fee_note_value - registry_change
//! ```
//!
//! where `refund_value = payment_value - price`. The payment, price, and
//! refund cancel in-bundle; the Registry fee notes fund the aggregate ZIP-317
//! fee.

use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::registry::transaction::{self, RegistryFeeInputs};
use crate::mint::signer;
use crate::mint::{Name, UnifiedAddress};
use crate::mint::registry::Registry;
use crate::wallet::{NoteLocator, Wallet};

/// The Treasury side of an atomic claim, settled inside the same Ironwood
/// bundle as the Registry's Name Note.
///
/// One V6 transaction carries exactly one `ironwood_bundle`, so the payment
/// spend, the retained price, the refund, the Name Note, and the fee funding
/// must all coexist in one bundle signed by both authorities. Per-action
/// authority is resolved by key at signing time (`ak` matching). Bundling the
/// refund address with the payment makes the claim-only coupling structural:
/// transitions pass `None` and can never emit a refund.
#[derive(Clone, Debug)]
pub struct ClaimSettlement {
    /// The exact Treasury Ironwood note carrying the claim payment.
    pub locator: NoteLocator,
    /// The claim price retained by the Treasury as an Ironwood change note.
    pub price: u64,
    /// The claimed UA's Orchard receiver, where the payment excess is
    /// refunded (always emitted for claims, including value-zero).
    pub refund_address: orchard::Address,
}

/// Assembles the complete atomic claim transaction: one Ironwood bundle,
/// proven, signed by both authorities, and serialized into broadcastable hex.
///
/// # Parameters
///
/// - `wallet`: the canonical wallet (mutated for witness lookup)
/// - `registry`: the canonical name-chain state
/// - `treasury_keys`: Treasury spending key (signs the payment spend)
/// - `registry_keys`: Registry spending key (signs the Name Note and fee spends)
/// - `name`: the canonical name to claim
/// - `ua`: the unified address to bind the name to
/// - `payment_locator`: the exact Treasury Ironwood note carrying the payment
/// - `fee_inputs`: the exact Registry fee notes selected for funding
/// - `price`: the claim price in zatoshis (Treasury retains this)
/// - `anchor_height`: the fully-applied cursor height for witness binding
/// - `target_height`: the next mineable height for fee and expiry binding
#[allow(clippy::too_many_arguments)]
pub fn assemble_atomic_claim<P: Parameters>(
    network: &P,
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
) -> Result<(zcash_primitives::transaction::TxId, String), crate::mint::AssemblyError> {
    // The refund requires an Orchard receiver: the excess is returned as an
    // Ironwood output addressed to the claimed UA's Orchard receiver. A claim
    // without one is not settleable — and the controller could never receive
    // an OTP either.
    let refund_address = ua
        .orchard()
        .copied()
        .ok_or(crate::mint::AssemblyError::NoOrchardReceiver)?;

    let bundle = transaction::build_transaction(
        network,
        wallet,
        registry,
        registry_keys,
        crate::mint::registry::authorize::NameNoteRequest::Claim(
            crate::mint::registry::authorize::ClaimRequest {
                name,
                ua,
                expires_at: crate::mint::Expiry::Never,
            },
        ),
        fee_inputs,
        anchor_height,
        target_height,
        Some((
            treasury_keys,
            ClaimSettlement {
                locator: payment_locator,
                price,
                refund_address,
            },
        )),
    )?;

    // Prove, sign, and freeze the single bundle in one V6 transaction.
    // Both authorities sign: the bundle carries a Treasury payment spend and
    // Registry lifecycle spends.
    let tx = signer::assemble_v6_transaction(
        network,
        Some(bundle),
        Some(treasury_keys),
        Some(registry_keys),
        None,
        target_height,
    )?;
    Ok((tx.txid(), signer::serialize_tx(&tx)?))
}

/// Assembles, proves, signs, and serializes a complete atomic claim transaction.
///
/// This is the complete claim path: selects Registry fee notes, then calls
/// [`assemble_atomic_claim`] to build the single Ironwood bundle (payment
/// spend + price change + Name Note + refund + fee spends + change) and signs
/// it with both authorities into one broadcastable V6 transaction.
#[allow(clippy::too_many_arguments)]
pub fn execute_claim<P: Parameters>(
    network: &P,
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
    let claim_req = crate::mint::registry::authorize::NameNoteRequest::Claim(
        crate::mint::registry::authorize::ClaimRequest {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: crate::mint::Expiry::Never,
        }
    );
    // One extra output (the always-present refund) plus the Treasury
    // payment spend and price change in the same bundle.
    let fee_inputs = crate::mint::registry::transaction::select_registry_fee_inputs(
        network,
        wallet,
        &claim_req,
        target_height,
        excluded,
        1,
        true,
    )?;
    let (txid, hex) = assemble_atomic_claim(
        network,
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
pub fn process_claim<P: Parameters>(
    network: &P,
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
    mint: &mut crate::mint::MintState,
) -> Option<crate::mint::RequestOutcome> {
    use crate::mint::{Action, NameNote, SubmissionKind, CLAIM_PRICE, RequestOutcome};

    // The single UA validation boundary: ZIP 316 grammar, receiver order,
    // network prefix. A UA without an Orchard receiver can never receive an
    // OTP or a refund — binding a name to one would brick it.
    let Some(ua) = NameNote::parse_ua(network, ua) else {
        return None;
    };
    if ua.orchard().is_none() {
        return None;
    }

    if !mint.claim_check_and_mark(&name) {
        return None;
    }
    let available = match registry.record(&name) {
        None => true,
        Some(r) => r.action == Action::Release,
    };
    if !available {
        return None;
    }
    if value < CLAIM_PRICE {
        return None;
    }
    if registry
        .record(&name)
        .is_some_and(|record| confirmed_height <= record.confirmed_height)
    {
        return None;
    }

    let record_commitment = registry.record(&name).map(|record| record.commitment);
    let lock = mint.reserve_name(&name, record_commitment)?;
    let name_binding = lock.binding();
    let result = execute_claim(
        network,
        wallet,
        registry,
        treasury_keys,
        registry_keys,
        name,
        ua,
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
