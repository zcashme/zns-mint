//! Registry-only claim transaction assembly.
//!
//! A claim is a single V6 transaction whose Ironwood bundle is signed by the
//! Registry alone:
//!
//! - **Registry authority**: spends Registry fee notes, creates the value-0
//!   Name Note (a self-send to the Registry account), and creates Registry
//!   change for the remaining fee value.
//!
//! The Treasury is **not** involved in the claim transaction. The user's
//! payment note is pure revenue — it sits in the Treasury wallet and is never
//! spent. The Mint verifies the payment off-chain (it sees the confirmed
//! Treasury note with a valid claim memo and sufficient value) before
//! authorizing the Registry to mint.
//!
//! # Value flow
//!
//! ```text
//! Bundle value balance = fee_note_value - 0 (Name Note) - registry_change
//! Total fee             = fee_note_value - registry_change
//! ```
//!
//! Overpayments are retained by the Treasury. No refund is issued.

use std::collections::BTreeSet;

use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::key::RegistryKeys;
use crate::mint::registry::authorize::{ClaimRequest, NameNoteRequest};
use crate::mint::registry::transaction::{self};
use crate::mint::signer;
use crate::mint::{Expiry, Name, UnifiedAddress};
use crate::mint::registry::Registry;
use crate::wallet::{NoteLocator, Wallet};

/// Assembles, proves, signs, and serializes a complete Registry-only claim
/// transaction.
///
/// Selects Registry fee notes, builds a single Ironwood bundle (Name Note +
/// fee spends + change), and signs it with the Registry key only. Returns the
/// txid, broadcast hex, and the reserved fee-note locators.
#[allow(clippy::too_many_arguments)]
pub fn execute_claim<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    registry: &Registry,
    registry_keys: &RegistryKeys,
    name: Name,
    ua: UnifiedAddress,
    excluded: &BTreeSet<NoteLocator>,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
) -> Result<(zcash_primitives::transaction::TxId, String, Vec<NoteLocator>), crate::mint::AssemblyError> {
    let claim_req = NameNoteRequest::Claim(ClaimRequest {
        name: name.clone(),
        ua: ua.clone(),
        expires_at: Expiry::Never,
    });
    let fee_inputs = transaction::select_registry_fee_inputs(
        network,
        wallet,
        &claim_req,
        target_height,
        excluded,
        0,
    )?;
    let bundle = transaction::build_transaction(
        network,
        wallet,
        registry,
        registry_keys,
        claim_req,
        &fee_inputs,
        anchor_height,
        target_height,
    )?;
    let tx = signer::assemble_v6_transaction(
        network,
        bundle,
        None,
        Some(registry_keys),
        None,
        target_height,
    )?;
    Ok((
        tx.txid(),
        signer::serialize_tx(&tx)?,
        fee_inputs.locators().iter().copied().collect(),
    ))
}

/// Validates a claim request, reserves the name, and assembles the transaction.
/// Returns `None` if the request is invalid or the name is already locked.
///
/// Deduplication is by note locator (`intake_seen` in `MintState`), not by
/// name — a failed claim on a live name must not block a future claim after
/// that name is released.
#[allow(clippy::too_many_arguments)]
pub fn process_claim<P: Parameters>(
    network: &P,
    name: crate::mint::Name,
    ua: &str,
    value: u64,
    confirmed_height: BlockHeight,
    cursor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &BTreeSet<NoteLocator>,
    wallet: &mut Wallet,
    registry: &Registry,
    registry_keys: &RegistryKeys,
    mint: &mut crate::mint::MintState,
) -> Option<crate::mint::RequestOutcome> {
    use crate::mint::{Action, NameNote, SubmissionKind, CLAIM_PRICE, RequestOutcome};

    // The single UA validation boundary: ZIP 316 grammar, receiver order,
    // network prefix. A UA without an Orchard receiver can never receive an
    // OTP — binding a name to one would brick it.
    let Some(ua) = NameNote::parse_ua(network, ua) else {
        return None;
    };
    if ua.orchard().is_none() {
        return None;
    }

    // Check availability first — no name-level dedup. A claim on a live name
    // is rejected here, but a future claim after release is still possible.
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
    if mint.is_name_locked(&name) {
        return None;
    }
    let name_binding = mint.name_binding(&name, record_commitment);
    let result = execute_claim(
        network,
        wallet,
        registry,
        registry_keys,
        name,
        ua,
        excluded,
        cursor_height,
        target_height,
    )
    .map(|(txid, hex, notes)| (SubmissionKind::Claim, txid, hex, notes));

    Some(RequestOutcome {
        result,
        name_binding: Some(name_binding),
        relay_otp: None,
    })
}