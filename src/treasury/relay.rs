//! OTP relay transaction assembly.
//!
//! The relay is a mixed V6 transaction because Orchard V3 disables
//! cross-address transfers (NU6.3 consensus rule). The Treasury cannot
//! send an Orchard note to the controller's address directly.
//!
//! Structure:
//! - **Orchard V3 bundle** (Treasury authority): spends the request note.
//!   No change output — the full value leaves the Orchard pool as value
//!   balance. 1 action, padded to 2 by min_actions.
//! - **Ironwood V3 bundle** (output-only, no spend authority): creates one
//!   output to the controller's address with the OTP memo. Ironwood V3
//!   permits cross-address transfers, so `add_output` works.
//!
//! Value flows cross-pool: Orchard spend → Ironwood output to controller.
//! The requester funds the entire transaction.

use orchard::builder::BundleType;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::auth::{encode_otp_relay_memo, OtpCode};
use crate::key::TreasuryKeys;
use crate::mint::{Action, Name, UnifiedAddress, TREASURY_ACCOUNT};
use crate::wallet::{NoteLocator, Wallet};

use zcash_keys::address::Address as ParsedAddress;
use zcash_protocol::consensus::Parameters;
use crate::zcash::NETWORK;

/// Returns the exact request-note value for an OTP relay at `target_height`.
///
/// The relay has two padded Orchard-family bundles, so the user provides two
/// identical ZIP-317 fee units: one for the network and one for the original
/// controller.
pub fn required_relay_value(target_height: BlockHeight) -> Result<u64, crate::mint::AssemblyError> {
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    FeeRule::standard()
        .fee_required(
            &NETWORK,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            2,
            2,
        )
        .map(Zatoshis::into_u64)
        .map_err(|_| crate::mint::AssemblyError::FeeOverflow)?
        .checked_mul(2)
        .ok_or(crate::mint::AssemblyError::FeeOverflow)
}

/// The result of building an OTP relay transaction.
pub struct RelayAssembly {
    pub txid: zcash_primitives::transaction::TxId,
    pub hex: String,
    pub reserved_notes: Vec<NoteLocator>,
}

/// Extracts the Orchard receiver from a mainnet Unified Address.
///
/// Both OTP relay delivery and claim-excess settlement require an Orchard
/// receiver because their cross-pool outputs are Ironwood outputs.
pub(crate) fn extract_orchard_address(ua_str: &str) -> Option<orchard::Address> {
    let zaddr: zcash_address::ZcashAddress = ua_str.parse().ok()?;
    let parsed: ParsedAddress = zaddr
        .convert_if_network(NETWORK.network_type())
        .ok()?;
    match parsed {
        ParsedAddress::Unified(ua) => ua.orchard().copied(),
        _ => None,
    }
}

/// Builds, proves, signs, and serializes an OTP relay transaction.
///
/// Mixed V6: Orchard spend + Ironwood output-only. The requester provides
/// exactly twice the ZIP-317 fee: one fee funds the transaction and the other
/// is delivered to the current controller with the OTP relay memo.
#[allow(clippy::too_many_arguments)]
pub fn assemble_otp_relay(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    name: &Name,
    action: Action,
    controller_ua: &UnifiedAddress,
    requested_ua: &UnifiedAddress,
    otp: &OtpCode,
    request_note_locator: NoteLocator,
    request_note_value: u64,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
    _excluded: &std::collections::BTreeSet<orchard::note::Rho>,
) -> Result<RelayAssembly, crate::mint::AssemblyError> {
    use rand::rngs::OsRng;

    if action == Action::Claim {
        return Err(crate::mint::AssemblyError::ClaimNoOtp);
    }

    let controller_orchard =
        extract_orchard_address(controller_ua.as_str()).ok_or(crate::mint::AssemblyError::NoOrchardReceiver)?;

    let memo = encode_otp_relay_memo(name, action, requested_ua, otp)
        .ok_or(crate::mint::AssemblyError::MemoEncode)?;

    let required_value = required_relay_value(target_height)?;
    if request_note_value != required_value {
        return Err(crate::mint::AssemblyError::IncorrectRelayValue);
    }

    let relay_value = required_value / 2;

    // --- Orchard V3 bundle: spend request note, Treasury change ---
    let orchard_anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoAnchor)?;

    let orchard_version = orchard::bundle::BundleVersion::orchard_v3();
    let orchard_flags = orchard_version.default_flags();
    let mut orchard_builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        orchard_version,
        orchard_flags,
        orchard_anchor.into(),
    )
    .map_err(|_| crate::mint::AssemblyError::BuilderCreation)?;

    let fvk = orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());

    // Spend the request note.
    let (request_note, request_position) = {
        let note = wallet
            .orchard_note(request_note_locator)
            .ok_or(crate::mint::AssemblyError::NoteNotFound)?;
        if note.account_id != TREASURY_ACCOUNT {
            return Err(crate::mint::AssemblyError::WrongAccount);
        }
        (note.note.clone(), note.position)
    };

    let merkle_path = wallet
        .orchard_witness(request_position, anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoWitness)?;

    orchard_builder
        .add_spend(fvk.clone(), request_note, merkle_path.into())
        .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

    // No Orchard change output is needed: exactly one ZIP-317 fee leaves the
    // transaction and the matching fee-sized remainder enters Ironwood for the
    // original owner.
    // Without change: 1 spend + 0 outputs, cross-address disabled → 1 action,
    // padded to 2 by min_actions. Same action count as with a zero-value change.

    let (orchard_bundle, _) = orchard_builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| crate::mint::AssemblyError::BuildFailed)?
        .ok_or(crate::mint::AssemblyError::BuildFailed)?;

    // --- Ironwood V3 bundle: output-only, controller + OTP memo ---
    let ironwood_anchor = wallet
        .latest_ironwood_anchor()
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoAnchor)?;

    let ironwood_version = orchard::bundle::BundleVersion::ironwood_v3();
    let ironwood_flags = ironwood_version.default_flags();
    let mut ironwood_builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        ironwood_version,
        ironwood_flags,
        ironwood_anchor.into(),
    )
    .map_err(|_| crate::mint::AssemblyError::BuilderCreation)?;

    ironwood_builder
        .add_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            controller_orchard,
            orchard::value::NoteValue::from_raw(relay_value),
            memo,
        )
        .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

    let (ironwood_bundle, _) = ironwood_builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| crate::mint::AssemblyError::BuildFailed)?
        .ok_or(crate::mint::AssemblyError::BuildFailed)?;

    // --- Prove, sign, serialize both bundles in one V6 transaction ---
    use crate::registry::signing;
    let (txid, hex) = signing::assemble_v6_transaction(
        Some(orchard_bundle),
        Some(ironwood_bundle),
        Some(treasury_keys),
        None, // no Registry signer — Ironwood is output-only
        None,
        target_height,
    )?;

    Ok(RelayAssembly {
        txid,
        hex,
        reserved_notes: vec![request_note_locator],
    })
}

/// Validates an OTP relay request (update or release without OTP), reserves the
/// challenge, and assembles the relay transaction.
/// Returns `None` if the request is invalid or the challenge is already reserved.
#[allow(clippy::too_many_arguments)]
pub fn process_otp_relay(
    name: &crate::mint::Name,
    action: crate::mint::Action,
    requested_ua: &crate::mint::UnifiedAddress,
    controller_ua: &crate::mint::UnifiedAddress,
    tip_commitment: crate::mint::NameCommitment,
    locator: NoteLocator,
    value: u64,
    cursor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &std::collections::BTreeSet<NoteLocator>,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    ops: &mut crate::mint::OperationalState,
    seen_no_otp: &mut std::collections::BTreeSet<crate::auth::ChallengeKey>,
) -> Option<crate::mint::RequestOutcome> {
    use crate::auth::{ChallengeKey, OtpCode};
    use crate::mint::{SubmissionKind, RequestOutcome, has_orchard_receiver};

    let key = ChallengeKey::new(name.clone(), action, requested_ua.clone(), tip_commitment);
    if ops.pending_otps.contains(&key)
        || ops.pending_otps.is_challenge_reserved(&key)
        || seen_no_otp.contains(&key)
    {
        return None;
    }
    if required_relay_value(target_height).ok() != Some(value) {
        crate::metrics::inc_request_invalid("incorrect_relay_value");
        return None;
    }
    if !has_orchard_receiver(controller_ua) {
        crate::metrics::inc_request_invalid("no_orchard_receiver");
        return None;
    }
    crate::metrics::inc_request_received(action.as_str());
    seen_no_otp.insert(key.clone());

    let name_binding = ops.name_binding(name, Some(tip_commitment));
    if !ops.pending_otps.reserve_challenge(&key) {
        return None;
    }
    let otp = OtpCode::generate();
    let excluded_rhos = crate::wallet::treasury_excluded_rhos(excluded);
    let result = assemble_otp_relay(
        wallet,
        treasury_keys,
        name,
        action,
        controller_ua,
        requested_ua,
        &otp,
        locator,
        value,
        cursor_height,
        target_height,
        &excluded_rhos,
    )
    .map(|r| (SubmissionKind::OtpRelay, r.txid, r.hex, r.reserved_notes));

    Some(RequestOutcome {
        result,
        name_lock: None,
        name_binding: Some(name_binding),
        relay_challenge: Some((key, otp)),
    })
}
