//! OTP relay transaction assembly.
//!
//! One Ironwood V3 bundle: the Treasury spends the request note and delivers
//! the OTP memo plus the controller's compensation to the current controller's
//! Orchard receiver. Ironwood permits the cross-address transfer that NU6.3
//! forbids in the Orchard pool — the same rule that makes user requests
//! Ironwood notes in the first place.
//!
//! Value flow: the requester's note (exactly two ZIP-317 marginal fee units
//! for this bundle shape) is spent; one unit is the network fee and the other
//! is delivered to the controller with the OTP. The Treasury retains nothing.

use orchard::builder::BundleType;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::mint::otp::{encode_otp_relay_memo, OtpCode};
use crate::key::TreasuryKeys;
use crate::mint::{Action, Name, UnifiedAddress, TREASURY_ACCOUNT};
use crate::wallet::{NoteLocator, Wallet};


/// Returns the exact request-note value for an OTP relay at `target_height`.
///
/// The relay is a single Ironwood bundle with two actions (one padded spend of
/// the request note, one controller output), so the user provides two
/// identical ZIP-317 fee units: one for the network and one for the original
/// controller.
pub fn required_relay_value<P: Parameters>(
    network: &P,
    target_height: BlockHeight,
) -> Result<u64, crate::mint::AssemblyError> {
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    FeeRule::standard()
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
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
/// receiver because their cross-address outputs are Ironwood outputs.
pub(crate) fn extract_orchard_address(ua: &UnifiedAddress) -> Option<orchard::Address> {
    ua.orchard().copied()
}

/// Builds, proves, signs, and serializes an OTP relay transaction.
///
/// A single Ironwood bundle spends the request note under Treasury authority
/// and delivers one fee unit to the current controller with the OTP relay
/// memo. The requester provides exactly twice the ZIP-317 fee; the Treasury
/// retains no relay value.
#[allow(clippy::too_many_arguments)]
pub fn assemble_otp_relay<P: Parameters>(
    network: &P,
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
) -> Result<RelayAssembly, crate::mint::AssemblyError> {
    use rand::rngs::OsRng;

    if action == Action::Claim {
        return Err(crate::mint::AssemblyError::ClaimNoOtp);
    }

    let controller_orchard = extract_orchard_address(controller_ua)
        .ok_or(crate::mint::AssemblyError::NoOrchardReceiver)?;

    let memo = encode_otp_relay_memo(network, name, action, requested_ua, otp)
        .ok_or(crate::mint::AssemblyError::MemoEncode)?;

    let required_value = required_relay_value(network, target_height)?;
    if request_note_value != required_value {
        return Err(crate::mint::AssemblyError::IncorrectRelayValue);
    }

    let relay_value = required_value / 2;

    // One bundle, so the bundle spends and must bind its witnesses to an
    // exact-height Ironwood checkpoint root.
    let anchor = wallet
        .ironwood_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoAnchor)?;

    let bundle_version = orchard::bundle::BundleVersion::ironwood_v3();
    let flags = bundle_version.default_flags();
    let mut builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        bundle_version,
        flags,
        anchor.into(),
    )
    .map_err(|_| crate::mint::AssemblyError::BuilderCreation)?;

    let fvk = orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());

    // Spend the request note.
    let (request_note, request_position) = {
        let note = wallet
            .ironwood_note(request_note_locator)
            .ok_or(crate::mint::AssemblyError::NoteNotFound)?;
        if note.account_id != TREASURY_ACCOUNT {
            return Err(crate::mint::AssemblyError::WrongAccount);
        }
        (note.note.clone(), note.position)
    };

    let merkle_path = wallet
        .ironwood_witness(request_position, anchor_height)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoWitness)?;

    builder
        .add_spend(fvk.clone(), request_note, merkle_path.into())
        .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

    // Deliver the OTP and the controller's fee unit to the controller's
    // Orchard receiver. Cross-address is permitted in Ironwood.
    builder
        .add_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            controller_orchard,
            orchard::value::NoteValue::from_raw(relay_value),
            memo,
        )
        .map_err(|_| crate::mint::AssemblyError::BuilderAdd)?;

    // 1 spend + 1 output, padded to 2 actions. Bundle balance is exactly one
    // fee unit: the network fee.
    let (bundle, _) = builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| crate::mint::AssemblyError::BuildFailed)?
        .ok_or(crate::mint::AssemblyError::BuildFailed)?;

    // Prove, sign, and serialize the single Ironwood bundle in one V6
    // transaction. Only the Treasury signs: the bundle carries no Registry
    // spend.
    use crate::mint::v6;
    let tx = v6::assemble_v6_transaction(
        network,
        Some(bundle),
        Some(treasury_keys),
        None, // no Registry signer — the relay carries no Name Note authority
        None,
        target_height,
    )?;

    Ok(RelayAssembly {
        txid: tx.txid(),
        hex: v6::serialize_tx(&tx)?,
        reserved_notes: vec![request_note_locator],
    })
}

/// Validates an OTP relay request (update or release without OTP), reserves the
/// challenge, and assembles the relay transaction.
/// Returns `None` if the request is invalid or the challenge is already reserved.
#[allow(clippy::too_many_arguments)]
pub fn process_otp_relay<P: Parameters>(
    network: &P,
    name: &crate::mint::Name,
    action: crate::mint::Action,
    requested_ua: &crate::mint::UnifiedAddress,
    controller_ua: &crate::mint::UnifiedAddress,
    record_commitment: crate::mint::NameCommitment,
    locator: NoteLocator,
    value: u64,
    cursor_height: BlockHeight,
    target_height: BlockHeight,
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    ops: &mut crate::mint::OperationalState,
    seen_no_otp: &mut std::collections::BTreeSet<crate::mint::otp::ChallengeKey>,
) -> Option<crate::mint::RequestOutcome> {
    use crate::mint::otp::{ChallengeKey, OtpCode};
    use crate::mint::{SubmissionKind, RequestOutcome};

    let key = ChallengeKey::new(network, name.clone(), action, requested_ua.clone(), record_commitment);
    if ops.pending_otps.contains(&key)
        || ops.pending_otps.is_challenge_reserved(&key)
        || seen_no_otp.contains(&key)
    {
        return None;
    }
    if required_relay_value(network, target_height).ok() != Some(value) {
        return None;
    }
    if controller_ua.orchard().is_none() {
        return None;
    }
    seen_no_otp.insert(key.clone());

    let name_binding = ops.name_binding(name, Some(record_commitment));
    if !ops.pending_otps.reserve_challenge(&key) {
        return None;
    }
    let otp = OtpCode::generate();
    let result = assemble_otp_relay(
        network,
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
    )
    .map(|r| (SubmissionKind::OtpRelay, r.txid, r.hex, r.reserved_notes));

    Some(RequestOutcome {
        result,
        name_lock: None,
        name_binding: Some(name_binding),
        relay_challenge: Some((key, otp)),
    })
}
