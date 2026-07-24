//! OTP relay transaction assembly.
//!
//! The relay is a mixed V6 transaction because Orchard V3 disables
//! cross-address transfers (NU6.3 consensus rule). The Treasury cannot
//! send an Orchard note to the controller's address directly.
//!
//! Structure:
//! - **Orchard V3 bundle** (Treasury authority): spends the request note,
//!   creates Treasury change via `add_change_output`. Positive value
//!   balance leaves the Orchard pool.
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
use zcash_protocol::consensus::{Parameters, MAIN_NETWORK};

/// The result of building an OTP relay transaction.
pub struct RelayAssembly {
    pub txid: zcash_primitives::transaction::TxId,
    pub hex: String,
    pub reserved_notes: Vec<NoteLocator>,
}

fn extract_orchard_address(ua_str: &str) -> Option<orchard::Address> {
    let zaddr: zcash_address::ZcashAddress = ua_str.parse().ok()?;
    let parsed: ParsedAddress = zaddr
        .convert_if_network(MAIN_NETWORK.network_type())
        .ok()?;
    match parsed {
        ParsedAddress::Unified(ua) => ua.orchard().copied(),
        _ => None,
    }
}

/// Builds, proves, signs, and serializes an OTP relay transaction.
///
/// Mixed V6: Orchard spend + Ironwood output-only. The requester's payment
/// flows from the Orchard pool through the Ironwood pool to the controller.
#[allow(clippy::too_many_arguments)]
pub fn assemble_otp_relay(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    name: &Name,
    action: Action,
    controller_ua: &UnifiedAddress,
    otp: &OtpCode,
    request_note_locator: NoteLocator,
    request_note_value: u64,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
    _excluded: &std::collections::BTreeSet<orchard::note::Rho>,
) -> Result<RelayAssembly, &'static str> {
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    if action == Action::Claim {
        return Err("claims do not use OTPs");
    }

    let controller_orchard =
        extract_orchard_address(controller_ua.as_str()).ok_or("controller UA has no Orchard receiver")?;

    let memo = encode_otp_relay_memo(name, action, controller_ua, otp)
        .ok_or("failed to encode OTP relay memo")?;

    // --- Fee computation ---
    // Orchard V3 (cross-address disabled): 1 real spend + optional change.
    //   Without change: 1 action (spend + fabricated output). min_actions=2 → 2.
    //   With change: 2 actions (spend + change). min_actions=2 → 2.
    // Ironwood V3 (cross-address enabled): 1 output, 0 spends. min_actions=2 → 2.
    // Total logical_actions = 2 + 2 = 4.
    let fee = FeeRule::standard()
        .fee_required(
            &MAIN_NETWORK,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0, 0,
            2, // orchard_action_count (padded to min 2)
            2, // ironwood_action_count (padded to min 2)
        )
        .map(Zatoshis::into_u64)
        .map_err(|_| "ZIP-317 fee computation overflow")?;

    if request_note_value < fee {
        return Err("request note value insufficient for relay fee");
    }

    let relay_value = request_note_value - fee;

    // --- Orchard V3 bundle: spend request note, Treasury change ---
    let orchard_anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or("no orchard anchor at accepted anchor height")?;

    let orchard_version = orchard::bundle::BundleVersion::orchard_v3();
    let orchard_flags = orchard_version.default_flags();
    let mut orchard_builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        orchard_version,
        orchard_flags,
        orchard_anchor.into(),
    )
    .map_err(|_| "failed to create orchard builder")?;

    let fvk = orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());

    // Spend the request note.
    let (request_note, request_position) = {
        let note = wallet
            .orchard_note(request_note_locator)
            .ok_or("request note not found in wallet")?;
        if note.account_id != TREASURY_ACCOUNT {
            return Err("request note is not a Treasury note");
        }
        (note.note.clone(), note.position)
    };

    let merkle_path = wallet
        .orchard_witness(request_position, anchor_height)
        .ok()
        .flatten()
        .ok_or("witness for request note not found")?;

    orchard_builder
        .add_spend(fvk.clone(), request_note, merkle_path.into())
        .map_err(|_| "failed to add request note spend")?;

    // Treasury change (back to Treasury's own address — add_change_output,
    // not add_output, because Orchard V3 disables cross-address).
    if relay_value > 0 {
        let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6;
        orchard_builder
            .add_change_output(
                fvk.clone(),
                Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
                change_address,
                orchard::value::NoteValue::from_raw(0), // change is 0; relay_value goes to Ironwood
                change_memo,
            )
            .map_err(|_| "failed to add orchard change output")?;
    }

    let (orchard_bundle, _) = orchard_builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build orchard bundle")?
        .ok_or("orchard builder produced no bundle")?;

    // --- Ironwood V3 bundle: output-only, controller + OTP memo ---
    let ironwood_anchor = wallet
        .latest_ironwood_anchor()
        .ok()
        .flatten()
        .ok_or("no ironwood anchor available")?;

    let ironwood_version = orchard::bundle::BundleVersion::ironwood_v3();
    let ironwood_flags = ironwood_version.default_flags();
    let mut ironwood_builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        ironwood_version,
        ironwood_flags,
        ironwood_anchor.into(),
    )
    .map_err(|_| "failed to create ironwood builder")?;

    ironwood_builder
        .add_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            controller_orchard,
            orchard::value::NoteValue::from_raw(relay_value),
            memo,
        )
        .map_err(|_| "failed to add ironwood relay output")?;

    let (ironwood_bundle, _) = ironwood_builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build ironwood bundle")?
        .ok_or("ironwood builder produced no bundle")?;

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