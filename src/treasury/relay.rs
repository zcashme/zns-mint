//! OTP relay transaction assembly.
//!
//! An OTP relay is a Treasury-origin Orchard transaction that delivers the
//! OTP challenge to the current name controller, funded by the requester's
//! payment.
//!
//! The relay is a standard Orchard bundle (Treasury authority) that:
//! 1. Spends the request note (the Treasury Orchard note carrying the
//!    `ZNS:update` or `ZNS:release` memo from the requester).
//! 2. Creates an output to the controller's Orchard receiver with the OTP
//!    relay memo (`ZNS:otp:<name>:<verb>:<ua>:<otp>`). The output value is
//!    `request_value - network_fee` — the requester's payment flows through
//!    to the controller.
//! 3. Creates a Treasury change output if there's residual value.
//!
//! The Treasury does not add its own notes — the requester funds the entire
//! relay. This provides sybil resistance: each update/release request costs
//! the requester ZEC, which flows to the controller.
//!
//! # Protocol constraint
//!
//! The controller's UA must have an Orchard receiver. If it doesn't, the
//! mint rejects the request at reconciliation time (before reaching this
//! assembly path). This is a protocol constraint: all ZNS UAs must have
//! an Orchard receiver so the Treasury can deliver OTP relay notes.
//!
//! # OVK recovery policy
//!
//! The relay output uses the Treasury external OVK so the Treasury can audit
//! its own relay outputs ("did we send this relay?"). The OTP in the memo is
//! ephemeral and already burned by the time anyone would check.

use orchard::builder::BundleType;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::ZatBalance;

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

/// Parses a unified address string and extracts the Orchard receiver.
///
/// Returns `None` if the string is not a valid UA or has no Orchard receiver.
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
/// The relay is funded entirely by the request note. The requester's payment
/// (minus the network fee) flows to the controller.
///
/// # Parameters
///
/// - `wallet`: the canonical wallet (mutated for witness lookup)
/// - `treasury_keys`: Treasury spending key (signs the Orchard bundle)
/// - `name`: the name being updated or released
/// - `action`: `Update` or `Release` (claims don't use OTPs)
/// - `controller_ua`: the current controller's unified address string
/// - `otp`: the freshly issued OTP code
/// - `request_note_locator`: the Treasury Orchard note carrying the request
/// - `request_note_value`: the value of the request note (for fee computation)
/// - `anchor_height`: the fully-applied cursor height
/// - `target_height`: the next mineable height
/// - `excluded`: Treasury note rhos already reserved by other in-flight txs
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

    // Only update and release use OTPs.
    if action == Action::Claim {
        return Err("claims do not use OTPs");
    }

    // 1. Parse the controller's UA to extract the Orchard receiver.
    let controller_orchard =
        extract_orchard_address(controller_ua.as_str()).ok_or("controller UA has no Orchard receiver")?;

    // 2. Encode the OTP relay memo.
    let memo = encode_otp_relay_memo(name, action, controller_ua, otp)
        .ok_or("failed to encode OTP relay memo")?;

    // 3. Get the Orchard anchor.
    let anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or("no orchard anchor at accepted anchor height")?;

    // 4. Initialize the Orchard builder.
    let bundle_version = orchard::bundle::BundleVersion::orchard_v3();
    let flags = bundle_version.default_flags();
    let mut builder =
        orchard::builder::Builder::new(BundleType::DEFAULT, bundle_version, flags, anchor.into())
            .map_err(|_| "failed to create orchard builder")?;

    let fvk = orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());

    // 5. Resolve and spend the request note.
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

    builder
        .add_spend(fvk.clone(), request_note, merkle_path.into())
        .map_err(|_| "failed to add request note spend")?;

    let reserved_notes = vec![request_note_locator];

    // 6. Compute the network fee.
    // 1 spend + 1 output (OTP relay) + optional change.
    // With 1 spend and 1 output, actions = max(1, 1) = 1.
    // If we need change, actions = max(1, 2) = 2.
    let fee_without_change = FeeRule::standard()
        .fee_required(
            &MAIN_NETWORK,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            1, // max(1 spend, 1 output) = 1
        )
        .map(zcash_protocol::value::Zatoshis::into_u64)
        .map_err(|_| "ZIP-317 fee computation overflow")?;

    let fee_with_change = FeeRule::standard()
        .fee_required(
            &MAIN_NETWORK,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            2, // max(1 spend, 2 outputs) = 2
        )
        .map(zcash_protocol::value::Zatoshis::into_u64)
        .map_err(|_| "ZIP-317 fee computation overflow")?;

    // 7. Add the OTP relay output to the controller.
    // The output value is request_value - fee.
    let (relay_value, fee) = if request_note_value > fee_with_change {
        // Enough for relay output + change.
        (request_note_value - fee_with_change, fee_with_change)
    } else if request_note_value > fee_without_change {
        // Enough for relay output but no change — the excess is the fee.
        (request_note_value - fee_without_change, fee_without_change)
    } else {
        // Not enough to cover even the minimum fee.
        return Err("request note value insufficient for relay fee");
    };

    builder
        .add_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            controller_orchard,
            orchard::value::NoteValue::from_raw(relay_value),
            memo,
        )
        .map_err(|_| "failed to add OTP relay output")?;

    // 8. Add Treasury change if there's residual value.
    let change_value = request_note_value - relay_value - fee;
    if change_value > 0 {
        let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6;

        builder
            .add_output(
                Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
                change_address,
                orchard::value::NoteValue::from_raw(change_value),
                change_memo,
            )
            .map_err(|_| "failed to add change output")?;
    }

    // 9. Build and verify value balance.
    let (bundle, _meta) = builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build orchard bundle")?
        .ok_or("orchard builder produced no bundle")?;

    let actual_fee: i64 = bundle.value_balance().into();
    assert_eq!(
        actual_fee, fee as i64,
        "OTP relay bundle value balance {} != intended fee {}",
        actual_fee, fee,
    );

    // 10. Sign and serialize.
    use crate::registry::signing;
    let (txid, hex) = signing::assemble_v6_transaction(
        Some(bundle),
        None,
        Some(treasury_keys),
        None,
        None,
        target_height,
    )?;

    Ok(RelayAssembly {
        txid,
        hex,
        reserved_notes,
    })
}