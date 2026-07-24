//! OTP relay transaction assembly.
//!
//! An OTP relay is a Treasury-origin Orchard transaction that delivers the
//! OTP challenge to the current name controller, funded by the requester's
//! payment.
//!
//! The relay is a standard Orchard bundle (Treasury authority) that:
//! 1. Spends the request note (the Treasury Orchard note carrying the
//!    `ZNS:update` or `ZNS:release` memo from the requester).
//! 2. Creates one output to the controller's Orchard receiver with the OTP
//!    relay memo. The output value is `request_value - network_fee`.
//!
//! One spend, one output, one action. The requester's payment flows through
//! to the controller minus the network fee. No change output, no Treasury
//! notes needed.
//!
//! # Protocol constraint
//!
//! The controller's UA must have an Orchard receiver. If it doesn't, the
//! mint rejects the request at reconciliation time.
//!
//! # OVK
//!
//! Treasury external OVK — audit trail. The OTP in the memo is already
//! burned by the time anyone would check.

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
/// One spend (request note), one output (controller + OTP memo), one action.
/// The requester funds the entire relay. No change output, no Treasury notes.
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

    let anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or("no orchard anchor at accepted anchor height")?;

    let bundle_version = orchard::bundle::BundleVersion::orchard_v3();
    let flags = bundle_version.default_flags();
    let mut builder =
        orchard::builder::Builder::new(BundleType::DEFAULT, bundle_version, flags, anchor.into())
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

    builder
        .add_spend(fvk.clone(), request_note, merkle_path.into())
        .map_err(|_| "failed to add request note spend")?;

    // Fee: 1 action (1 spend, 1 output).
    let fee = FeeRule::standard()
        .fee_required(
            &MAIN_NETWORK,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            1, // orchard_action_count
            0, // ironwood_action_count
        )
        .map(zcash_protocol::value::Zatoshis::into_u64)
        .map_err(|_| "ZIP-317 fee computation overflow")?;

    if request_note_value < fee {
        return Err("request note value insufficient for relay fee");
    }

    // One output to controller: request_value - fee.
    let relay_value = request_note_value - fee;

    builder
        .add_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            controller_orchard,
            orchard::value::NoteValue::from_raw(relay_value),
            memo,
        )
        .map_err(|_| "failed to add OTP relay output")?;

    let reserved_notes = vec![request_note_locator];

    // Build and verify.
    let (bundle, _) = builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build orchard bundle")?
        .ok_or("orchard builder produced no bundle")?;

    let actual_fee: i64 = bundle.value_balance().into();
    assert_eq!(actual_fee, fee as i64, "relay value balance mismatch");

    // Sign and serialize.
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