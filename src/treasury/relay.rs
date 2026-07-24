//! OTP relay transaction assembly.
//!
//! An OTP relay is a Treasury-origin transaction that delivers the OTP
//! challenge to the current name controller. The current controller is the
//! address bound to the name's live Name Note tip.
//!
//! The relay uses a standard Orchard bundle (Treasury authority) that:
//! 1. Spends Treasury Orchard notes for fee funding.
//! 2. Creates an output to the controller's Orchard receiver with the OTP
//!    relay memo (`ZNS:otp:<name>:<verb>:<ua>:<otp>`).
//! 3. Creates a change output to the Treasury's internal address.
//!
//! # Open design questions (from docs/design/09-transaction-assembly.md)
//!
//! - Non-Orchard controller handling: if the controller's UA has no Orchard
//!   receiver, the relay cannot be delivered via this path. The current
//!   implementation logs and skips.
//! - Output value: the relay output carries 0 zatoshis (just the memo).
//! - OVK recovery policy: the output uses the Treasury external OVK so the
//!   Treasury can recover the output if needed.

use orchard::builder::BundleType;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::ZatBalance;

use crate::auth::{encode_otp_relay_memo, OtpCode};
use crate::key::TreasuryKeys;
use crate::mint::{Action, Name, UnifiedAddress};
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
#[allow(clippy::too_many_arguments)]
pub fn assemble_otp_relay(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    name: &Name,
    action: Action,
    controller_ua: &UnifiedAddress,
    otp: &OtpCode,
    anchor_height: BlockHeight,
    target_height: BlockHeight,
    excluded: &std::collections::BTreeSet<orchard::note::Rho>,
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

    // 5. Add the OTP output to the controller (value 0, OTP memo).
    let value = orchard::value::NoteValue::from_raw(0);
    builder
        .add_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            controller_orchard,
            value,
            memo,
        )
        .map_err(|_| "failed to add OTP relay output")?;

    // 6. Estimate the fee and select Treasury funding notes.
    let num_outputs = 2usize; // OTP output + change
    let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);

    // Clone note data out of wallet references to avoid borrow conflicts.
    // Each entry: (note, position, value)
    let mut funding_notes: Vec<(orchard::note::Note, incrementalmerkletree::Position, u64)> =
        Vec::new();
    let mut total_funded = 0u64;
    let mut reserved_notes = Vec::new();
    let mut fee;

    loop {
        let num_spends = funding_notes.len();
        let actions = std::cmp::max(num_spends, num_outputs);
        fee = FeeRule::standard()
            .fee_required(
                &MAIN_NETWORK,
                target_height,
                std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
                std::iter::empty::<usize>(),
                0,
                0,
                0,
                actions,
            )
            .map(zcash_protocol::value::Zatoshis::into_u64)
            .map_err(|_| "ZIP-317 fee computation overflow")?;

        if total_funded >= fee {
            break;
        }

        let mut excluded_with_reserved = excluded.clone();
        for (note, _, _) in &funding_notes {
            excluded_with_reserved.insert(note.rho());
        }

        let candidate = wallet
            .orchard_notes_for(crate::mint::TREASURY_ACCOUNT)
            .filter(|n| !excluded_with_reserved.contains(&n.note.rho()))
            .filter(|n| n.note.value().inner() > 0)
            .min_by_key(|n| n.note.value().inner());

        let Some(note_ref) = candidate else {
            return Err("insufficient Treasury notes for OTP relay fee");
        };

        let val = note_ref.note.value().inner();
        total_funded += val;
        funding_notes.push((note_ref.note.clone(), note_ref.position, val));
    }

    // 7. Add the funding spends.
    for (note, position, _) in &funding_notes {
        let merkle_path = wallet
            .orchard_witness(*position, anchor_height)
            .ok()
            .flatten()
            .ok_or("witness for funding note not found")?;

        builder
            .add_spend(fvk.clone(), note.clone(), merkle_path.into())
            .map_err(|_| "failed to add treasury fee spend")?;

        reserved_notes.push(NoteLocator::orchard(
            crate::mint::TREASURY_ACCOUNT,
            note.rho(),
        ));
    }

    // 8. Add change output.
    let change_value = total_funded - fee;
    if change_value > 0 {
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6; // ZIP-302 empty memo

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