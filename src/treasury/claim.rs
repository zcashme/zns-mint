//! Atomic claim transaction assembly.
//!
//! An atomic claim is one V6 transaction that settles the user's name payment
//! and creates the value-0 Name Note in a single indivisible operation:
//!
//! - **Orchard bundle** (Treasury authority): spends the user's payment note
//!   received at the Treasury address. No Orchard output — the full payment
//!   value becomes part of the transaction fee. The Treasury "retains" the
//!   `price` portion; the `payment - price` excess is returned via an
//!   Ironwood refund output in the Ironwood bundle.
//!
//! - **Ironwood bundle** (Registry authority): creates the new Name Note
//!   (value 0), creates an Ironwood refund output to the Treasury's internal
//!   address (`payment - price`, always present including value-zero), spends
//!   Registry fee notes, and creates Registry change. The Registry funds the
//!   complete transaction's aggregate ZIP-317 fee.
//!
//! Both bundles share one V6 sighash via [`assemble_v6_transaction`]. The
//! Orchard bundle is signed with the Treasury spending key; the Ironwood
//! bundle is signed with the Registry spending key.
//!
//! # Value flow
//!
//! ```text
//! Orchard value balance  = payment_value           (spend, no output)
//! Ironwood value balance  = fee_note_value
//!                         - refund_value
//!                         - change_value
//! Total fee              = payment_value
//!                         + fee_note_value
//!                         - refund_value
//!                         - change_value
//!                        = price + ironwood_fee
//! ```
//!
//! where `refund_value = payment_value - price` and `change_value =
//! fee_note_value - ironwood_fee - refund_value`.

use orchard::builder::{BundleType, InProgress, Unauthorized, Unproven};
use orchard::bundle::BundleVersion;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::ZatBalance;

use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::{Name, UnifiedAddress};
use crate::registry::state::Registry;
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

/// Builds the Orchard (Treasury) side of the atomic claim: spends the
/// payment note, no outputs.
///
/// The full payment value contributes to the transaction fee. The Treasury
/// "retains" `price`; the excess `payment - price` is returned via an
/// Ironwood refund output in the Ironwood bundle.
fn build_treasury_orchard_bundle(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    payment_locator: NoteLocator,
    anchor_height: BlockHeight,
) -> Result<
    (
        orchard::Bundle<InProgress<Unproven, Unauthorized>, ZatBalance>,
        u64,
    ),
    &'static str,
> {
    use rand::rngs::OsRng;

    let anchor = wallet
        .orchard_anchor(anchor_height)
        .ok()
        .flatten()
        .ok_or("no orchard anchor at accepted anchor height")?;

    let bundle_version = BundleVersion::orchard_v3();
    let flags = bundle_version.default_flags();
    let mut builder =
        orchard::builder::Builder::new(BundleType::DEFAULT, bundle_version, flags, anchor.into())
            .map_err(|_| "failed to create orchard builder")?;

    let fvk = orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());

    let (note, position, payment_value) = {
        let note = wallet
            .orchard_note(payment_locator)
            .ok_or("payment note not found in wallet")?;
        if note.account_id != crate::mint::TREASURY_ACCOUNT {
            return Err("payment note is not a Treasury note");
        }
        (note.note.clone(), note.position, note.note.value().inner())
    };

    let merkle_path = wallet
        .orchard_witness(position, anchor_height)
        .ok()
        .flatten()
        .ok_or("witness for payment note not found")?;

    builder
        .add_spend(fvk, note, merkle_path.into())
        .map_err(|_| "failed to add treasury payment spend")?;

    let (bundle, _meta) = builder
        .build::<ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build orchard bundle")?
        .ok_or("orchard builder produced no bundle")?;

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
) -> Result<(zcash_primitives::transaction::TxId, String, u64), &'static str> {
    // 1. Build the Treasury Orchard bundle (payment spend, no outputs).
    let (orchard_bundle, payment_value) = build_treasury_orchard_bundle(
        wallet,
        treasury_keys,
        payment_locator,
        anchor_height,
    )?;

    if payment_value < price {
        return Err("payment value is below the claim price");
    }

    let refund_value = payment_value - price;

    // 2. Build the Registry Ironwood bundle (Name Note + refund + fee + change).
    //
    // The refund is an Ironwood output to the Treasury's internal address.
    // It is always present (even if value is 0) per the protocol: the refund
    // output is the mechanism that returns excess payment to the user.
    let treasury_fvk =
        orchard::keys::FullViewingKey::from(treasury_keys.orchard_spending_key());
    let refund_address = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);

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