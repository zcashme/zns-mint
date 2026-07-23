//! Treasury transaction assembly.
//!
//! This module turns a matched claim payment into a signed, broadcastable Zcash
//! V6 transaction. The design is intentionally pool-specific:
//!
//! - The payment note is spent from the Treasury Orchard pool.
//! - The refund is sent back to the user as an Ironwood output to the Orchard
//!   receiver embedded in their unified address. This avoids the post-NU6.3
//!   Orchard cross-address transfer restriction while reusing the same
//!   `PostNu6_3` Halo2 prover that the Registry already caches.
//! - Treasury change returns to the Treasury Orchard internal address.
//!
//! The resulting transaction is a mixed-pool V6 transaction and is assembled
//! through [`crate::registry::signing::assemble_v6_transaction`], which follows
//! the upstream `zcash_primitives::transaction::Builder` sighash ordering and
//! reuses the cached proving/verifying keys.

use crate::key::TreasuryKeys;
use crate::mint::TREASURY_ACCOUNT;
use crate::treasury::memo::RequestMemo;
use crate::wallet::transaction::ReceivedOrchardNote;
use crate::wallet::Wallet;
use orchard::builder::{Builder as OrchardBuilder, BundleType};
use orchard::bundle::BundleVersion;
use orchard::keys::Scope;
use orchard::value::NoteValue;
use rand::rngs::OsRng;
use zcash_keys::address::Address;
use zcash_primitives::transaction::{
    fees::{transparent::InputSize, zip317::FeeRule as Zip317FeeRule, FeeRule as _},
    TxId,
};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkUpgrade, Parameters, MAIN_NETWORK},
    memo::MemoBytes,
    value::Zatoshis,
};

/// Tiny Treasury fee multiplier over the ZIP-317 network fee.
const TINY_FEE_MULTIPLIER: u64 = 10;

/// Returns the exact logical action counts for the refund bundle shape.
///
/// The counts are delegated to the Orchard fork's bundle policy instead of
/// being duplicated here. Orchard V3 disables cross-address transfers, so its
/// one payment spend and one change output occupy two actions. Ironwood V3
/// permits cross-address transfers, so its one output is padded to the default
/// two-action minimum.
fn refund_action_counts() -> Result<(usize, usize), &'static str> {
    let orchard_version = BundleVersion::orchard_v3();
    let ironwood_version = BundleVersion::ironwood_v3();

    let orchard_actions = BundleType::DEFAULT.num_actions(orchard_version.default_flags(), 1, 1)?;
    let ironwood_actions =
        BundleType::DEFAULT.num_actions(ironwood_version.default_flags(), 0, 1)?;

    Ok((orchard_actions, ironwood_actions))
}

/// Computes refund and Treasury change values for the approved fee policy.
fn refund_values(
    payment: Zatoshis,
    price: Zatoshis,
    network_fee: Zatoshis,
) -> Result<(Zatoshis, Zatoshis), &'static str> {
    let tiny_fee = (network_fee * TINY_FEE_MULTIPLIER).ok_or("tiny fee overflow")?;
    let minimum_payment = (price + tiny_fee).ok_or("minimum payment overflow")?;

    if payment < minimum_payment {
        return Err("payment is below the claim price plus Treasury fee");
    }

    let after_tiny_fee = (payment - tiny_fee).ok_or("payment too small for tiny fee")?;
    let refund = (after_tiny_fee - price).ok_or("refund value underflow")?;
    let treasury_revenue = (price + tiny_fee).ok_or("Treasury revenue overflow")?;
    let change = (treasury_revenue - network_fee).ok_or("Treasury change underflow")?;

    Ok((refund, change))
}

/// Inputs required to build a claim refund transaction.
pub struct RefundRequest<'a> {
    /// The Treasury Orchard note that paid for the claim.
    pub payment_note: &'a ReceivedOrchardNote,
    /// The parsed claim request (carries the name and destination UA).
    pub request: &'a RequestMemo,
    /// The claim price the user must pay.
    pub price: Zatoshis,
    /// The fully-applied height whose Orchard root witnesses the payment.
    pub anchor_height: BlockHeight,
    /// The next height at which the transaction should be mined.
    pub target_height: BlockHeight,
}

/// Builds and signs a Treasury claim refund transaction.
///
/// The refund transaction spends the incoming Orchard payment note and:
///
/// - refunds `payment - price - tiny_fee` to the user as an Ironwood output;
/// - sends Treasury change (`price + tiny_fee - network_fee`) back to the
///   Treasury Orchard internal address.
///
/// `tiny_fee` is defined as `10 * network_fee` where `network_fee` is the
/// ZIP-317 fee for the transaction shape. If the payment exactly equals
/// `price + tiny_fee`, the refund amount is zero and the transaction has a
/// value-0 Ironwood refund output.
///
/// Returns the transaction ID and the serialized transaction as a hex string.
///
/// # Errors
///
/// Returns an error if:
/// - the payment note is not a Treasury Orchard note,
/// - the payment memo is not the exact claim request being refunded,
/// - the destination unified address has no Orchard receiver,
/// - the payment is smaller than `price + tiny_fee`,
/// - NU6.3 is not active at the target height,
/// - a target-height Orchard witness or current Ironwood anchor is not available, or
/// - proof creation or signing fails.
pub fn build_refund_transaction(
    wallet: &mut Wallet,
    treasury_keys: &TreasuryKeys,
    refund: RefundRequest,
) -> Result<(TxId, String), &'static str> {
    let RefundRequest {
        payment_note,
        request,
        price,
        anchor_height,
        target_height,
    } = refund;

    if !MAIN_NETWORK.is_nu_active(NetworkUpgrade::Nu6_3, target_height) {
        return Err("refund transactions require NU6.3 activation");
    }

    if payment_note.account_id != TREASURY_ACCOUNT {
        return Err("payment note is not owned by the Treasury account");
    }

    let RequestMemo::Claim { name: _, ua } = request else {
        return Err("refund transactions are only valid for claim requests");
    };

    let observed_request = RequestMemo::parse(payment_note.memo.as_array())
        .map_err(|_| "payment memo is not a valid ZNS request")?;
    if &observed_request != request {
        return Err("payment memo does not match the refund request");
    }

    let payment_value = Zatoshis::from_u64(payment_note.note.value().inner())
        .map_err(|_| "payment value out of range")?;

    // Decode the user's unified address and extract its Orchard receiver.
    let Some(Address::Unified(ua)) = Address::decode(&MAIN_NETWORK, ua) else {
        return Err("claim UA is not a valid unified address");
    };
    let Some(refund_address) = ua.orchard().copied() else {
        return Err("claim UA does not contain an Orchard receiver; refunds to Sapling/Transparent are not yet supported");
    };

    // ZIP-317 fee for the exact requested bundle shape. The Ironwood output is
    // always present, including when its value is zero, so the shape is stable.
    let (orchard_actions, ironwood_actions) = refund_action_counts()?;
    let network_fee = Zip317FeeRule::standard()
        .fee_required(
            &MAIN_NETWORK,
            target_height,
            core::iter::empty::<InputSize>(),
            core::iter::empty::<usize>(),
            0,
            0,
            orchard_actions,
            ironwood_actions,
        )
        .map_err(|_| "fee computation overflow")?;
    let (refund_value, treasury_change_value) = refund_values(payment_value, price, network_fee)?;

    // Orchard anchor for spending the payment note.
    let orchard_anchor = wallet
        .orchard_anchor(anchor_height)
        .map_err(|_| "failed to read orchard anchor")?
        .ok_or("no orchard anchor at target height")?;

    let merkle_path: orchard::tree::MerklePath = wallet
        .orchard_witness(payment_note.position, anchor_height)
        .map_err(|_| "failed to read orchard witness")?
        .ok_or("no orchard witness for payment note")?
        .into();

    let ironwood_anchor = wallet
        .latest_ironwood_anchor()
        .map_err(|_| "failed to read ironwood anchor")?
        .ok_or("no current ironwood anchor")?;

    let treasury_ufvk = treasury_keys.fvk();
    let treasury_fvk = treasury_ufvk
        .orchard()
        .ok_or("Treasury has no Orchard key")?;

    // --- Orchard bundle: spend the payment note, return change to Treasury ---
    let orchard_bundle_version = BundleVersion::orchard_v3();
    let orchard_flags = orchard_bundle_version.default_flags();
    let mut orchard_builder = OrchardBuilder::new(
        BundleType::DEFAULT,
        orchard_bundle_version,
        orchard_flags,
        orchard_anchor.into(),
    )
    .map_err(|_| "invalid orchard bundle flags")?;

    orchard_builder
        .add_spend(treasury_fvk.clone(), payment_note.note, merkle_path)
        .map_err(|_| "failed to add orchard spend")?;

    let change_address = treasury_fvk.address_at(0u32, Scope::Internal);
    let change_ovk = Some(treasury_fvk.to_ovk(Scope::Internal));
    let empty_memo = MemoBytes::empty().into_bytes();
    orchard_builder
        .add_change_output(
            treasury_fvk.clone(),
            change_ovk,
            change_address,
            NoteValue::from_raw(treasury_change_value.into_u64()),
            empty_memo,
        )
        .map_err(|_| "failed to add orchard change output")?;

    let (orchard_unproven, _) = orchard_builder
        .build::<zcash_protocol::value::ZatBalance>(OsRng)
        .map_err(|_| "failed to build orchard bundle")?
        .ok_or("orchard bundle produced no actions")?;

    // --- Ironwood bundle: refund output to the user ---
    let ironwood_bundle_version = BundleVersion::ironwood_v3();
    let ironwood_flags = ironwood_bundle_version.default_flags();
    let mut ironwood_builder = OrchardBuilder::new(
        BundleType::DEFAULT,
        ironwood_bundle_version,
        ironwood_flags,
        ironwood_anchor.into(),
    )
    .map_err(|_| "invalid ironwood bundle flags")?;

    let refund_ovk = Some(treasury_fvk.to_ovk(Scope::External));
    ironwood_builder
        .add_output(
            refund_ovk,
            refund_address,
            NoteValue::from_raw(refund_value.into_u64()),
            MemoBytes::empty().into_bytes(),
        )
        .map_err(|_| "failed to add ironwood refund output")?;

    let (ironwood_unproven, _) = ironwood_builder
        .build::<zcash_protocol::value::ZatBalance>(OsRng)
        .map_err(|_| "failed to build ironwood bundle")?
        .ok_or("ironwood bundle produced no actions")?;

    // TX-003: independently verify that the bundles about to be signed pay the
    // exact fee calculated for their final logical-action shape.
    let aggregate_balance = (*orchard_unproven.value_balance()
        + *ironwood_unproven.value_balance())
    .ok_or("aggregate value balance overflow")?;
    let aggregate_fee = Zatoshis::try_from(aggregate_balance)
        .map_err(|_| "aggregate value balance is not a fee")?;
    if aggregate_fee != network_fee {
        return Err("aggregate value balance does not equal the ZIP-317 fee");
    }

    // --- Assemble and sign the mixed V6 transaction ---
    crate::registry::signing::assemble_v6_transaction(
        Some(orchard_unproven),
        Some(ironwood_unproven),
        Some(treasury_keys),
        None,
        None,
        target_height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::derive_treasury;
    use crate::mint::{Memo, UnifiedAddress as ZnsUnifiedAddress, REGISTRY_ACCOUNT};
    use crate::treasury::memo::RequestMemo;
    use crate::wallet::transaction::ReceivedOrchardNote;
    use incrementalmerkletree::Position;
    use orchard::note::Nullifier;
    use secrecy::Secret;
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::value::Zatoshis;
    use zip32::AccountId;

    fn test_seed() -> Secret<[u8; 32]> {
        Secret::new([7u8; 32])
    }

    fn test_treasury_keys() -> TreasuryKeys {
        derive_treasury(&test_seed())
    }

    /// A minimal wallet with an empty Orchard tree so that we can exercise the
    /// assembly error paths without requiring real chain data.
    #[test]
    fn refund_fails_without_anchor() {
        let keys = test_treasury_keys();
        let ufvk: UnifiedFullViewingKey = keys.fvk().clone();
        let mut wallet = Wallet::new([(AccountId::const_from_u32(0), ufvk)]);

        let keys_fvk = keys.fvk();
        let fvk = keys_fvk.orchard().unwrap();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Option::<orchard::note::Rho>::from(orchard::note::Rho::from_bytes(&[1u8; 32]))
            .expect("test rho is valid");
        let rseed = (0u8..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        let note = orchard::Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(1_000_000),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .expect("test note is valid");
        let nullifier =
            Option::<Nullifier>::from(Nullifier::from_bytes(&[0u8; 32])).expect("test nullifier");
        let mut payment = ReceivedOrchardNote {
            account_id: AccountId::const_from_u32(0),
            note,
            nullifier,
            memo: Memo::from_bytes(&[]).expect("temporary test memo"),
            position: Position::from(0),
            confirmed_height: 1u32.into(),
        };

        let ua = ZnsUnifiedAddress::from_string(
            keys.fvk()
                .default_address(zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys)
                .unwrap()
                .0
                .encode(&MAIN_NETWORK),
        );
        let request = RequestMemo::Claim {
            name: "alice".to_string(),
            ua: ua.as_str().to_string(),
        };
        let payment_memo = format!("ZNS:claim:alice:{}", ua.as_str());
        payment.memo = Memo::from_bytes(payment_memo.as_bytes()).expect("valid claim memo");

        let result = build_refund_transaction(
            &mut wallet,
            &keys,
            RefundRequest {
                payment_note: &payment,
                request: &request,
                price: Zatoshis::const_from_u64(100_000),
                anchor_height: 3_500_000u32.into(),
                target_height: 3_500_000u32.into(),
            },
        );

        assert_eq!(result, Err("no orchard anchor at target height"));

        let mut wrong_account = payment.clone();
        wrong_account.account_id = REGISTRY_ACCOUNT;
        assert_eq!(
            build_refund_transaction(
                &mut wallet,
                &keys,
                RefundRequest {
                    payment_note: &wrong_account,
                    request: &request,
                    price: Zatoshis::const_from_u64(100_000),
                    anchor_height: 3_500_000u32.into(),
                    target_height: 3_500_000u32.into(),
                },
            ),
            Err("payment note is not owned by the Treasury account")
        );

        let mut wrong_memo = payment.clone();
        wrong_memo.memo = Memo::from_bytes(b"ZNS:claim:bob:u1wrong").expect("valid request memo");
        assert_eq!(
            build_refund_transaction(
                &mut wallet,
                &keys,
                RefundRequest {
                    payment_note: &wrong_memo,
                    request: &request,
                    price: Zatoshis::const_from_u64(100_000),
                    anchor_height: 3_500_000u32.into(),
                    target_height: 3_500_000u32.into(),
                },
            ),
            Err("payment memo does not match the refund request")
        );

        assert_eq!(
            build_refund_transaction(
                &mut wallet,
                &keys,
                RefundRequest {
                    payment_note: &payment,
                    request: &request,
                    price: Zatoshis::const_from_u64(100_000),
                    anchor_height: 3_000_000u32.into(),
                    target_height: 3_000_000u32.into(),
                },
            ),
            Err("refund transactions require NU6.3 activation")
        );
    }

    #[test]
    fn refund_shape_has_four_zip317_actions() {
        assert_eq!(refund_action_counts(), Ok((2, 2)));
    }

    #[test]
    fn refund_values_balance_at_threshold_and_overpayment() {
        let fee = Zatoshis::const_from_u64(20_000);
        let price = Zatoshis::const_from_u64(100_000);
        let threshold = Zatoshis::const_from_u64(300_000);

        assert_eq!(
            refund_values(threshold, price, fee),
            Ok((
                Zatoshis::const_from_u64(0),
                Zatoshis::const_from_u64(280_000),
            ))
        );
        assert_eq!(
            refund_values(Zatoshis::const_from_u64(1_000_000), price, fee),
            Ok((
                Zatoshis::const_from_u64(700_000),
                Zatoshis::const_from_u64(280_000),
            ))
        );
    }

    #[test]
    fn refund_values_reject_underpayment() {
        assert_eq!(
            refund_values(
                Zatoshis::const_from_u64(299_999),
                Zatoshis::const_from_u64(100_000),
                Zatoshis::const_from_u64(20_000),
            ),
            Err("payment is below the claim price plus Treasury fee")
        );
    }
}
