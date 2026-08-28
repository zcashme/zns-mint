//! Treasury wallet view and Treasury policy for the mint.
//!
//! The Treasury is the user-facing account's agent (ZIP-32 account 0): it is
//! everything that account must do, and nothing more. Five responsibilities:
//!
//! 1. **Interpret intake** — claim payments and OTP relay requests arrive as
//!    Ironwood notes owned by the wallet; Treasury decodes their stored memos
//!    (`memo`) and classifies them. Treasury is keyless: it holds no keys and
//!    no notes of its own — not even viewing keys. Every fact it learns flows
//!    through a wallet projection, and every signing capability arrives as a
//!    borrowed argument.
//! 2. **Guarantee payment freshness** — a payment confirmed at or before the
//!    name's current tip is rejected; a payment cannot be reused after a
//!    release/reclaim boundary.
//! 3. **Participate in settlements** — the atomic claim (spend the payment
//!    note, retain the fixed price). OTP relay delivery is a mint-level
//!    concern ([`crate::mint::otp`]): an ordinary upstream-built Treasury
//!    payment to the current controller. Treasury never decides a name's
//!    lifecycle — that is the Registry's.
//! 4. **Deposit to the vault** — when the spendable balance exceeds
//!    the threshold, send the excess to the project vault's transparent
//!    address, retaining a fixed reserve.
//! 5. **Pay Name Note fees** — the Treasury funds the ZIP-317 fee for every
//!    Name Note transaction in a multi-authority bundle with the Registry.

use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError;
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::mint::{Action, Name, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// Parses a 512-byte memo sent to the Treasury as a ZNS transition request.
///
/// A request memo is `ZNS:<verb>:<name>:<ua>`, where `verb` is `claim`,
/// `update`, or `release`. OTPs are delivered through the separate relay-memo
/// path; request memos never carry an OTP.
///
/// Returns `None` unless the memo's grammar, name, and Unified Address for
/// `network` are all valid. The intake loop then tries
/// [`crate::mint::otp::decode_otp_relay_memo`] for non-request memos.
pub fn parse_request<P: Parameters>(
    network: &P,
    raw: &[u8; 512],
) -> Option<(Action, Name, UnifiedAddress)> {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    if raw[end..].iter().any(|b| *b != 0) {
        return None;
    }
    let text = core::str::from_utf8(&raw[..end]).ok()?;

    let mut fields = text.split(':');
    if fields.next()? != "ZNS" {
        return None;
    }
    let verb = fields.next()?;
    let name_str = fields.next()?;
    let name = Name::parse(name_str)?;

    let ua_str = fields.next()?;
    if ua_str.is_empty() {
        return None;
    }

    if fields.next().is_some() {
        return None;
    }

    let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
        zcash_keys::address::Address::Unified(ua) => ua,
        _ => return None,
    };

    let action = match verb {
        "claim" => Action::Claim,
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    Some((action, name, ua))
}

/// The Treasury's Ironwood fee-note candidates, largest value first.
///
/// The builder consumes these greedily (fewest notes → fewest actions →
/// lowest fee); the ordering here implements the Treasury's selection
/// policy so the builder stays a mechanical composer.
pub(crate) fn fee_note_candidates(
    wallet: &Wallet,
    tip: BlockHeight,
) -> Vec<ReceivedNote<NoteId, orchard::note::Note>> {
    let mut notes = wallet.unspent_ironwood_notes(
        TREASURY_ACCOUNT,
        zcash_client_backend::data_api::wallet::TargetHeight::from(tip),
    );
    notes.sort_by_key(|note| std::cmp::Reverse(note.note().value().inner()));
    notes
}

/// Minimum spendable Treasury balance to trigger a vault sweep (2 ZEC).
const SWEEP_THRESHOLD: Zatoshis = Zatoshis::const_from_u64(200_000_000);

/// Amount retained as Treasury change after a sweep (0.01 ZEC): the
/// operating float that funds the next Name Note's fee.
const SWEEP_RESERVE: Zatoshis = Zatoshis::const_from_u64(1_000_000);

/// The project vault's P2PKH address (placeholder pending final approved
/// address).
const VAULT_ADDRESS: transparent::address::TransparentAddress =
    transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]);

/// The upstream error surface of a vault sweep. Both the proposal and the
/// execution steps share this shape for our wallet: `Wallet`'s
/// commitment-tree error is [`Infallible`], and the single-output change
/// strategy's error is the ZIP-317 fee error, so both steps propagate with
/// `?` and no cause is discarded.
type SweepError = zcash_client_backend::data_api::wallet::CreateErrT<
    Wallet,
    GreedyInputSelectorError,
    zcash_client_backend::fees::StandardFeeRule,
    zcash_primitives::transaction::fees::zip317::FeeError,
    NoteId,
>;

/// Sweeps excess Treasury Ironwood balance to the project vault.
///
/// Retains [`SWEEP_RESERVE`]: the Ironwood float funds every future Name
/// Note fee and relay, so only the excess above [`SWEEP_THRESHOLD`] leaves.
/// Returns `Ok(None)` when the balance is at or below the threshold —
/// nothing to sweep is not an error.
pub fn sweep_ironwood_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Result<Option<zcash_primitives::transaction::TxId>, SweepError> {
    use zcash_client_backend::data_api::wallet::input_selection::{
        GreedyInputSelector, SpendPolicy,
    };
    use zcash_client_backend::data_api::wallet::{
        create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
    };
    use zcash_client_backend::data_api::WalletRead as _;
    use zcash_client_backend::fees::{
        standard::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule,
    };
    use zcash_client_backend::wallet::OvkPolicy;

    let summary = wallet
        .get_wallet_summary(ConfirmationsPolicy::new_symmetrical(
            std::num::NonZeroU32::MIN,
            false,
        ))
        .ok()
        .flatten();
    let spendable = summary
        .as_ref()
        .and_then(|s| s.account_balances().get(&TREASURY_ACCOUNT))
        .map(|b| b.ironwood_balance().spendable_value())
        .unwrap_or(Zatoshis::ZERO);
    if spendable <= SWEEP_THRESHOLD {
        return Ok(None);
    }

    // The threshold (2 ZEC) dwarfs the reserve (0.01 ZEC), so after the
    // threshold check the subtraction cannot fail.
    let sweep_amount = (spendable - SWEEP_RESERVE)
        .expect("spendable above SWEEP_THRESHOLD exceeds SWEEP_RESERVE");
    let recipient =
        zcash_keys::address::Address::Transparent(VAULT_ADDRESS).to_zcash_address(network);
    let payment = zip321::Payment::new(recipient, Some(sweep_amount), None, None, None, Vec::new())
        .expect("a transparent recipient with a nonzero amount cannot fail");
    let request = zip321::TransactionRequest::new(vec![payment])
        .expect("single-payment request cannot fail");

    let input_selector = GreedyInputSelector::new();
    let change_strategy = SingleOutputChangeStrategy::<Wallet>::new(
        StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );
    let proposal = propose_transfer(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::new_symmetrical(std::num::NonZeroU32::MIN, false),
        &SpendPolicy::shielded_pools([zcash_protocol::ShieldedPool::Ironwood]),
        None,
        None,
    )?;

    // Only the Treasury signs; the sweep carries no Registry authority.
    let spending_keys = SpendingKeys::new(treasury_keys.usk_clone());
    let txids = create_proposed_transactions(
        wallet,
        network,
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    )?;

    Ok(Some(*txids.first()))
}

/// Sweeps all spendable Treasury Sapling notes to the project vault.
/// Send-max: no reserve — Sapling is a legacy pool for the mint, nothing
/// ZNS ever spends from it. Returns `Ok(None)` when the balance is zero.
pub fn sweep_sapling_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Result<Option<zcash_primitives::transaction::TxId>, SweepError> {
    use zcash_client_backend::data_api::wallet::{
        create_proposed_transactions, propose_send_max_transfer, ConfirmationsPolicy, SpendingKeys,
    };
    use zcash_client_backend::data_api::{MaxSpendMode, WalletRead as _};
    use zcash_client_backend::fees::StandardFeeRule;
    use zcash_client_backend::wallet::OvkPolicy;
    let summary = wallet
        .get_wallet_summary(ConfirmationsPolicy::new_symmetrical(
            std::num::NonZeroU32::MIN,
            false,
        ))
        .ok()
        .flatten();
    let sapling_balance = summary
        .as_ref()
        .and_then(|s| s.account_balances().get(&TREASURY_ACCOUNT))
        .map(|b| b.sapling_balance().spendable_value())
        .unwrap_or(Zatoshis::ZERO);
    if sapling_balance == Zatoshis::ZERO {
        return Ok(None);
    }

    let vault_recipient =
        zcash_keys::address::Address::Transparent(VAULT_ADDRESS).to_zcash_address(network);
    let proposal = propose_send_max_transfer(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &[zcash_protocol::ShieldedPool::Sapling],
        &StandardFeeRule::Zip317,
        vault_recipient,
        None,
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::new_symmetrical(std::num::NonZeroU32::MIN, false),
        &zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::default(),
        None,
    )?;

    // Only the Treasury signs; the sweep carries no Registry authority.
    // The Sapling provers are invoked here: this sweep spends Sapling notes.
    let spending_keys = SpendingKeys::new(treasury_keys.usk_clone());
    let txids = create_proposed_transactions(
        wallet,
        network,
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    )?;

    Ok(Some(*txids.first()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    fn padded(s: &str) -> [u8; 512] {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m
    }

    #[test]
    fn accepts_exactly_the_three_request_forms() {
        let network = MainNetwork;

        let (action, name, _) =
            parse_request(&network, &padded(&format!("ZNS:claim:alice:{TEST_UA}"))).unwrap();
        assert_eq!(action, Action::Claim);
        assert_eq!(name.as_str(), "alice");

        let (action, name, _) =
            parse_request(&network, &padded(&format!("ZNS:update:alice:{TEST_UA}"))).unwrap();
        assert_eq!(action, Action::Update);
        assert_eq!(name.as_str(), "alice");

        let (action, name, _) =
            parse_request(&network, &padded(&format!("ZNS:release:alice:{TEST_UA}"))).unwrap();
        assert_eq!(action, Action::Release);
        assert_eq!(name.as_str(), "alice");
    }

    #[test]
    fn rejects_extra_field() {
        let network = MainNetwork;
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}:extra"))
        )
        .is_none());
    }

    #[test]
    fn rejects_unknown_verb() {
        let network = MainNetwork;
        assert!(parse_request(&network, &padded(&format!("ZNS:otp:alice:{TEST_UA}"))).is_none());
    }

    #[test]
    fn rejects_non_zns() {
        let network = MainNetwork;
        assert!(parse_request(&network, &padded("hello world")).is_none());
    }

    #[test]
    fn rejects_invalid_name() {
        let network = MainNetwork;
        assert!(
            parse_request(&network, &padded(&format!("ZNS:claim:INVALID:{TEST_UA}"))).is_none()
        );
    }
}
