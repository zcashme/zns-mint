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
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::Memo;
use zcash_protocol::value::Zatoshis;

use crate::mint::TREASURY_ACCOUNT;
use crate::wallet::Wallet;

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
    // Protocol messages and the operating float share the Treasury account.
    // A Name Note fee must never consume some other message before its own
    // rule sees it, so only empty-memo notes are fee candidates.
    notes.retain(|note| {
        matches!(
            wallet.get_memo(*note.internal_note_id()),
            Ok(None) | Ok(Some(Memo::Empty))
        )
    });
    notes.sort_by_key(|note| std::cmp::Reverse(note.note().value().inner()));
    notes
}

/// Minimum spendable Treasury balance to trigger a vault sweep (2 ZEC).
pub const SWEEP_THRESHOLD: Zatoshis = Zatoshis::const_from_u64(200_000_000);

/// Amount retained as Treasury change after a sweep (0.01 ZEC): the
/// operating float that funds the next Name Note's fee.
pub const SWEEP_RESERVE: Zatoshis = Zatoshis::const_from_u64(1_000_000);

/// The project vault's P2PKH address (placeholder pending final approved
/// address).
pub const VAULT_ADDRESS: transparent::address::TransparentAddress =
    transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]);

/// Sweeps all spendable Treasury Sapling notes to the project vault.
/// Send-max: no reserve — Sapling is a legacy pool for the mint, nothing
/// ZNS ever spends from it. Returns `Ok(None)` when the balance is zero.
pub fn sweep_sapling_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Result<
    Option<zcash_primitives::transaction::TxId>,
    zcash_client_backend::data_api::wallet::CreateErrT<
        Wallet,
        GreedyInputSelectorError,
        zcash_client_backend::fees::StandardFeeRule,
        zcash_primitives::transaction::fees::zip317::FeeError,
        NoteId,
    >,
> {
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
