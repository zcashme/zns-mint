//! Treasury wallet view and Treasury policy for the mint: the vault
//! sweep, the challenge relay builder, the request queue, and refunds
//! of underpaid payments.
//!

mod otp;
mod refund;

pub use otp::{OtpChallenge, OtpCode, OtpQueue, D_OTP};
pub use refund::{
    access_code_penalty, payment_against_quote, refund_output, PaymentAgainstQuote, Refund,
    RefundQueue,
};

use std::convert::Infallible;

use zcash_client_backend::data_api::error::Error;
use zcash_client_backend::data_api::locking::LockedInputPolicy;
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector;
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError;
use zcash_client_backend::data_api::wallet::input_selection::SpendPolicy;
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_send_max_transfer, propose_transfer, CreateErrT,
    ProposeTransferErrT,
};
use zcash_client_backend::data_api::{MaxSpendMode, WalletRead as _};
use zcash_client_backend::fees::zip317::SingleOutputChangeStrategy;
use zcash_client_backend::fees::{DustAction, DustOutputPolicy};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::util::SystemClock;
use zcash_client_backend::wallet::{NoteId, OvkPolicy};
use zcash_keys::address::Address;
use zcash_primitives::transaction::fees::zip317::{FeeError, FeeRule, MARGINAL_FEE};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, MainNetwork, NetworkType, Parameters, TestNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::{BalanceError, Zatoshis};
use zcash_protocol::ShieldedPool;
use zip321::{Payment, TransactionRequest};

use crate::mint::{Name, Request, UnifiedAddress, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

type TreasuryProposalError<P> = ProposeTransferErrT<
    Wallet<P>,
    Infallible,
    GreedyInputSelector<Wallet<P>>,
    SingleOutputChangeStrategy<FeeRule, Wallet<P>>,
>;
type TreasuryBuildError<P> =
    CreateErrT<Wallet<P>, GreedyInputSelectorError, FeeRule, FeeError, NoteId>;
type TreasuryProposal = Proposal<FeeRule, NoteId>;

/// Minimum vault payment for a sweep to fire (1 ZEC): a floor on what
/// actually moves, not on the balance behind it.
pub const SWEEP_MINIMUM: Zatoshis = Zatoshis::const_from_u64(100_000_000);

/// Amount retained as Treasury change after a sweep (0.01 ZEC): the
/// operating float that funds the next Name Note's fee.
pub const SWEEP_RESERVE: Zatoshis = Zatoshis::const_from_u64(1_000_000);

/// The relay sends no value — the memo is the message. The
/// transaction's ZIP-317 fee is calculated separately.
pub const CHALLENGE_RELAY_VALUE: Zatoshis = Zatoshis::ZERO;

/// The project vault's mainnet Unified Address.
const MAINNET_VAULT_ADDRESS: &str = "u1eqcql0r460xjqk49maglfxa02mfuetaed4h0nkf0lum4m6ay6t9gjpuxhuuygfeuz3d9sfgcjpz7uev2gsk5nnpf6g0uh0rn2uq0gz44";

/// The project vault's testnet Unified Address (also used on regtest).
const TESTNET_VAULT_ADDRESS: &str = "utest1v5p9lqxsshgrhdcj3gsg60vglxlkhwmhpvhtv3884pgwxktas9s95ws5qvypv4qyxadd5gjhzp4vczpd95flh307x42ssrynp9az3j4fyhz8knacwkzf8xk2f9726480ym2ntmv3ftk9z7gy5a8tarndrm0p992dx7gsczewsglqnpxg";

fn vault_address<P: Parameters>(network: &P) -> Address {
    match network.network_type() {
        NetworkType::Main => Address::decode(&MainNetwork, MAINNET_VAULT_ADDRESS),
        NetworkType::Test | NetworkType::Regtest => {
            Address::decode(&TestNetwork, TESTNET_VAULT_ADDRESS)
        }
    }
    .expect("FATAL: the configured vault Unified Address is invalid for its network")
}

/// A Treasury transaction was not built. Distinct from "nothing to do".
#[derive(Debug)]
pub enum BuildFailure<ProposalError, TransactionError> {
    /// The sendable total overflowed the monetary range.
    Balance(BalanceError),
    /// The upstream wallet API rejected transaction proposal construction.
    Proposal(ProposalError),
    /// The upstream wallet API rejected transaction construction or storage.
    Transaction(TransactionError),
}

impl<ProposalError: std::fmt::Debug, TransactionError: std::fmt::Debug> std::fmt::Display
    for BuildFailure<ProposalError, TransactionError>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Balance(error) => write!(f, "sendable total is invalid: {error}"),
            Self::Proposal(error) => write!(f, "proposal failed: {error:?}"),
            Self::Transaction(error) => write!(f, "transaction build failed: {error:?}"),
        }
    }
}

impl<ProposalError: std::fmt::Debug, TransactionError: std::fmt::Debug> std::error::Error
    for BuildFailure<ProposalError, TransactionError>
{
}

/// What a refund attempt can do this tip.
#[derive(Debug)]
pub enum RefundPlan {
    /// Build and broadcast this proposal.
    Send(Box<TreasuryProposal>),
    /// The payment does not cover the fee the proposal would charge.
    Dust,
    /// The note is not spendable yet, or the fee did not settle.
    Wait,
}

/// A proposal that spends `note` and pays `to` what remains of `paid`.
///
/// `penalty` stays as change. The note is the whole input, so the
/// Treasury adds nothing. A fee that does not match that shape is tried
/// once more; a second miss waits.
pub fn plan_refund<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    fee_rule: &FeeRule,
    note: NoteId,
    paid: Zatoshis,
    penalty: Zatoshis,
    to: &zcash_keys::address::Address,
) -> Result<RefundPlan, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let Some(value) = wallet.spendable_note_value(TREASURY_ACCOUNT, note) else {
        return Ok(RefundPlan::Wait);
    };
    if value != paid {
        tracing::warn!(
            paid = paid.into_u64(),
            note = value.into_u64(),
            "refund note value disagrees with the payment"
        );
        return Ok(RefundPlan::Wait);
    }
    let Some(returning) = paid - penalty else {
        return Ok(RefundPlan::Dust);
    };
    let Some(mut fee) = fee_rule.marginal_fee() * fee_rule.grace_actions() else {
        return Ok(RefundPlan::Wait);
    };
    // The first guess is one shielded action. The built fee can be higher
    // when the output pool is not the note's pool. One revision settles
    // a stable shape; a third guess waits for the next tip.
    for _ in 0..2 {
        if returning <= fee {
            return Ok(RefundPlan::Dust);
        }
        let amount = (returning - fee).expect("the remainder exceeds the fee");
        match propose_one_note(network, wallet, fee_rule, note, to, amount) {
            Ok(proposal) => {
                if refund_settles(&proposal, note, paid, penalty) {
                    return Ok(RefundPlan::Send(Box::new(proposal)));
                }
                fee = proposal.steps().first().balance().fee_required();
            }
            Err(Error::InsufficientFunds {
                required,
                available,
            }) if available == paid => {
                let Some(wanted) = required - amount else {
                    return Ok(RefundPlan::Wait);
                };
                fee = wanted;
            }
            Err(Error::ScanRequired) | Err(Error::InsufficientFunds { .. }) => {
                return Ok(RefundPlan::Wait);
            }
            Err(error) => return Err(BuildFailure::Proposal(error)),
        }
    }
    Ok(RefundPlan::Wait)
}

/// Spends `note` and no other. The limit is cleared before this returns.
fn propose_one_note<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    fee_rule: &FeeRule,
    note: NoteId,
    to: &zcash_keys::address::Address,
    amount: Zatoshis,
) -> Result<TreasuryProposal, TreasuryProposalError<P>> {
    wallet.set_refund_note(Some(note));
    // A penalty below the marginal fee is still the change. The sweep and
    // the relays reject change at or below `MARGINAL_FEE`.
    let request = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(network),
        amount,
    )])
    .expect("one shielded payment satisfies a ZIP 321 request");
    let change_strategy = SingleOutputChangeStrategy::new(
        fee_rule.clone(),
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::new(DustAction::AllowDustChange, None),
    );
    let result = propose_transfer(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &GreedyInputSelector::new(),
        &change_strategy,
        request,
        crate::wallet::CONFIRMATIONS,
        &SpendPolicy::default(),
        None,
        None,
    );
    wallet.set_refund_note(None);
    result
}

/// The proposal spends `note` alone, leaves `penalty` as change, and
/// pays out `paid` minus that minus the fee.
fn refund_settles(
    proposal: &TreasuryProposal,
    note: NoteId,
    paid: Zatoshis,
    penalty: Zatoshis,
) -> bool {
    let step = proposal.steps().first();
    let Some(inputs) = step.shielded_inputs() else {
        return false;
    };
    if inputs.notes().len() != 1 || *inputs.notes().first().internal_note_id() != note {
        return false;
    }
    let Some(change) = step
        .balance()
        .proposed_change()
        .iter()
        .map(|change| change.value())
        .sum::<Option<Zatoshis>>()
    else {
        return false;
    };
    if change != penalty {
        return false;
    }
    let Ok(Some(sent)) = step.transaction_request().total() else {
        return false;
    };
    (sent + step.balance().fee_required() + penalty) == Some(paid)
}

/// When `paid` is below `price`, keeps it or admits a refund to `recipient`.
///
/// Returns `true` when the payment does not cover `price`.
#[allow(clippy::too_many_arguments)]
pub fn refund_underpaid<P: Parameters>(
    refunds: &mut RefundQueue,
    wallet: &mut Wallet<P>,
    fee_rule: &FeeRule,
    txid: TxId,
    output_index: Option<u16>,
    paid: Zatoshis,
    price: Zatoshis,
    recipient: &UnifiedAddress,
    name: &Name,
    height: BlockHeight,
    kind: &'static str,
) -> bool {
    match payment_against_quote(paid, price, fee_rule) {
        PaymentAgainstQuote::Covers => false,
        PaymentAgainstQuote::BelowFee | PaymentAgainstQuote::Remainder(_) => {
            admit_refund(
                refunds,
                wallet,
                fee_rule,
                txid,
                output_index,
                paid,
                Zatoshis::ZERO,
                recipient,
                name,
                height,
                kind,
                "underpaid",
            );
            true
        }
    }
}

/// Refunds `paid` minus `penalty` minus the refund fee. `penalty` is left
/// as change. Returns whether a refund was admitted.
#[allow(clippy::too_many_arguments)]
pub fn refund_keeping<P: Parameters>(
    refunds: &mut RefundQueue,
    wallet: &mut Wallet<P>,
    fee_rule: &FeeRule,
    txid: TxId,
    output_index: Option<u16>,
    paid: Zatoshis,
    penalty: Zatoshis,
    recipient: &UnifiedAddress,
    name: &Name,
    height: BlockHeight,
    kind: &'static str,
    reason: &'static str,
) -> bool {
    admit_refund(
        refunds,
        wallet,
        fee_rule,
        txid,
        output_index,
        paid,
        penalty,
        recipient,
        name,
        height,
        kind,
        reason,
    )
}

/// Admits the refund, or logs that the payment is kept when `paid` minus
/// `penalty` does not exceed the refund fee.
#[allow(clippy::too_many_arguments)]
fn admit_refund<P: Parameters>(
    refunds: &mut RefundQueue,
    wallet: &mut Wallet<P>,
    fee_rule: &FeeRule,
    txid: TxId,
    output_index: Option<u16>,
    paid: Zatoshis,
    penalty: Zatoshis,
    recipient: &UnifiedAddress,
    name: &Name,
    height: BlockHeight,
    kind: &'static str,
    reason: &'static str,
) -> bool {
    let kept = || {
        tracing::info!(
            %txid,
            name = %name.as_str(),
            kind,
            reason,
            paid = paid.into_u64(),
            penalty = penalty.into_u64(),
            "payment kept"
        );
    };
    let Some(net) = paid - penalty else {
        kept();
        return false;
    };
    let Some(output) = refund_output(net, fee_rule) else {
        kept();
        return false;
    };
    let Some(index) = output_index else {
        kept();
        return false;
    };
    let note = NoteId::new(txid, ShieldedPool::Ironwood, index);
    tracing::info!(
        %txid,
        name = %name.as_str(),
        kind,
        reason,
        paid = paid.into_u64(),
        penalty = penalty.into_u64(),
        refund = output.into_u64(),
        "payment refund"
    );
    refunds.admit(Refund::new(
        note,
        recipient.clone(),
        paid,
        penalty,
        name.clone(),
        height,
    ));
    wallet.reserve_refund(note);
    true
}

/// The refund no longer holds `note`. The sweep may select it.
pub fn release_refund<P: Parameters>(wallet: &mut Wallet<P>, note: NoteId) {
    wallet.release_refund(note);
}

/// Drops refunds mined at or below the wallet's rewind floor, and releases
/// their notes. A reorg can still unmine anything above that floor.
pub fn prune_buried_refunds<P: Parameters>(refunds: &mut RefundQueue, wallet: &mut Wallet<P>) {
    let tip = wallet.tip().block_height();
    let Some(floor) = wallet.rewind_floor() else {
        refunds.prune_orphaned(|txid| wallet.expired_unmined_at(txid, tip));
        return;
    };
    for note in refunds.prune_buried(floor, |txid| wallet.mined_height(&txid)) {
        wallet.release_refund(note);
    }
    refunds.prune_orphaned(|txid| {
        wallet
            .mined_height(&txid)
            .is_some_and(|height| height <= floor)
            || wallet.expired_unmined_at(txid, tip)
    });
}

/// Drops a rejected or expired refund transaction. The note stays reserved.
pub fn refund_rejected<P: Parameters>(wallet: &mut Wallet<P>, txid: TxId) {
    wallet.release_rejected_spend(txid);
}

/// Builds `proposal`. The wallet records the spend. A rejected broadcast
/// drops that spend; the note stays reserved.
pub fn build_refund<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    proposal: &TreasuryProposal,
) -> Result<Transaction, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let spending_keys = treasury_keys.spending_keys();
    let txids = create_proposed_transactions::<
        Wallet<P>,
        P,
        GreedyInputSelectorError,
        FeeRule,
        FeeError,
        NoteId,
    >(
        wallet,
        network,
        &SystemClock,
        &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        proposal,
        None,
    )
    .map_err(BuildFailure::Transaction)?;
    Ok(wallet
        .get_transaction(*txids.first())
        .expect("FATAL: refund transaction lookup failed")
        .expect("FATAL: refund transaction was not recorded"))
}

/// Pays the vault what send-max could deliver, less the float.
fn propose_vault_sweep<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    fee_rule: &FeeRule,
) -> Result<Option<TreasuryProposal>, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>>
{
    let vault = vault_address(network);
    let sendable = match propose_send_max_transfer::<_, _, _, Infallible>(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &[ShieldedPool::Sapling, ShieldedPool::Ironwood],
        fee_rule,
        vault.to_zcash_address(network),
        None,
        MaxSpendMode::MaxSpendable,
        crate::wallet::CONFIRMATIONS,
        &LockedInputPolicy::Exclude,
        None,
    ) {
        Ok(max) => max.steps().first().transaction_request().total(),
        Err(Error::InsufficientFunds { .. }) => return Ok(None),
        Err(error) => return Err(BuildFailure::Proposal(error)),
    };
    let sendable = sendable
        .map_err(BuildFailure::Balance)?
        .unwrap_or(Zatoshis::ZERO);

    let Some(payment) = (sendable - SWEEP_RESERVE).filter(|p| *p >= SWEEP_MINIMUM) else {
        tracing::debug!(
            sendable_zats = sendable.into_u64(),
            "vault sweep skipped: payment below the minimum"
        );
        return Ok(None);
    };

    let request = TransactionRequest::new(vec![Payment::without_memo(
        vault.to_zcash_address(network),
        payment,
    )])
    .expect("one payment is a valid ZIP 321 request");
    propose_transfer::<_, _, _, _, Infallible>(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &GreedyInputSelector::new(),
        &SingleOutputChangeStrategy::new(
            fee_rule.clone(),
            None,
            ShieldedPool::Ironwood,
            DustOutputPolicy::new(DustAction::Reject, Some(MARGINAL_FEE)),
        ),
        request,
        crate::wallet::CONFIRMATIONS,
        &SpendPolicy::default(),
        None,
        None,
    )
    .map(Some)
    .map_err(BuildFailure::Proposal)
}

/// Builds the vault sweep. `Ok(None)` means nothing to move.
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    fee_rule: &FeeRule,
) -> Result<Option<Transaction>, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let Some(proposal) = propose_vault_sweep(network, wallet, fee_rule)? else {
        return Ok(None);
    };

    let spending_keys = treasury_keys.spending_keys();
    let txids = create_proposed_transactions::<_, _, GreedyInputSelectorError, _, FeeError, _>(
        wallet,
        network,
        &SystemClock,
        &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .map_err(BuildFailure::Transaction)?;

    tracing::info!(txid = %txids.first(), "vault sweep built");

    // The build stored the tx and marked its inputs spent; a miss here is
    // the wallet contradicting itself, not a skip. Stop; restart rescans.
    Ok(Some(
        wallet
            .get_transaction(*txids.first())
            .expect("FATAL: vault sweep lookup failed after build")
            .expect("FATAL: built vault sweep tx missing from wallet"),
    ))
}

/// Proposes, builds, and records a Treasury payment carrying an OTP challenge
/// memo to the controller. Funded from Treasury notes via upstream's generic
/// selection path. Build failures are returned to the relay lane, which
/// logs them and tries again on a later tip.
#[allow(clippy::too_many_arguments)]
pub fn challenge<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    fee_rule: &FeeRule,
    controller: &zcash_keys::address::UnifiedAddress,
    memo: MemoBytes,
) -> Result<Transaction, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let payment = Payment::new(
        Address::Unified(Box::new(controller.clone())).to_zcash_address(network),
        Some(CHALLENGE_RELAY_VALUE),
        Some(memo),
        None,
        None,
        vec![],
    )
    .map_err(|error| BuildFailure::Proposal(Error::Payment(error)))?;
    let request =
        TransactionRequest::new(vec![payment]).expect("one payment is a valid ZIP 321 request");
    let proposal = propose_transfer::<_, _, _, _, Infallible>(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &GreedyInputSelector::new(),
        &SingleOutputChangeStrategy::new(
            fee_rule.clone(),
            None,
            ShieldedPool::Ironwood,
            DustOutputPolicy::new(DustAction::Reject, Some(MARGINAL_FEE)),
        ),
        request,
        crate::wallet::CONFIRMATIONS,
        &SpendPolicy::default(),
        None,
        None,
    )
    .map_err(BuildFailure::Proposal)?;

    let spending_keys = treasury_keys.spending_keys();
    let txids = create_proposed_transactions::<
        Wallet<P>,
        P,
        GreedyInputSelectorError,
        FeeRule,
        FeeError,
        NoteId,
    >(
        wallet,
        network,
        &SystemClock,
        &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .map_err(BuildFailure::Transaction)?;

    Ok(wallet
        .get_transaction(*txids.first())
        .expect("FATAL: challenge transaction lookup failed")
        .expect("FATAL: challenge transaction was not recorded"))
}

// ---------------------------------------------------------------------------
// RequestQueue — Treasury requests decoded once, at block application
// ---------------------------------------------------------------------------

/// Treasury requests decoded once at block application: what each memo
/// said, what it paid, which output carried it, the block. Entries are
/// queued at block application and leave by decision (`resolved`) or by
/// reorg (`truncate_to`); nothing else removes them.
#[derive(Clone, Debug, Default)]
pub struct RequestQueue {
    requests: Vec<(TxId, Option<u16>, Request, Zatoshis, BlockHeight)>,
}

impl RequestQueue {
    /// A recognized request, routed after block application. Admission
    /// records facts in transaction order; the deciding pass rules.
    /// `output_index` names the shielded output the payment arrived on.
    pub fn record(
        &mut self,
        txid: TxId,
        output_index: Option<u16>,
        request: Request,
        paid: Zatoshis,
        height: BlockHeight,
    ) {
        self.requests
            .push((txid, output_index, request, paid, height));
    }

    /// Every request pending decision, in queue order.
    pub fn pending(&self) -> Vec<(TxId, Option<u16>, Request, Zatoshis, BlockHeight)> {
        self.requests.clone()
    }

    /// The name of every request pending decision, borrowed.
    pub fn names(&self) -> impl Iterator<Item = &Name> {
        self.requests
            .iter()
            .map(|(_, _, request, _, _)| request.name())
    }

    /// The request is decided. The only removal besides reorg truncation.
    pub fn resolved(&mut self, txid: TxId) {
        self.requests.retain(|(queued, _, _, _, _)| *queued != txid);
    }

    /// Reorg: entries whose block was orphaned fall with it.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) {
        self.requests
            .retain(|(_, _, _, _, height)| *height <= ancestor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Action, Name, Term, TREASURY_ACCOUNT};
    use crate::wallet::testing::{Cache, Factory};
    use crate::zcash::fees::fee_rule;
    use zcash_client_backend::data_api::testing::pool::dsl::TestDsl;
    use zcash_client_backend::data_api::testing::sapling::SaplingPoolTester;
    use zcash_client_backend::data_api::wallet::TargetHeight;
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn request(action: Action) -> Request {
        let ua = match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => *ua,
            _ => panic!("vector is a mainnet Unified Address"),
        };
        let name = Name::parse("alice").unwrap();
        match action {
            Action::Claim => Request::Claim {
                name,
                ua,
                term: Term::Forever,
                code: None,
            },
            Action::Update => Request::Update {
                name,
                ua,
                term: None,
            },
            Action::Release => Request::Release { name, ua },
        }
    }

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    #[test]
    fn vault_addresses_match_the_network() {
        for (vault, encoded) in [
            (
                vault_address(&MainNetwork).to_receiver_preserving_zcash_address(&MainNetwork),
                MAINNET_VAULT_ADDRESS,
            ),
            (
                vault_address(&TestNetwork).to_receiver_preserving_zcash_address(&TestNetwork),
                TESTNET_VAULT_ADDRESS,
            ),
        ] {
            assert_eq!(vault.to_string(), encoded);
        }
        assert!(
            zcash_keys::address::Address::decode(&MainNetwork, TESTNET_VAULT_ADDRESS).is_none()
        );
        assert!(
            zcash_keys::address::Address::decode(&TestNetwork, MAINNET_VAULT_ADDRESS).is_none()
        );
    }

    /// The float survives any note count and fee rate.
    #[test]
    fn sweep_proposal_leaves_exactly_the_float_at_any_note_count() {
        for (note_count, fee_rule) in [3usize, 198, 250, 400].into_iter().flat_map(|count| {
            [
                (count, FeeRule::standard()),
                (count, fee_rule(Zatoshis::const_from_u64(1_000))),
            ]
        }) {
            let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
                .build::<SaplingPoolTester>();
            st.add_notes_checking_balance([vec![Zatoshis::const_from_u64(50_000_000); note_count]]);
            st.add_empty_blocks(1);

            let network = *st.network();
            let proposal = propose_vault_sweep(&network, st.wallet_mut(), &fee_rule)
                .expect("the sweep proposal closes")
                .expect("the surplus is far above the minimum");

            let step = proposal.steps().first();
            assert_eq!(
                step.shielded_inputs()
                    .map_or(0, |inputs| inputs.notes().len()),
                note_count
            );
            assert_eq!(change(step), SWEEP_RESERVE, "float at {note_count} notes");
            assert!(step.balance().fee_required() > fee_rule.marginal_fee());
        }
    }

    fn change(step: &zcash_client_backend::proposal::Step<NoteId>) -> Zatoshis {
        step.balance()
            .proposed_change()
            .iter()
            .map(|change| change.value())
            .sum::<Option<Zatoshis>>()
            .expect("change fits in the monetary range")
    }

    #[test]
    fn queue_records_in_block_order() {
        let mut queue = RequestQueue::default();
        assert!(queue.pending().is_empty());

        queue.record(
            TxId::from_bytes([1; 32]),
            Some(0),
            request(Action::Claim),
            Zatoshis::ZERO,
            h(100),
        );
        queue.record(
            TxId::from_bytes([2; 32]),
            Some(0),
            request(Action::Update),
            Zatoshis::ZERO,
            h(101),
        );

        let pending = queue.pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].0, TxId::from_bytes([1; 32]));
        assert_eq!(pending[0].4, h(100));
        assert_eq!(pending[1].4, h(101));
    }

    #[test]
    fn queue_records_every_claim_in_order() {
        let ua = match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => *ua,
            _ => panic!("vector is a mainnet Unified Address"),
        };
        let alice = Name::parse("alice").unwrap();
        let bob = Name::parse("bob").unwrap();
        let mut queue = RequestQueue::default();

        queue.record(
            TxId::from_bytes([1; 32]),
            Some(0),
            Request::Claim {
                name: alice.clone(),
                ua: ua.clone(),
                term: Term::Forever,
                code: None,
            },
            Zatoshis::ZERO,
            h(100),
        );
        queue.record(
            TxId::from_bytes([2; 32]),
            Some(0),
            Request::Claim {
                name: alice.clone(),
                ua: ua.clone(),
                term: Term::Forever,
                code: None,
            },
            Zatoshis::ZERO,
            h(101),
        );
        queue.record(
            TxId::from_bytes([3; 32]),
            Some(0),
            Request::Claim {
                name: bob,
                ua,
                term: Term::Forever,
                code: None,
            },
            Zatoshis::ZERO,
            h(102),
        );

        // Admission records every claim; the deciding pass rules.
        let pending = queue.pending();
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].0, TxId::from_bytes([1; 32]));
        assert_eq!(pending[1].0, TxId::from_bytes([2; 32]));
        assert_eq!(pending[2].0, TxId::from_bytes([3; 32]));
        assert!(matches!(
            pending[0].2,
            Request::Claim { ref name, .. } if name.as_str() == "alice"
        ));
        assert!(matches!(
            pending[1].2,
            Request::Claim { ref name, .. } if name.as_str() == "alice"
        ));
    }

    #[test]
    fn resolved_leaves_survivors_in_order() {
        let mut queue = RequestQueue::default();
        queue.record(
            TxId::from_bytes([1; 32]),
            Some(0),
            request(Action::Claim),
            Zatoshis::ZERO,
            h(100),
        );
        queue.record(
            TxId::from_bytes([2; 32]),
            Some(0),
            request(Action::Update),
            Zatoshis::ZERO,
            h(101),
        );
        queue.record(
            TxId::from_bytes([3; 32]),
            Some(0),
            request(Action::Release),
            Zatoshis::ZERO,
            h(102),
        );

        queue.resolved(TxId::from_bytes([2; 32]));
        let pending = queue.pending();
        assert_eq!(pending.len(), 2);
        // The neighbors kept their relative order.
        assert_eq!(pending[0].0, TxId::from_bytes([1; 32]));
        assert_eq!(pending[1].0, TxId::from_bytes([3; 32]));
        assert!(matches!(pending[1].2, Request::Release { .. }));
        assert_eq!(pending[1].4, h(102));
    }

    #[test]
    fn resolved_unknown_txid_is_a_no_op() {
        let mut queue = RequestQueue::default();
        queue.record(
            TxId::NULL,
            Some(0),
            request(Action::Claim),
            Zatoshis::ZERO,
            h(100),
        );

        queue.resolved(TxId::from_bytes([9; 32]));
        assert_eq!(queue.pending().len(), 1);
    }

    #[test]
    fn queue_truncate_drops_only_orphaned_heights() {
        let mut queue = RequestQueue::default();
        queue.record(
            TxId::NULL,
            Some(0),
            request(Action::Claim),
            Zatoshis::ZERO,
            h(100),
        );
        queue.record(
            TxId::NULL,
            Some(0),
            request(Action::Update),
            Zatoshis::ZERO,
            h(150),
        );
        queue.record(
            TxId::NULL,
            Some(0),
            request(Action::Release),
            Zatoshis::ZERO,
            h(200),
        );

        queue.truncate_to(h(120));
        let pending = queue.pending();
        assert_eq!(pending.len(), 1);
        assert!(matches!(pending[0].2, Request::Claim { .. }));
        assert_eq!(pending[0].4, h(100));
    }

    /// The payment note funds the refund. While it is owed, the sweep
    /// spends the other notes and a later attempt still selects it.
    #[test]
    fn an_underpaid_note_is_refunded_and_stays_out_of_the_sweep() {
        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();
        st.add_notes_checking_balance([
            vec![Zatoshis::const_from_u64(100_000)],
            vec![Zatoshis::const_from_u64(80_000_000)],
            vec![Zatoshis::const_from_u64(80_000_000)],
        ]);
        st.add_empty_blocks(1);

        let network = *st.network();
        let tip = TargetHeight::from(st.wallet().tip().block_height() + 1);
        let paid = Zatoshis::const_from_u64(100_000);
        let payment = *st
            .wallet()
            .unspent_sapling_notes(TREASURY_ACCOUNT, tip)
            .iter()
            .find(|note| note.note_value().unwrap() == paid)
            .expect("payment note")
            .internal_note_id();
        let to = vault_address(&network);

        let proposal = match plan_refund(
            &network,
            st.wallet_mut(),
            &FeeRule::standard(),
            payment,
            paid,
            Zatoshis::ZERO,
            &to,
        )
        .expect("plan")
        {
            RefundPlan::Send(proposal) => proposal,
            other => panic!("refund plan was not send: {other:?}"),
        };
        let step = proposal.steps().first();
        let inputs = step.shielded_inputs().expect("one shielded input");
        assert_eq!(inputs.notes().len(), 1);
        assert_eq!(*inputs.notes().first().internal_note_id(), payment);
        let sent = step
            .transaction_request()
            .total()
            .expect("total")
            .expect("the payment has an amount");
        assert_eq!((sent + step.balance().fee_required()).unwrap(), paid);
        assert_eq!(
            step.transaction_request()
                .payments()
                .values()
                .next()
                .expect("one payment")
                .recipient_address(),
            &to.to_zcash_address(&network)
        );
        assert_eq!(
            step.balance()
                .proposed_change()
                .iter()
                .map(|change| change.value())
                .sum::<Option<Zatoshis>>()
                .expect("change"),
            Zatoshis::ZERO
        );

        let penalty = Zatoshis::const_from_u64(20_000);
        let penalized = match plan_refund(
            &network,
            st.wallet_mut(),
            &FeeRule::standard(),
            payment,
            paid,
            penalty,
            &to,
        )
        .expect("penalized plan")
        {
            RefundPlan::Send(proposal) => proposal,
            other => panic!("penalized refund plan was not send: {other:?}"),
        };
        let penalized_step = penalized.steps().first();
        let penalized_sent = penalized_step
            .transaction_request()
            .total()
            .expect("total")
            .expect("the payment has an amount");
        assert_eq!(
            (penalized_sent + penalized_step.balance().fee_required() + penalty).unwrap(),
            paid
        );
        assert_eq!(
            penalized_step
                .balance()
                .proposed_change()
                .iter()
                .map(|change| change.value())
                .sum::<Option<Zatoshis>>()
                .expect("change"),
            penalty
        );

        let dust_penalty = Zatoshis::const_from_u64(1_000);
        let dust = match plan_refund(
            &network,
            st.wallet_mut(),
            &FeeRule::standard(),
            payment,
            paid,
            dust_penalty,
            &to,
        )
        .expect("dust penalty plan")
        {
            RefundPlan::Send(proposal) => proposal,
            other => panic!("dust-penalty refund plan was not send: {other:?}"),
        };
        let dust_step = dust.steps().first();
        let dust_sent = dust_step
            .transaction_request()
            .total()
            .expect("total")
            .expect("the payment has an amount");
        assert_eq!(
            (dust_sent + dust_step.balance().fee_required() + dust_penalty).unwrap(),
            paid
        );
        assert_eq!(
            dust_step
                .balance()
                .proposed_change()
                .iter()
                .map(|change| change.value())
                .sum::<Option<Zatoshis>>()
                .expect("change"),
            dust_penalty
        );

        st.wallet_mut().reserve_refund(payment);
        assert!(matches!(
            plan_refund(
                &network,
                st.wallet_mut(),
                &FeeRule::standard(),
                payment,
                paid,
                Zatoshis::ZERO,
                &to
            )
            .expect("retry"),
            RefundPlan::Send(_)
        ));

        let sweep = propose_vault_sweep(&network, st.wallet_mut(), &FeeRule::standard())
            .expect("sweep")
            .expect("the other notes clear the minimum");
        let spent: Vec<_> = sweep
            .steps()
            .first()
            .shielded_inputs()
            .expect("sweep inputs")
            .notes()
            .iter()
            .map(|note| *note.internal_note_id())
            .collect();
        assert_eq!(spent.len(), 2);
        assert!(!spent.contains(&payment));
    }
}
