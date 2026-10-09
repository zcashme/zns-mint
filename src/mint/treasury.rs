//! Treasury wallet view and Treasury policy for the mint: the vault
//! sweep, the challenge relay builder, and the request queue.
//!

mod otp;

pub use otp::{OtpChallenge, OtpCode, OtpQueue, D_OTP};

use std::convert::Infallible;
use std::num::NonZeroU32;

use zcash_client_backend::data_api::error::Error as ProposeError;
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector;
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError;
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_standard_transfer_to_address, ConfirmationsPolicy,
    CreateErrT, ProposeTransferErrT,
};
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::wallet::{NoteId, OvkPolicy};
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::{BalanceError, Zatoshis};
use zcash_protocol::ShieldedPool;

use crate::mint::{Request, TREASURY_ACCOUNT};
use crate::wallet::{Wallet, WalletError};

type TreasuryProposalError<P> = ProposeTransferErrT<
    Wallet<P>,
    Infallible,
    GreedyInputSelector<Wallet<P>>,
    SingleOutputChangeStrategy<Wallet<P>>,
>;
type TreasuryBuildError<P> =
    CreateErrT<Wallet<P>, GreedyInputSelectorError, StandardFeeRule, FeeError, NoteId>;

/// Minimum vault payment for a sweep to fire (1 ZEC): a floor on what
/// actually moves, not on the balance behind it.
pub const SWEEP_MINIMUM: Zatoshis = Zatoshis::const_from_u64(100_000_000);

/// The operating waterline (0.01 ZEC): the float that OTP relays and
/// Name Note fees draw on. The drain moves only the surplus above the
/// waterline and holds the float itself whole — its fee is charged to
/// the surplus, never to the float.
pub const SWEEP_RESERVE: Zatoshis = Zatoshis::const_from_u64(1_000_000);

/// The relay sends no value — the memo is the message. The
/// transaction's ZIP-317 fee is calculated separately.
pub const CHALLENGE_RELAY_VALUE: Zatoshis = Zatoshis::ZERO;

/// The project vault's P2PKH address (placeholder pending final approved
/// address).
pub const VAULT_ADDRESS: transparent::address::TransparentAddress =
    transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]);

/// A Treasury transaction was not built. Distinct from "nothing to do".
#[derive(Debug)]
pub enum BuildFailure<ProposalError, TransactionError> {
    /// No target height or anchor was available.
    HeightsUnavailable,
    /// The wallet failed while reading target/anchor heights.
    Heights(WalletError),
    /// Wallet note selection failed.
    Selection(WalletError),
    /// The wallet failed to produce the balance summary.
    Summary(WalletError),
    /// Selected note values overflowed or underflowed the monetary range.
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
            Self::HeightsUnavailable => write!(f, "no target or anchor height"),
            Self::Heights(error) => write!(f, "target/anchor height lookup failed: {error}"),
            Self::Selection(error) => write!(f, "note selection failed: {error}"),
            Self::Summary(error) => write!(f, "balance summary failed: {error}"),
            Self::Balance(error) => write!(f, "selected note value is invalid: {error}"),
            Self::Proposal(error) => write!(f, "proposal failed: {error:?}"),
            Self::Transaction(error) => write!(f, "transaction build failed: {error:?}"),
        }
    }
}

impl<ProposalError: std::fmt::Debug, TransactionError: std::fmt::Debug> std::error::Error
    for BuildFailure<ProposalError, TransactionError>
{
}

/// One drain per day: everything above the operating waterline moves to
/// the vault when at least `SWEEP_MINIMUM` moves. `main` gates the
/// once-per-day cadence, so the pump fires at most daily — and most days
/// not at all, because the pool sits at the line.
///
/// The drain prices its own fee from upstream's refusal: `InsufficientFunds`
/// reports `required = payment + fee`, so the exact fee is read off the
/// error — or off the priced proposal — and charged to the surplus, never
/// to the float. The fee depends only on the note set and transaction
/// shape, never on the amount, so the re-priced second attempt converges.
/// Sub-economic notes (value at or below the marginal fee) are already
/// classified out of `spendable_value` by the wallet's balance layer, so
/// the arithmetic here matches what the proposer will gather.
///
/// `Ok(None)` means nothing needs moving: at or below the waterline, or
/// the surplus is under `SWEEP_MINIMUM`. `Err` reports a build failure;
/// the next daily gate tries again. A read-back miss after a successful
/// build is FATAL — the wallet has already marked the inputs spent.
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Result<Option<Transaction>, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let policy = ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false);

    // Spendable = confirmed, witnessable, unlocked, and non-economic notes
    // excluded: the balance layer classifies notes at or below `MARGINAL_FEE`
    // as uneconomic (`add_note_to_balance`), matching the proposer's own
    // input pruning, so the drain's arithmetic cannot disagree with it.
    let summary = match wallet.get_wallet_summary(policy) {
        Ok(Some(summary)) => summary,
        Ok(None) => return Ok(None),
        Err(error) => return Err(BuildFailure::Summary(error)),
    };
    let Some(balance) = summary.account_balances().get(&TREASURY_ACCOUNT) else {
        tracing::debug!("vault drain skipped: no treasury account in summary");
        return Ok(None);
    };
    let drainable = (balance.sapling_balance().spendable_value()
        + balance.ironwood_balance().spendable_value())
    .ok_or(BuildFailure::Balance(BalanceError::Overflow))?;

    // The waterline: relays and Name Note fees draw on the float, so the
    // drain moves only the surplus above it. Most midnights end here.
    if drainable <= SWEEP_RESERVE {
        tracing::debug!(
            spendable_zats = drainable.into_u64(),
            float_zats = SWEEP_RESERVE.into_u64(),
            "vault drain skipped: at the waterline"
        );
        return Ok(None);
    }
    let Some(payment) = drainable - SWEEP_RESERVE else {
        return Err(BuildFailure::Balance(BalanceError::Underflow));
    };
    if payment < SWEEP_MINIMUM {
        tracing::debug!(
            surplus_zats = payment.into_u64(),
            minimum_zats = SWEEP_MINIMUM.into_u64(),
            "vault drain skipped: surplus below the minimum"
        );
        return Ok(None);
    }

    // Attempt 1: pay the vault the surplus. Two outcomes leave the float
    // short — upstream refuses (`InsufficientFunds`), or the priced fee
    // cannot fit above the waterline — and both measure the exact fee.
    let fee = match propose_vault_drain::<P>(network, wallet, payment) {
        Ok(proposal) => {
            let balance = proposal.steps().first().balance();
            let fee = balance.fee_required();
            let change =
                (balance.total() - fee).ok_or(BuildFailure::Balance(BalanceError::Underflow))?;
            if change >= SWEEP_RESERVE {
                return record_vault_drain(
                    network,
                    wallet,
                    treasury_keys,
                    spend_prover,
                    output_prover,
                    proposal,
                );
            }
            fee
        }
        Err(BuildFailure::Proposal(ProposeError::InsufficientFunds { required, .. })) => {
            (required - payment).ok_or(BuildFailure::Balance(BalanceError::Underflow))?
        }
        Err(error) => return Err(error),
    };

    // Attempt 2: the fee charged to the surplus; the float is whole. If
    // even the surplus cannot cover its own movement cost, defer — the
    // next inbound payment grows the surplus faster than it grows the fee.
    let Some(payment) = (drainable - SWEEP_RESERVE).and_then(|surplus| surplus - fee) else {
        tracing::warn!(
            fee_zats = fee.into_u64(),
            "vault drain deferred: surplus cannot cover its own movement cost"
        );
        return Ok(None);
    };
    tracing::info!(
        fee_zats = fee.into_u64(),
        "vault drain re-priced from refusal"
    );
    let proposal = propose_vault_drain::<P>(network, wallet, payment)?;
    record_vault_drain(
        network,
        wallet,
        treasury_keys,
        spend_prover,
        output_prover,
        proposal,
    )
}

/// Proposes the vault payment itself: the standard single-payment transfer
/// to `VAULT_ADDRESS`, unchanged. Kept as its own step so the drain can
/// re-price — the caller reads the measured fee off either the returned
/// proposal or the `InsufficientFunds` refusal.
fn propose_vault_drain<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    payment: Zatoshis,
) -> Result<
    Proposal<StandardFeeRule, NoteId>,
    BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>,
> {
    propose_standard_transfer_to_address::<_, _, Infallible>(
        wallet,
        network,
        StandardFeeRule::Zip317,
        TREASURY_ACCOUNT,
        ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false),
        &zcash_keys::address::Address::Transparent(VAULT_ADDRESS),
        payment,
        None,
        None,
        ShieldedPool::Ironwood,
        None,
        None,
    )
    .map_err(BuildFailure::Proposal)
}

/// Builds, records, and reads back the drain transaction. The build stored
/// the tx and marked its inputs spent; a miss on read-back is the wallet
/// contradicting itself, not a skip. Stop; restart rescans.
#[allow(clippy::too_many_arguments)]
fn record_vault_drain<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    proposal: Proposal<StandardFeeRule, NoteId>,
) -> Result<Option<Transaction>, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let spending_keys = treasury_keys.spending_keys();
    let txids = create_proposed_transactions::<_, _, GreedyInputSelectorError, _, FeeError, _>(
        wallet,
        network,
        spend_prover,
        output_prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .map_err(BuildFailure::Transaction)?;

    tracing::info!(txid = %txids.first(), "vault drain built");

    Ok(Some(
        wallet
            .get_transaction(*txids.first())
            .expect("FATAL: vault drain lookup failed after build")
            .expect("FATAL: built vault drain tx missing from wallet"),
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
    controller: &zcash_keys::address::UnifiedAddress,
    memo: MemoBytes,
) -> Result<Transaction, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let proposal = propose_standard_transfer_to_address::<_, _, Infallible>(
        wallet,
        network,
        StandardFeeRule::Zip317,
        TREASURY_ACCOUNT,
        ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false),
        &zcash_keys::address::Address::Unified(controller.clone()),
        CHALLENGE_RELAY_VALUE,
        Some(memo),
        None,
        ShieldedPool::Ironwood,
        None,
        None,
    )
    .map_err(BuildFailure::Proposal)?;

    let spending_keys = treasury_keys.spending_keys();
    let txids = create_proposed_transactions::<
        Wallet<P>,
        P,
        GreedyInputSelectorError,
        StandardFeeRule,
        FeeError,
        NoteId,
    >(
        wallet,
        network,
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
/// said, what it paid, the block that carried it. Entries are queued at
/// block application and leave by decision (`resolved`) or by reorg
/// (`truncate_to`); nothing else removes them.
#[derive(Clone, Debug, Default)]
pub struct RequestQueue {
    requests: Vec<(TxId, Request, Zatoshis, BlockHeight)>,
}

impl RequestQueue {
    /// A recognized request, routed after block application. Admission
    /// records facts in transaction order; the deciding pass rules.
    pub fn record(&mut self, txid: TxId, request: Request, paid: Zatoshis, height: BlockHeight) {
        self.requests.push((txid, request, paid, height));
    }

    /// Every request pending decision, in queue order.
    pub fn pending(&self) -> Vec<(TxId, Request, Zatoshis, BlockHeight)> {
        self.requests.clone()
    }

    /// The request is decided. The only removal besides reorg truncation.
    pub fn resolved(&mut self, txid: TxId) {
        self.requests.retain(|(queued, _, _, _)| *queued != txid);
    }

    /// Reorg: entries whose block was orphaned fall with it.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) {
        self.requests
            .retain(|(_, _, _, height)| *height <= ancestor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Action, Name, Term};
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn request(action: Action) -> Request {
        let ua = match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
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
    fn queue_records_in_block_order() {
        let mut queue = RequestQueue::default();
        assert!(queue.pending().is_empty());

        queue.record(
            TxId::from_bytes([1; 32]),
            request(Action::Claim),
            Zatoshis::ZERO,
            h(100),
        );
        queue.record(
            TxId::from_bytes([2; 32]),
            request(Action::Update),
            Zatoshis::ZERO,
            h(101),
        );

        let pending = queue.pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].0, TxId::from_bytes([1; 32]));
        assert_eq!(pending[0].3, h(100));
        assert_eq!(pending[1].3, h(101));
    }

    #[test]
    fn queue_records_every_claim_in_order() {
        let ua = match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        };
        let alice = Name::parse("alice").unwrap();
        let bob = Name::parse("bob").unwrap();
        let mut queue = RequestQueue::default();

        queue.record(
            TxId::from_bytes([1; 32]),
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
            pending[0].1,
            Request::Claim { ref name, .. } if name.as_str() == "alice"
        ));
        assert!(matches!(
            pending[1].1,
            Request::Claim { ref name, .. } if name.as_str() == "alice"
        ));
    }

    #[test]
    fn resolved_leaves_survivors_in_order() {
        let mut queue = RequestQueue::default();
        queue.record(
            TxId::from_bytes([1; 32]),
            request(Action::Claim),
            Zatoshis::ZERO,
            h(100),
        );
        queue.record(
            TxId::from_bytes([2; 32]),
            request(Action::Update),
            Zatoshis::ZERO,
            h(101),
        );
        queue.record(
            TxId::from_bytes([3; 32]),
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
        assert!(matches!(pending[1].1, Request::Release { .. }));
        assert_eq!(pending[1].3, h(102));
    }

    #[test]
    fn resolved_unknown_txid_is_a_no_op() {
        let mut queue = RequestQueue::default();
        queue.record(TxId::NULL, request(Action::Claim), Zatoshis::ZERO, h(100));

        queue.resolved(TxId::from_bytes([9; 32]));
        assert_eq!(queue.pending().len(), 1);
    }

    #[test]
    fn queue_truncate_drops_only_orphaned_heights() {
        let mut queue = RequestQueue::default();
        queue.record(TxId::NULL, request(Action::Claim), Zatoshis::ZERO, h(100));
        queue.record(TxId::NULL, request(Action::Update), Zatoshis::ZERO, h(150));
        queue.record(TxId::NULL, request(Action::Release), Zatoshis::ZERO, h(200));

        queue.truncate_to(h(120));
        let pending = queue.pending();
        assert_eq!(pending.len(), 1);
        assert!(matches!(pending[0].1, Request::Claim { .. }));
        assert_eq!(pending[0].3, h(100));
    }
}
