//! Treasury wallet view and Treasury policy for the mint: the vault
//! sweep, the challenge relay builder, and the request queue.
//!

mod otp;

pub use otp::{OtpChallenge, OtpCode, OtpQueue, D_OTP};

use std::convert::Infallible;
use std::num::NonZeroU32;

use zcash_client_backend::data_api::locking::{LockFilter, LockedInputPolicy};
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector;
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError;
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_standard_transfer_to_address, ConfirmationsPolicy,
    CreateErrT, ProposeTransferErrT, TargetHeight,
};
use zcash_client_backend::data_api::{
    InputSource as _, MaxSpendMode, ReceivedNotes, TargetValue, WalletRead as _,
};
use zcash_client_backend::fees::orchard::EmptyBundleView;
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
use zcash_client_backend::fees::{
    ChangeError, ChangeStrategy as _, DustOutputPolicy, StandardFeeRule,
};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::wallet::{NoteId, OvkPolicy, WalletTransparentOutput};
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::{BalanceError, Zatoshis};
use zcash_protocol::ShieldedPool;

use crate::mint::{Request, TREASURY_ACCOUNT};
use crate::wallet::{Wallet, WalletError};
use orchard::bundle::BundleVersion;
use transparent::bundle::TxOut;
use zip32::AccountId;

type TreasuryProposalError<P> = ProposeTransferErrT<
    Wallet<P>,
    Infallible,
    GreedyInputSelector<Wallet<P>>,
    SingleOutputChangeStrategy<Wallet<P>>,
>;
type TreasuryBuildError<P> =
    CreateErrT<Wallet<P>, GreedyInputSelectorError, StandardFeeRule, FeeError, NoteId>;
type VaultSweepProposal = Proposal<StandardFeeRule, NoteId>;

/// Minimum vault payment for a sweep to fire (1 ZEC): a floor on what
/// actually moves, not on the balance behind it.
pub const SWEEP_MINIMUM: Zatoshis = Zatoshis::const_from_u64(100_000_000);

/// Amount retained as Treasury change after a sweep (0.01 ZEC): the
/// operating float that funds the next relay and Name Note fees. The
/// sweep's own fee comes out of the vault payment, never out of the float.
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
    /// Selected note values overflowed or underflowed the monetary range.
    Balance(BalanceError),
    /// The change strategy could not price the sweep.
    Fee(ChangeError<FeeError, NoteId>),
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
            Self::Balance(error) => write!(f, "selected note value is invalid: {error}"),
            Self::Fee(error) => write!(f, "sweep fee computation failed: {error:?}"),
            Self::Proposal(error) => write!(f, "proposal failed: {error:?}"),
            Self::Transaction(error) => write!(f, "transaction build failed: {error:?}"),
        }
    }
}

impl<ProposalError: std::fmt::Debug, TransactionError: std::fmt::Debug> std::error::Error
    for BuildFailure<ProposalError, TransactionError>
{
}

/// The ZIP-317 fee of sweeping `notes` to the vault, priced by the change
/// strategy `propose_standard_transfer_to_address` uses, so it includes the
/// change output. The fee depends on the notes and the shape, not the
/// amount, so the vault output carries zero.
fn sweep_fee<P: Parameters>(
    network: &P,
    wallet: &Wallet<P>,
    notes: &ReceivedNotes<NoteId>,
    target_height: TargetHeight,
    anchor_height: BlockHeight,
) -> Result<Zatoshis, ChangeError<FeeError, NoteId>> {
    let change_strategy = SingleOutputChangeStrategy::<Wallet<P>>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );
    let ironwood_version = bundle_version_for_branch(
        BranchId::for_height(network, BlockHeight::from(target_height)),
        orchard::ValuePool::Ironwood,
    )
    .unwrap_or(BundleVersion::ironwood_v3());

    change_strategy
        .compute_balance(
            network,
            target_height,
            anchor_height,
            &wallet.pool_migration_params(),
            &[] as &[WalletTransparentOutput<AccountId>],
            &[TxOut::new(Zatoshis::ZERO, VAULT_ADDRESS.script().into())],
            &(
                sapling::builder::BundleType::DEFAULT,
                notes.sapling(),
                &[] as &[Infallible],
            ),
            &EmptyBundleView,
            &(ironwood_version, notes.ironwood(), &[] as &[Infallible]),
            None,
            &(),
        )
        .map(|balance| balance.fee_required())
}

/// The vault payment: `total` less the sweep's fee and the float, when at
/// least `SWEEP_MINIMUM`.
fn sweep_payment(total: Zatoshis, fee: Zatoshis) -> Option<Zatoshis> {
    (total - fee)
        .and_then(|sendable| sendable - SWEEP_RESERVE)
        .filter(|payment| *payment >= SWEEP_MINIMUM)
}

/// Proposes the sweep: the vault payment is `sweep_payment` over the
/// economic Treasury notes, so the fee comes out of the payment and the
/// change is the float. `None` means nothing needs moving.
fn propose_vault_sweep<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
) -> Result<Option<VaultSweepProposal>, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>>
{
    let policy = ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false);
    let (target_height, anchor_height) = match wallet.get_target_and_anchor_heights(NonZeroU32::MIN)
    {
        Ok(Some(heights)) => heights,
        Ok(None) => return Err(BuildFailure::HeightsUnavailable),
        Err(error) => return Err(BuildFailure::Heights(error)),
    };

    // Uneconomic notes are named by the change strategy and left out, as
    // upstream's selector does.
    let lock_policy = LockedInputPolicy::Exclude;
    let mut exclude = Vec::new();
    let (notes, fee) = loop {
        let notes = match wallet.select_spendable_notes(
            TREASURY_ACCOUNT,
            TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
            &[ShieldedPool::Sapling, ShieldedPool::Ironwood],
            target_height,
            policy,
            &exclude,
            LockFilter::Policy(&lock_policy),
        ) {
            Ok(notes) if !notes.is_empty() => notes,
            Ok(_) => {
                tracing::debug!("vault sweep skipped: no spendable notes");
                return Ok(None);
            }
            Err(error) => return Err(BuildFailure::Selection(error)),
        };
        match sweep_fee(network, wallet, &notes, target_height, anchor_height) {
            Ok(fee) => break (notes, fee),
            Err(ChangeError::DustInputs {
                sapling, ironwood, ..
            }) => {
                exclude.extend(sapling);
                exclude.extend(ironwood);
            }
            Err(ChangeError::InsufficientFunds { available, .. }) => {
                tracing::debug!(
                    spendable_zats = available.into_u64(),
                    "vault sweep skipped: spendable below its own fee"
                );
                return Ok(None);
            }
            Err(error) => return Err(BuildFailure::Fee(error)),
        }
    };
    let total = notes.total_value().map_err(BuildFailure::Balance)?;

    let Some(payment) = sweep_payment(total, fee) else {
        if total < SWEEP_RESERVE {
            tracing::info!(
                spendable_zats = total.into_u64(),
                float_zats = SWEEP_RESERVE.into_u64(),
                "vault sweep skipped: spendable below the float"
            );
        } else {
            tracing::debug!(
                spendable_zats = total.into_u64(),
                fee_zats = fee.into_u64(),
                minimum_zats = SWEEP_MINIMUM.into_u64(),
                "vault sweep skipped: payment below the minimum"
            );
        }
        return Ok(None);
    };

    propose_standard_transfer_to_address::<_, _, Infallible>(
        wallet,
        network,
        StandardFeeRule::Zip317,
        TREASURY_ACCOUNT,
        policy,
        &zcash_keys::address::Address::Transparent(VAULT_ADDRESS),
        payment,
        None,
        None,
        ShieldedPool::Ironwood,
        None,
        None,
    )
    .map(Some)
    .map_err(BuildFailure::Proposal)
}

/// One sweep: Treasury value above the operating float moves to the vault
/// when at least `SWEEP_MINIMUM` moves. `main` gates the once-per-day
/// cadence. `Ok(None)` means nothing needs moving. `Err` reports a build
/// failure; the next daily gate tries again. A read-back miss after a
/// successful build is FATAL — the wallet has already marked the inputs
/// spent.
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Result<Option<Transaction>, BuildFailure<TreasuryProposalError<P>, TreasuryBuildError<P>>> {
    let Some(proposal) = propose_vault_sweep(network, wallet)? else {
        return Ok(None);
    };

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
    use crate::wallet::testing::{Cache, Factory};
    use zcash_client_backend::data_api::testing::pool::dsl::TestDsl;
    use zcash_client_backend::data_api::testing::sapling::SaplingPoolTester;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
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
    fn sweep_payment_leaves_the_float_and_the_fee() {
        let fee = Zatoshis::const_from_u64(1_255_000);
        let total = ((SWEEP_MINIMUM + SWEEP_RESERVE).unwrap() + fee).unwrap();
        assert_eq!(sweep_payment(total, fee), Some(SWEEP_MINIMUM));
        let short = (total - Zatoshis::const_from_u64(1)).unwrap();
        assert_eq!(sweep_payment(short, fee), None);
    }

    #[test]
    fn sweep_payment_is_none_when_the_fee_exceeds_the_total() {
        assert_eq!(sweep_payment(SWEEP_RESERVE, SWEEP_MINIMUM), None);
    }

    /// #321: past ~198 notes the sweep fee exceeds the float. The fee comes
    /// out of the vault payment, so the proposal closes and its change is
    /// exactly the float.
    #[test]
    fn sweep_proposal_leaves_exactly_the_float_at_any_note_count() {
        for note_count in [3usize, 198, 250, 400] {
            let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
                .build::<SaplingPoolTester>();
            st.add_notes_checking_balance([vec![Zatoshis::const_from_u64(50_000_000); note_count]]);
            st.add_empty_blocks(1);

            let network = *st.network();
            let proposal = propose_vault_sweep(&network, st.wallet_mut())
                .expect("the sweep proposal closes")
                .expect("the surplus is far above the minimum");

            let step = proposal.steps().first();
            assert_eq!(
                step.shielded_inputs()
                    .map_or(0, |inputs| inputs.notes().len()),
                note_count
            );
            let change = step
                .balance()
                .proposed_change()
                .iter()
                .map(|change| change.value())
                .sum::<Option<Zatoshis>>()
                .expect("change fits in the monetary range");
            assert_eq!(change, SWEEP_RESERVE, "float at {note_count} notes");
            assert!(step.balance().fee_required() > MARGINAL_FEE);
        }
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
