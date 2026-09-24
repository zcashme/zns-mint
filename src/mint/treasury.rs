//! Treasury wallet view and Treasury policy for the mint: the vault
//! sweep, the challenge relay builder, and the request queue.
//!

use std::convert::Infallible;
use std::num::NonZeroU32;

use zcash_client_backend::data_api::locking::{LockFilter, LockedInputPolicy};
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError;
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_standard_transfer_to_address, ConfirmationsPolicy,
    SpendingKeys,
};
use zcash_client_backend::data_api::{
    InputSource as _, MaxSpendMode, TargetValue, WalletRead as _,
};
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::wallet::{NoteId, OvkPolicy};
use zcash_primitives::transaction::fees::zip317::{FeeError, MINIMUM_FEE};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;

use crate::mint::{Request, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// Minimum vault payment for a sweep to fire (1 ZEC): a floor on what
/// actually moves, not on the balance behind it.
pub const SWEEP_MINIMUM: Zatoshis = Zatoshis::const_from_u64(100_000_000);

/// Amount retained as Treasury change after a sweep (0.01 ZEC): the
/// operating float that funds the next Name Note's fee.
pub const SWEEP_RESERVE: Zatoshis = Zatoshis::const_from_u64(1_000_000);

/// Amount paid to the controller with an OTP challenge memo. This is the
/// payment value; the transaction's ZIP-317 fee is calculated separately.
pub const CHALLENGE_RELAY_VALUE: Zatoshis = MINIMUM_FEE;

/// The project vault's P2PKH address (placeholder pending final approved
/// address).
pub const VAULT_ADDRESS: transparent::address::TransparentAddress =
    transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]);

/// A Treasury transaction was not built. Distinct from "nothing to do".
#[derive(Debug)]
pub enum BuildFailure {
    /// No target height or anchor was available.
    HeightsUnavailable,
    /// Note selection failed.
    Selection(String),
    /// Selected note values overflowed the monetary range.
    Balance,
    /// The ZIP-321 payment could not be formed.
    Request,
    /// Input selection or fee calculation refused the proposal.
    Proposal(String),
    /// Proving or signing failed. The wallet was not asked to store a tx.
    Build(String),
}

impl std::fmt::Display for BuildFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeightsUnavailable => write!(f, "no target or anchor height"),
            Self::Selection(error) => write!(f, "note selection failed: {error}"),
            Self::Balance => write!(f, "selected notes overflow"),
            Self::Request => write!(f, "ZIP-321 request invalid"),
            Self::Proposal(error) => write!(f, "proposal failed: {error}"),
            Self::Build(error) => write!(f, "transaction build failed: {error}"),
        }
    }
}

impl std::error::Error for BuildFailure {}

/// One sweep: all Treasury value above the operating float moves to the
/// vault when at least `SWEEP_MINIMUM` moves. `main` gates the once-per-day
/// cadence. The ZIP-321 amount is `total` minus `SWEEP_RESERVE`; the standard
/// transfer helper prices ZIP-317 and the fee comes out of the float. `Ok(None)`
/// means nothing needs moving. `Err` reports a build failure; the next daily
/// gate tries again. A read-back miss after a successful build is FATAL — the
/// wallet has already marked the inputs spent.
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Result<Option<Transaction>, BuildFailure> {
    let policy = ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false);
    let (target_height, _) = match wallet.get_target_and_anchor_heights(NonZeroU32::MIN) {
        Ok(Some(heights)) => heights,
        Ok(None) | Err(_) => return Err(BuildFailure::HeightsUnavailable),
    };

    let lock_policy = LockedInputPolicy::Exclude;
    let notes = match wallet.select_spendable_notes(
        TREASURY_ACCOUNT,
        TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
        &[ShieldedPool::Sapling, ShieldedPool::Ironwood],
        target_height,
        policy,
        &[],
        LockFilter::Policy(&lock_policy),
    ) {
        Ok(notes) if !notes.is_empty() => notes,
        Ok(_) => {
            tracing::debug!("vault sweep skipped: no spendable notes");
            return Ok(None);
        }
        Err(error) => return Err(BuildFailure::Selection(format!("{error:?}"))),
    };
    let total = notes.total_value().map_err(|_| BuildFailure::Balance)?;

    let Some(payment) = (total - SWEEP_RESERVE).filter(|p| *p >= SWEEP_MINIMUM) else {
        if total < SWEEP_RESERVE {
            tracing::info!(
                spendable_zats = total.into_u64(),
                float_zats = SWEEP_RESERVE.into_u64(),
                "vault sweep skipped: spendable below the float"
            );
        } else {
            tracing::debug!(
                spendable_zats = total.into_u64(),
                minimum_zats = SWEEP_MINIMUM.into_u64(),
                "vault sweep skipped: payment below the minimum"
            );
        }
        return Ok(None);
    };

    let proposal = propose_standard_transfer_to_address::<_, _, Infallible>(
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
    .map_err(|error| BuildFailure::Proposal(format!("{error:?}")))?;

    let spending_keys = SpendingKeys::new(treasury_keys.usk_clone());
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
    .map_err(|error| BuildFailure::Build(format!("{error:?}")))?;

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
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    controller: &zcash_keys::address::UnifiedAddress,
    memo: MemoBytes,
) -> Result<Transaction, BuildFailure> {
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
    .map_err(|error| BuildFailure::Proposal(format!("{error:?}")))?;

    let spending_keys = SpendingKeys::new(treasury_keys.usk_clone());
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
    .map_err(|error| BuildFailure::Build(format!("{error:?}")))?;

    Ok(wallet
        .get_transaction(*txids.first())
        .expect("FATAL: challenge transaction lookup failed")
        .expect("FATAL: challenge transaction was not recorded"))
}

// ---------------------------------------------------------------------------
// RequestQueue — Treasury requests decoded once, at block application
// ---------------------------------------------------------------------------

/// Treasury requests decoded once at block application: what each memo
/// said, what it paid, the block that carried it. Entries leave by
/// decision (`remove`) or by reorg (`truncate_to`); nothing else removes
/// them.
#[derive(Clone, Debug, Default)]
pub struct RequestQueue {
    requests: Vec<(TxId, Request, Zatoshis, BlockHeight)>,
}

impl RequestQueue {
    /// A recognized name request, routed after block application.
    pub fn record(&mut self, txid: TxId, request: Request, paid: Zatoshis, height: BlockHeight) {
        self.requests.push((txid, request, paid, height));
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// The entry at `index`, in block order — the drain cursor reads.
    pub fn entry(&self, index: usize) -> (&TxId, &Request, Zatoshis, BlockHeight) {
        let (txid, request, paid, height) = &self.requests[index];
        (txid, request, *paid, *height)
    }

    /// The entry is decided. The only removal besides reorg truncation.
    pub fn remove(&mut self, index: usize) {
        self.requests.remove(index);
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
        assert_eq!(queue.len(), 0);

        queue.record(TxId::NULL, request(Action::Claim), Zatoshis::ZERO, h(100));
        queue.record(TxId::NULL, request(Action::Update), Zatoshis::ZERO, h(101));

        assert_eq!(queue.len(), 2);
        assert_eq!(*queue.entry(0).0, TxId::NULL);
        assert_eq!(queue.entry(0).3, h(100));
        assert_eq!(queue.entry(1).3, h(101));
    }

    #[test]
    fn queue_remove_shifts_neighbors() {
        let mut queue = RequestQueue::default();
        queue.record(TxId::NULL, request(Action::Claim), Zatoshis::ZERO, h(100));
        queue.record(TxId::NULL, request(Action::Update), Zatoshis::ZERO, h(101));
        queue.record(TxId::NULL, request(Action::Release), Zatoshis::ZERO, h(102));

        queue.remove(1);
        assert_eq!(queue.len(), 2);
        // The entry after the removed one shifted into its place.
        assert!(matches!(queue.entry(1).1, Request::Release { .. }));
        assert_eq!(queue.entry(1).3, h(102));
    }

    #[test]
    fn queue_truncate_drops_only_orphaned_heights() {
        let mut queue = RequestQueue::default();
        queue.record(TxId::NULL, request(Action::Claim), Zatoshis::ZERO, h(100));
        queue.record(TxId::NULL, request(Action::Update), Zatoshis::ZERO, h(150));
        queue.record(TxId::NULL, request(Action::Release), Zatoshis::ZERO, h(200));

        queue.truncate_to(h(120));
        assert_eq!(queue.len(), 1);
        assert!(matches!(queue.entry(0).1, Request::Claim { .. }));
        assert_eq!(queue.entry(0).3, h(100));
    }
}
