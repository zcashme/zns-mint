//! Treasury wallet view and Treasury policy for the mint: the vault
//! sweep, the challenge relay builder, and the request queue.
//!

use std::convert::Infallible;
use std::num::NonZeroU32;

use zcash_client_backend::data_api::locking::{LockFilter, LockedInputPolicy};
use zcash_client_backend::data_api::wallet::input_selection::{
    GreedyInputSelector, GreedyInputSelectorError, SpendPolicy,
};
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{
    InputSource as _, MaxSpendMode, TargetValue, WalletRead as _,
};
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
use zcash_client_backend::fees::{DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::wallet::{NoteId, OvkPolicy};
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;

use crate::mint::{MintInbound, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// Minimum vault payment for a sweep to fire (1 ZEC): a floor on what
/// actually moves, not on the balance behind it.
pub const SWEEP_MINIMUM: Zatoshis = Zatoshis::const_from_u64(100_000_000);

/// Amount retained as Treasury change after a sweep (0.01 ZEC): the
/// operating float that funds the next Name Note's fee.
pub const SWEEP_RESERVE: Zatoshis = Zatoshis::const_from_u64(1_000_000);

/// The project vault's P2PKH address (placeholder pending final approved
/// address).
pub const VAULT_ADDRESS: transparent::address::TransparentAddress =
    transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]);

/// One sweep: all Treasury value above the operating float moves to the
/// vault, and only when this tip's catch-up advanced the mint's day and
/// at least `SWEEP_MINIMUM` moves. The ZIP-321 amount is `total` minus
/// `SWEEP_RESERVE`; `propose_transfer` prices ZIP-317 and the fee comes
/// out of the float (leftover is reserve minus fee, not exactly reserve).
/// Only Sapling and Ironwood are spent. Returns `None` on a same-day
/// tip or any failure before the build; the next midnight crossing
/// tries again. A read-back miss after a successful build is FATAL —
/// the wallet has already marked the inputs spent.
#[allow(clippy::too_many_arguments)]
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    today: i64,
    previous_day: i64,
) -> Option<Transaction> {
    if today <= previous_day {
        return None;
    }

    let policy = ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false);
    let Some((target_height, _)) = wallet
        .get_target_and_anchor_heights(NonZeroU32::MIN)
        .ok()
        .flatten()
    else {
        tracing::warn!("vault sweep skipped: no target/anchor heights");
        return None;
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
            return None;
        }
        Err(error) => {
            tracing::warn!(?error, "vault sweep skipped: note selection failed");
            return None;
        }
    };
    let Some(total) = notes.total_value().ok() else {
        tracing::warn!("vault sweep skipped: selected notes overflow");
        return None;
    };

    let Some(payment) = (total - SWEEP_RESERVE).filter(|p| *p >= SWEEP_MINIMUM) else {
        tracing::debug!(
            spendable_zats = total.into_u64(),
            minimum_zats = SWEEP_MINIMUM.into_u64(),
            "vault sweep skipped: payment below the minimum"
        );
        return None;
    };

    let Some(request) = zip321::Payment::new(
        zcash_keys::address::Address::Transparent(VAULT_ADDRESS).to_zcash_address(network),
        Some(payment),
        None,
        None,
        None,
        vec![],
    )
    .ok()
    .and_then(|pay| zip321::TransactionRequest::new(vec![pay]).ok()) else {
        tracing::warn!("vault sweep skipped: ZIP-321 request invalid");
        return None;
    };

    let proposal = propose_transfer::<_, _, _, _, Infallible>(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &GreedyInputSelector::new(),
        &SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            zcash_protocol::ShieldedPool::Ironwood,
            DustOutputPolicy::default(),
        ),
        request,
        policy,
        &SpendPolicy::shielded_pools([ShieldedPool::Sapling, ShieldedPool::Ironwood]),
        None,
        None,
    )
    .map_err(|error| {
        tracing::warn!(
            ?error,
            payment_zats = payment.into_u64(),
            spendable_zats = total.into_u64(),
            "vault sweep proposal failed"
        )
    })
    .ok()?;

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
    .map_err(|error| tracing::warn!(?error, "vault sweep build failed"))
    .ok()?;

    // The build stored the tx and marked its inputs spent; a miss here is
    // the wallet contradicting itself, not a skip. Stop; restart rescans.
    Some(
        wallet
            .get_transaction(*txids.first())
            .expect("FATAL: vault sweep lookup failed after build")
            .expect("FATAL: built vault sweep tx missing from wallet"),
    )
}

/// Proposes, builds, and records a Treasury payment carrying an OTP challenge
/// memo to the controller. Funded from Treasury notes via upstream's generic
/// selection path. Returns `None` when the Treasury cannot cover the relay
/// value and fee; the lane retries next tip.
#[allow(clippy::too_many_arguments)]
pub fn challenge<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    controller: &zcash_keys::address::UnifiedAddress,
    memo: MemoBytes,
    relay_value: Zatoshis,
) -> Option<Transaction> {
    let Some(request) = zip321::Payment::new(
        zcash_keys::address::Address::Unified(controller.clone()).to_zcash_address(network),
        Some(relay_value),
        Some(memo),
        None,
        None,
        vec![],
    )
    .ok()
    .and_then(|pay| zip321::TransactionRequest::new(vec![pay]).ok()) else {
        tracing::warn!("challenge relay skipped: ZIP-321 request invalid");
        return None;
    };

    let input_selector = GreedyInputSelector::<Wallet<P>>::new();
    let change_strategy = SingleOutputChangeStrategy::<Wallet<P>>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );

    let proposal = propose_transfer::<
        Wallet<P>,
        P,
        GreedyInputSelector<Wallet<P>>,
        SingleOutputChangeStrategy<Wallet<P>>,
        Infallible,
    >(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false),
        &SpendPolicy::default(),
        None,
        None,
    )
    .ok()?;

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
    .expect("FATAL: challenge transaction creation failed");

    Some(
        wallet
            .get_transaction(*txids.first())
            .expect("FATAL: challenge transaction lookup failed")
            .expect("FATAL: challenge transaction was not recorded"),
    )
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
    requests: Vec<(MintInbound, Zatoshis, BlockHeight)>,
}

impl RequestQueue {
    /// An arrival, decoded once at block application.
    pub fn record(&mut self, inbound: MintInbound, paid: Zatoshis, height: BlockHeight) {
        self.requests.push((inbound, paid, height));
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// The entry at `index`, in block order — the drain cursor reads.
    pub fn entry(&self, index: usize) -> (&MintInbound, Zatoshis, BlockHeight) {
        let (inbound, paid, height) = &self.requests[index];
        (inbound, *paid, *height)
    }

    /// The entry is decided. The only removal besides reorg truncation.
    pub fn remove(&mut self, index: usize) {
        self.requests.remove(index);
    }

    /// Reorg: entries whose block was orphaned fall with it.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) {
        self.requests.retain(|(_, _, height)| *height <= ancestor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Action, Name, Request, Term};
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn request(action: Action) -> MintInbound {
        let ua = match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        };
        let name = Name::parse("alice").unwrap();
        MintInbound::Request(match action {
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
        })
    }

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    #[test]
    fn queue_records_in_block_order() {
        let mut queue = RequestQueue::default();
        assert_eq!(queue.len(), 0);

        queue.record(request(Action::Claim), Zatoshis::ZERO, h(100));
        queue.record(request(Action::Update), Zatoshis::ZERO, h(101));

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.entry(0).2, h(100));
        assert_eq!(queue.entry(1).2, h(101));
    }

    #[test]
    fn queue_remove_shifts_neighbors() {
        let mut queue = RequestQueue::default();
        queue.record(request(Action::Claim), Zatoshis::ZERO, h(100));
        queue.record(request(Action::Update), Zatoshis::ZERO, h(101));
        queue.record(request(Action::Release), Zatoshis::ZERO, h(102));

        queue.remove(1);
        assert_eq!(queue.len(), 2);
        // The entry after the removed one shifted into its place.
        assert!(matches!(
            queue.entry(1).0,
            MintInbound::Request(Request::Release { .. })
        ));
        assert_eq!(queue.entry(1).2, h(102));
    }

    #[test]
    fn queue_truncate_drops_only_orphaned_heights() {
        let mut queue = RequestQueue::default();
        queue.record(request(Action::Claim), Zatoshis::ZERO, h(100));
        queue.record(request(Action::Update), Zatoshis::ZERO, h(150));
        queue.record(request(Action::Release), Zatoshis::ZERO, h(200));

        queue.truncate_to(h(120));
        assert_eq!(queue.len(), 1);
        assert!(matches!(
            queue.entry(0).0,
            MintInbound::Request(Request::Claim { .. })
        ));
        assert_eq!(queue.entry(0).2, h(100));
    }
}
