//! Treasury wallet view and Treasury policy for the mint.
//!

use std::convert::Infallible;
use std::num::NonZeroU32;

use zcash_client_backend::data_api::wallet::input_selection::{
    GreedyInputSelector, GreedyInputSelectorError, SpendPolicy,
};
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
use zcash_client_backend::fees::{DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::wallet::{NoteId, OvkPolicy};
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::fees::zip317::{FeeError, GRACE_ACTIONS, MARGINAL_FEE};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::mint::{Action, Name, Term, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// A user memo decoded from a Treasury note. Claims always carry a term
/// (`forever` or `<N>y`); updates carry `none` or `<N>y`. The wire never
/// carries an OTP — `otp` is set only by intake, when a relay echo
/// (`ZNS:otp:…`, routed by `Challenge::decode`) rides the queue in
/// request shape.
#[derive(Clone, Debug)]
pub struct ParsedRequest {
    pub action: Action,
    pub name: Name,
    pub ua: UnifiedAddress,
    pub term: Option<Term>,
    /// Intake-only: the relay echo's digits. `parse_request` never sets it.
    pub otp: Option<[u8; 6]>,
}

/// Parses a 512-byte memo sent to the Treasury as a ZNS Request.
///
/// Field slots are positional; the term leads, so every human-facing memo
/// keeps `<ua>` terminal — the NameNote is the one exception, ending in
/// its chain link:
///
/// - Claim: `ZNS:claim:<term>:<name>:<ua>` — `<term>` is `forever` or
///   `<N>y`, N = 1–99.
/// - Update: `ZNS:update:<term>:<name>:<ua>` — `<term>` is `none`
///   (expiry carried forward) or `<N>y`.
/// - Release: `ZNS:release:<name>:<ua>`
///
/// Requests never carry an OTP — answering is the respond's job: an echo
/// is the relay memo itself (`ZNS:otp:…`, routed by `Challenge::decode`),
/// never this parser.
pub fn parse_request<P: Parameters>(network: &P, raw: &[u8; 512]) -> Option<ParsedRequest> {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    if raw[end..].iter().any(|b| *b != 0) {
        return None;
    }
    let text = core::str::from_utf8(&raw[..end]).ok()?;

    let mut fields = text.split(':');
    if fields.next()? != "ZNS" {
        return None;
    }
    let action = match fields.next()? {
        "claim" => Action::Claim,
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    // The term leads: claims say `forever` or `<N>y`; updates say `none`
    // or `<N>y` — never `forever`.
    let term = match action {
        Action::Claim => Some(Term::parse(fields.next()?)?),
        Action::Update => match fields.next()? {
            "none" => None,
            "forever" => return None,
            field => Some(Term::parse(field)?),
        },
        Action::Release => None,
    };

    let name = Name::parse(fields.next()?)?;
    let ua_str = fields.next()?;
    if ua_str.is_empty() || fields.next().is_some() {
        return None;
    }
    let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
        zcash_keys::address::Address::Unified(ua) => ua,
        _ => return None,
    };

    Some(ParsedRequest {
        action,
        name,
        ua,
        term,
        otp: None,
    })
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

/// One sweep: all Treasury value above the operating float moves to the
/// vault through a single `propose_transfer` on default spend policy.
/// The selector drains the Sapling pool first — it is dead weight — and
/// Ironwood covers the remainder; the change returns as one Ironwood note
/// carrying the float. Returns `None` on any failure; retried at the next tip.
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Option<zcash_primitives::transaction::Transaction> {
    let policy = ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false);
    let Some((target_height, _)) = wallet
        .get_target_and_anchor_heights(NonZeroU32::MIN)
        .ok()
        .flatten()
    else {
        tracing::warn!("vault sweep skipped: no target/anchor heights");
        return None;
    };

    let Some(summary) = wallet.get_wallet_summary(policy).ok().flatten() else {
        tracing::warn!("vault sweep skipped: no wallet summary");
        return None;
    };
    let Some(account) = summary.account_balances().get(&TREASURY_ACCOUNT) else {
        tracing::warn!("vault sweep skipped: Treasury account missing from summary");
        return None;
    };
    let sapling = account.sapling_balance().spendable_value();
    let ironwood = account.ironwood_balance().spendable_value();
    let spendable = (sapling + ironwood).expect("balances sum");
    if spendable <= SWEEP_THRESHOLD {
        tracing::debug!(
            spendable_zats = spendable.into_u64(),
            threshold_zats = SWEEP_THRESHOLD.into_u64(),
            "vault sweep skipped: below threshold"
        );
        return None;
    }

    // The fee bound covers every note in both pools plus the transparent
    // output and the change note; the surplus returns as change.
    let note_count = wallet
        .unspent_sapling_notes(TREASURY_ACCOUNT, target_height)
        .len()
        + wallet
            .unspent_ironwood_notes(TREASURY_ACCOUNT, target_height)
            .len();
    let actions = (note_count + 3).max(GRACE_ACTIONS);
    let bound = Zatoshis::from_u64(MARGINAL_FEE.into_u64() * actions as u64)
        .expect("fee bound fits the monetary range");
    let Some(payment) = (spendable - SWEEP_RESERVE).and_then(|remaining| remaining - bound) else {
        tracing::warn!(
            spendable_zats = spendable.into_u64(),
            reserve_zats = SWEEP_RESERVE.into_u64(),
            "vault sweep skipped: reserve and fee exceed spendable"
        );
        return None;
    };
    if payment.is_zero() {
        tracing::warn!("vault sweep skipped: payment is zero");
        return None;
    }

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
        &SpendPolicy::default(),
        None,
        None,
    )
    .map_err(|error| tracing::warn!(?error, "vault sweep proposal failed"))
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

    match wallet.get_transaction(*txids.first()).ok().flatten() {
        Some(tx) => Some(tx),
        None => {
            tracing::warn!("vault sweep skipped: built tx missing from wallet");
            None
        }
    }
}

/// Proposes, builds, and records a Treasury payment carrying an OTP challenge
/// memo to the controller. Funded from Treasury notes via upstream's generic
/// selection path. Returns `None` when the Treasury cannot cover the relay
/// value and fee; the lane retries next tip.
#[allow(clippy::too_many_arguments)]
pub fn challenge<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    controller: &zcash_keys::address::UnifiedAddress,
    memo: [u8; 512],
    relay_value: Zatoshis,
) -> Option<zcash_primitives::transaction::Transaction> {
    use zcash_client_backend::data_api::wallet::input_selection::{
        GreedyInputSelector, SpendPolicy,
    };
    use zcash_client_backend::data_api::wallet::{
        create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
    };
    use zcash_client_backend::data_api::WalletRead as _;
    use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
    use zcash_client_backend::fees::{DustOutputPolicy, StandardFeeRule};
    use zcash_client_backend::wallet::OvkPolicy;

    let request = zip321::TransactionRequest::new(vec![zip321::Payment::new(
        zcash_keys::address::Address::Unified(controller.clone()).to_zcash_address(network),
        Some(relay_value),
        Some(
            zcash_protocol::memo::MemoBytes::from_bytes(&memo)
                .expect("a 512-byte protocol memo is valid"),
        ),
        None,
        None,
        vec![],
    )
    .expect("valid ZIP-321 payment")])
    .expect("valid ZIP-321 request");

    let input_selector = GreedyInputSelector::<Wallet>::new();
    let change_strategy = SingleOutputChangeStrategy::<Wallet>::new(
        StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );

    let proposal = propose_transfer::<
        Wallet,
        P,
        GreedyInputSelector<Wallet>,
        SingleOutputChangeStrategy<Wallet>,
        std::convert::Infallible,
    >(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::new_symmetrical(std::num::NonZeroU32::MIN, false),
        &SpendPolicy::default(),
        None,
        None,
    )
    .ok()?;

    let spending_keys = SpendingKeys::new(treasury_keys.usk_clone());
    let txids = create_proposed_transactions::<
        Wallet,
        P,
        GreedyInputSelectorError,
        StandardFeeRule,
        zcash_primitives::transaction::fees::zip317::FeeError,
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
    requests: Vec<(ParsedRequest, Zatoshis, BlockHeight)>,
}

impl RequestQueue {
    /// An arrival, decoded once at block application.
    pub fn record(&mut self, request: ParsedRequest, paid: Zatoshis, height: BlockHeight) {
        self.requests.push((request, paid, height));
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// The entry at `index`, in block order — the drain cursor reads.
    pub fn entry(&self, index: usize) -> (&ParsedRequest, Zatoshis, BlockHeight) {
        let (request, paid, height) = &self.requests[index];
        (request, *paid, *height)
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
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    fn request(action: Action) -> ParsedRequest {
        match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ParsedRequest {
                action,
                name: Name::parse("alice").unwrap(),
                ua,
                term: None,
                otp: None,
            },
            _ => panic!("vector is a mainnet Unified Address"),
        }
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
        assert_eq!(queue.entry(1).0.action, Action::Release);
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
        assert_eq!(queue.entry(0).0.action, Action::Claim);
        assert_eq!(queue.entry(0).2, h(100));
    }

    fn padded(s: &str) -> [u8; 512] {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m
    }

    #[test]
    fn accepts_exactly_the_three_request_forms() {
        let network = MainNetwork;

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:claim:forever:alice:{TEST_UA}")),
        )
        .unwrap();
        assert_eq!(req.action, Action::Claim);
        assert_eq!(req.name.as_str(), "alice");
        assert_eq!(req.term, Some(Term::Forever));

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:update:none:alice:{TEST_UA}")),
        )
        .unwrap();
        assert_eq!(req.action, Action::Update);
        assert_eq!(req.name.as_str(), "alice");
        assert_eq!(req.term, None);

        let req =
            parse_request(&network, &padded(&format!("ZNS:release:alice:{TEST_UA}"))).unwrap();
        assert_eq!(req.action, Action::Release);
        assert_eq!(req.name.as_str(), "alice");
        assert_eq!(req.term, None);
    }

    #[test]
    fn claims_say_forever_updates_say_none_or_years() {
        let network = MainNetwork;

        let req =
            parse_request(&network, &padded(&format!("ZNS:claim:12y:alice:{TEST_UA}"))).unwrap();
        assert_eq!(req.term, Some(Term::Years(12)));

        let req =
            parse_request(&network, &padded(&format!("ZNS:update:3y:alice:{TEST_UA}"))).unwrap();
        assert_eq!(req.term, Some(Term::Years(3)));

        // The verbs' term slots are not interchangeable.
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:none:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:forever:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(parse_request(&network, &padded(&format!("ZNS:claim::alice:{TEST_UA}"))).is_none());
    }

    #[test]
    fn strict_spellings_are_rejected_on_sight() {
        let network = MainNetwork;
        // Missing y, over the cap, leading zero.
        assert!(
            parse_request(&network, &padded(&format!("ZNS:claim:5:alice:{TEST_UA}"))).is_none()
        );
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:100y:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(
            parse_request(&network, &padded(&format!("ZNS:claim:01y:alice:{TEST_UA}"))).is_none()
        );
        // Seconds never appear on the request wire.
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:31557600:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:31557600:alice:{TEST_UA}"))
        )
        .is_none());
    }

    #[test]
    fn requests_never_carry_an_otp() {
        let network = MainNetwork;
        // The respond spellings are gone; the echo is the relay memo.
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:none:alice:{TEST_UA}:004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:forever:alice:{TEST_UA}:004206"))
        )
        .is_none());
    }

    #[test]
    fn rejects_extra_field() {
        let network = MainNetwork;
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:forever:alice:{TEST_UA}:extra"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:none:alice:{TEST_UA}:more"))
        )
        .is_none());
    }

    #[test]
    fn rejects_unknown_verb() {
        let network = MainNetwork;
        // The echo lane is routed by Challenge::decode, never here.
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:otp:417293:alice:update:{TEST_UA}"))
        )
        .is_none());
    }

    #[test]
    fn rejects_non_zns() {
        let network = MainNetwork;
        assert!(parse_request(&network, &padded("hello world")).is_none());
    }

    #[test]
    fn rejects_invalid_name() {
        let network = MainNetwork;
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:forever:INVALID:{TEST_UA}"))
        )
        .is_none());
    }
}
