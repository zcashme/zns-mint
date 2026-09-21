//! Treasury wallet view and Treasury policy for the mint.
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
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;

use crate::mint::presale::AccessCode;
use crate::mint::{Action, MintInbound, Name, Request, Term, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// Parses a 512-byte memo sent to the Treasury as a ZNS Request.
///
/// Field slots are positional; every human-facing memo keeps `<ua>`
/// terminal — the NameNote is the one exception, ending in its chain
/// link:
///
/// - Claim: `ZNS:claim:<term>:<name>:<ua>` or
///   `ZNS:claim:<code>:<term>:<name>:<ua>` — `<term>` is `forever` or
///   `<N>y`, N = 1–99. A leading field that parses as a term is the
///   term (codeless form, byte-identical to the three-slot claim);
///   otherwise it is the pre-sale access code: exactly six ASCII decimal
///   digits, including leading zeroes (claim-only; never a term spelling).
/// - Update: `ZNS:update:<term>:<name>:<ua>` — `<term>` is `none`
///   (expiry carried forward), `<N>y`, or `forever` (the upgrade: a
///   fixed-term registration converts to no fixed expiration).
/// - Release: `ZNS:release:<name>:<ua>`
///
/// Requests never carry an OTP — answering is the respond's job: an echo
/// is the relay memo itself (`ZNS:otp:…`, routed by `Challenge::decode`),
/// never this parser.
pub fn parse_request<P: Parameters>(network: &P, raw: &[u8; 512]) -> Option<Request> {
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

    // Claims may lead with a pre-sale code; the discriminator is whether
    // the next field is a term. Updates say `none`, `<N>y`, or `forever`.
    let (claim_code, term) = match action {
        Action::Claim => {
            let first = fields.next()?;
            if first.is_empty() {
                return None;
            }
            if let Some(term) = Term::parse(first) {
                (None, Some(term))
            } else {
                let code = AccessCode::parse(first)?;
                let term = Term::parse(fields.next()?)?;
                (Some(code), Some(term))
            }
        }
        Action::Update => {
            let term = match fields.next()? {
                "none" => None,
                "forever" => Some(Term::Forever),
                field => Some(Term::parse(field)?),
            };
            (None, term)
        }
        Action::Release => (None, None),
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

    Some(match (action, term) {
        (Action::Claim, Some(term)) => Request::Claim {
            name,
            ua,
            term,
            code: claim_code,
        },
        (Action::Update, _) => Request::Update { name, ua, term },
        (Action::Release, _) => Request::Release { name, ua },
        // The wire always carries a claim term.
        (Action::Claim, None) => unreachable!("claims always carry a term"),
    })
}

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
/// tip or any failure; the next midnight crossing tries again.
#[allow(clippy::too_many_arguments)]
pub fn sweep_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    today: i64,
    previous_day: i64,
) -> Option<zcash_primitives::transaction::Transaction> {
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
    wallet: &mut Wallet<P>,
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

    let input_selector = GreedyInputSelector::<Wallet<P>>::new();
    let change_strategy = SingleOutputChangeStrategy::<Wallet<P>>::new(
        StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );

    let proposal = propose_transfer::<
        Wallet<P>,
        P,
        GreedyInputSelector<Wallet<P>>,
        SingleOutputChangeStrategy<Wallet<P>>,
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
        Wallet<P>,
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
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

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

    fn padded(s: &str) -> [u8; 512] {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m
    }

    #[test]
    fn accepts_exactly_the_three_request_forms() {
        let network = MainNetwork;

        assert!(matches!(
            parse_request(&network, &padded(&format!("ZNS:claim:forever:alice:{TEST_UA}"))),
            Some(Request::Claim {
                name,
                term: Term::Forever,
                code: None,
                ..
            }) if name.as_str() == "alice"
        ));
        assert!(matches!(
            parse_request(
                &network,
                &padded(&format!("ZNS:update:none:alice:{TEST_UA}"))
            ),
            Some(Request::Update { term: None, .. })
        ));
        assert!(matches!(
            parse_request(&network, &padded(&format!("ZNS:release:alice:{TEST_UA}"))),
            Some(Request::Release { .. })
        ));
    }

    #[test]
    fn claim_may_lead_with_a_presale_code() {
        let network = MainNetwork;
        let code = AccessCode::parse("004206").unwrap();

        assert!(matches!(
            parse_request(
                &network,
                &padded(&format!("ZNS:claim:004206:forever:alice:{TEST_UA}"))
            ),
            Some(Request::Claim {
                term: Term::Forever,
                code: Some(ref parsed),
                ..
            }) if parsed == &code
        ));
        // Codeless three-slot form is unchanged.
        assert!(matches!(
            parse_request(
                &network,
                &padded(&format!("ZNS:claim:forever:alice:{TEST_UA}"))
            ),
            Some(Request::Claim {
                code: None,
                term: Term::Forever,
                ..
            })
        ));
        // A term-shaped first field is never taken as a code.
        assert!(matches!(
            parse_request(&network, &padded(&format!("ZNS:claim:12y:alice:{TEST_UA}"))),
            Some(Request::Claim {
                code: None,
                term: Term::Years(12),
                ..
            })
        ));
        // Not exactly six digits.
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:4206:forever:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:a1b2c3:forever:alice:{TEST_UA}"))
        )
        .is_none());
    }

    #[test]
    fn claims_say_forever_updates_say_none_years_or_forever() {
        let network = MainNetwork;

        assert!(matches!(
            parse_request(&network, &padded(&format!("ZNS:claim:12y:alice:{TEST_UA}"))),
            Some(Request::Claim {
                term: Term::Years(12),
                ..
            })
        ));
        assert!(matches!(
            parse_request(&network, &padded(&format!("ZNS:update:3y:alice:{TEST_UA}"))),
            Some(Request::Update {
                term: Some(Term::Years(3)),
                ..
            })
        ));

        // The verbs' term slots are not interchangeable: claims never
        // say `none`. Updates may also carry the upgrade spelling.
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:none:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(matches!(
            parse_request(
                &network,
                &padded(&format!("ZNS:update:forever:alice:{TEST_UA}"))
            ),
            Some(Request::Update {
                term: Some(Term::Forever),
                ..
            })
        ));
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
