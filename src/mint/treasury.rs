//! Treasury wallet view and Treasury policy for the mint.
//!

use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError;
use zcash_client_backend::wallet::NoteId;
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::mint::otp::OtpCode;
use crate::mint::{Action, Name, Term, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// A user memo decoded from a Treasury note.
///
/// `term` is the optional registration period (claim) or extension (update).
/// `None` means no fixed expiration on a claim, or carry-forward on an update.
/// `otp` is present only on an update/release Respond; its absence is a
/// Request (claim, or the first step of authorization).
pub struct ParsedRequest {
    pub action: Action,
    pub name: Name,
    pub ua: UnifiedAddress,
    pub term: Option<Term>,
    pub otp: Option<[u8; 6]>,
}

/// Parses a 512-byte memo sent to the Treasury as a ZNS Request or Respond.
///
/// Field slots are positional. Trailing OTP is omitted on a Request:
///
/// - Claim: `ZNS:claim:<name>:<ua>[:<term>]` — never an OTP.
/// - Update request: `ZNS:update:<name>:<ua>[:<term>]`
/// - Update respond: `ZNS:update:<name>:<ua>:<term>:<otp>`
/// - Release request: `ZNS:release:<name>:<ua>`
/// - Release respond: `ZNS:release:<name>:<ua>:<otp>`
///
/// `term` is a canonical second-duration or the exact field `none`. An update
/// Respond always occupies the term slot (`none` if the Request carried none).
/// `otp` is exactly six ASCII decimal digits, including leading zeroes.
/// Relay memos (`ZNS:otp:…`) are not Requests or Responds.
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
    let verb = fields.next()?;
    let name_str = fields.next()?;
    let name = Name::parse(name_str)?;

    let ua_str = fields.next()?;
    if ua_str.is_empty() {
        return None;
    }

    let extra1 = fields.next();
    let extra2 = fields.next();
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

    let (term, otp) = match action {
        Action::Claim => {
            if extra2.is_some() {
                return None;
            }
            (parse_term_slot(extra1)?, None)
        }
        Action::Update => {
            let otp = match extra2 {
                None => None,
                Some(field) => Some(parse_otp_slot(field)?),
            };
            (parse_term_slot(extra1)?, otp)
        }
        Action::Release => {
            if extra2.is_some() {
                return None;
            }
            let otp = match extra1 {
                None => None,
                Some(field) => Some(parse_otp_slot(field)?),
            };
            (None, otp)
        }
    };

    Some(ParsedRequest {
        action,
        name,
        ua,
        term,
        otp,
    })
}

fn parse_term_slot(field: Option<&str>) -> Option<Option<Term>> {
    match field {
        None | Some("none") => Some(None),
        Some(field) => Term::parse(field).map(Some),
    }
}

fn parse_otp_slot(field: &str) -> Option<[u8; 6]> {
    let digits: [u8; 6] = field.as_bytes().try_into().ok()?;
    OtpCode::from_digits(&digits)?;
    Some(digits)
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
/// ZNS ever spends from it. Returns `None` when the balance is zero.
pub fn sweep_sapling_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Option<zcash_primitives::transaction::Transaction> {
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
        return None;
    }

    let vault_recipient =
        zcash_keys::address::Address::Transparent(VAULT_ADDRESS).to_zcash_address(network);
    let proposal =
        match propose_send_max_transfer::<Wallet, P, StandardFeeRule, std::convert::Infallible>(
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
        ) {
            Ok(p) => p,
            Err(error) => {
                tracing::error!(?error, "Sapling vault sweep construction failed");
                return None;
            }
        };

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
    .expect("FATAL: Sapling vault sweep creation failed");

    Some(
        wallet
            .get_transaction(*txids.first())
            .expect("FATAL: Sapling sweep transaction lookup failed")
            .expect("FATAL: Sapling sweep was not recorded"),
    )
}

/// Sweeps excess Ironwood Treasury notes to the project vault, retaining a
/// reserve for fees. Returns `None` when the balance is below the threshold.
pub fn sweep_ironwood_to_vault<P: Parameters>(
    network: &P,
    wallet: &mut Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    tip: BlockHeight,
    target_height: BlockHeight,
) -> Option<zcash_primitives::transaction::Transaction> {
    use zcash_client_backend::data_api::wallet::TargetHeight;
    use zcash_client_backend::data_api::{SentTransaction, WalletWrite as _};
    use zcash_client_backend::fees::StandardFeeRule;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::zip317::P2PKH_STANDARD_OUTPUT_SIZE;
    use zcash_primitives::transaction::fees::FeeRule as _;

    let mut sweep_notes = wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, TargetHeight::from(tip));
    sweep_notes.retain(|note| note.mined_height().is_some());
    let sweep_funding = sweep_notes.iter().fold(Zatoshis::ZERO, |total, note| {
        (total
            + Zatoshis::from_u64(note.note().value().inner())
                .expect("Treasury note value fits the monetary range"))
        .expect("Treasury balance fits the monetary range")
    });
    if sweep_funding <= SWEEP_THRESHOLD {
        return None;
    }

    let ironwood_actions = sweep_notes.len().max(1);
    let transaction_fee = StandardFeeRule::Zip317
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            [P2PKH_STANDARD_OUTPUT_SIZE],
            0,
            0,
            0,
            ironwood_actions,
        )
        .expect("FATAL: vault-sweep fee is not representable");
    let sweep_amount = (sweep_funding - SWEEP_RESERVE)
        .and_then(|remaining| remaining - transaction_fee)
        .expect("sweep threshold covers reserve and fee");
    let anchor = wallet
        .ironwood_anchor(tip)
        .expect("FATAL: Ironwood tree access failed")
        .expect("FATAL: wallet has no Ironwood anchor at its applied tip");
    let mut prepared = Vec::with_capacity(sweep_notes.len());
    for note in &sweep_notes {
        let path = wallet
            .ironwood_witness(note.note_commitment_tree_position(), tip)
            .expect("FATAL: Ironwood tree access failed")
            .expect("FATAL: sweep input has no witness");
        prepared.push((*note.note(), orchard::tree::MerklePath::from(path)));
    }

    let treasury_fvk = treasury_keys.orchard_fvk();
    let mut builder = Builder::new(
        network.clone(),
        target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    for (note, path) in prepared {
        builder
            .add_ironwood_spend::<zcash_primitives::transaction::fees::zip317::FeeError>(
                treasury_fvk.clone(),
                note,
                path,
            )
            .expect("FATAL: valid Treasury sweep input was rejected");
    }
    builder
        .add_transparent_output(&VAULT_ADDRESS, sweep_amount)
        .expect("FATAL: valid vault output was rejected");
    builder
        .add_ironwood_output::<zcash_primitives::transaction::fees::zip317::FeeError>(
            Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
            treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            SWEEP_RESERVE,
            zcash_protocol::memo::MemoBytes::empty(),
        )
        .expect("FATAL: valid Treasury reserve was rejected");
    let built = builder
        .build(
            &Default::default(),
            &[],
            &[orchard::keys::SpendAuthorizingKey::from(
                treasury_keys.orchard_spending_key(),
            )],
            rand::rngs::OsRng,
            spend_prover,
            output_prover,
            &StandardFeeRule::Zip317,
        )
        .expect("FATAL: Ironwood vault sweep proving or signing failed");
    let transaction = built.transaction().clone();
    let sent = SentTransaction::new(
        &transaction,
        time::OffsetDateTime::now_utc(),
        TargetHeight::from(target_height),
        TREASURY_ACCOUNT,
        &[],
        transaction_fee,
        &[],
    );
    wallet
        .store_transactions_to_be_sent(&[sent])
        .expect("FATAL: wallet rejected the Ironwood vault sweep");
    Some(transaction)
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

        let req = parse_request(&network, &padded(&format!("ZNS:claim:alice:{TEST_UA}"))).unwrap();
        assert_eq!(req.action, Action::Claim);
        assert_eq!(req.name.as_str(), "alice");
        assert_eq!(req.term, None);
        assert_eq!(req.otp, None);

        let req = parse_request(&network, &padded(&format!("ZNS:update:alice:{TEST_UA}"))).unwrap();
        assert_eq!(req.action, Action::Update);
        assert_eq!(req.name.as_str(), "alice");
        assert_eq!(req.term, None);
        assert_eq!(req.otp, None);

        let req =
            parse_request(&network, &padded(&format!("ZNS:release:alice:{TEST_UA}"))).unwrap();
        assert_eq!(req.action, Action::Release);
        assert_eq!(req.name.as_str(), "alice");
        assert_eq!(req.term, None);
        assert_eq!(req.otp, None);
    }

    #[test]
    fn claim_and_update_accept_a_canonical_term() {
        let network = MainNetwork;
        let term = Term::parse("31536000").unwrap();

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}:31536000")),
        )
        .unwrap();
        assert_eq!(req.action, Action::Claim);
        assert_eq!(req.term, Some(term));
        assert_eq!(req.otp, None);

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:31536000")),
        )
        .unwrap();
        assert_eq!(req.action, Action::Update);
        assert_eq!(req.term, Some(term));
        assert_eq!(req.otp, None);

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}:none")),
        )
        .unwrap();
        assert_eq!(req.term, None);
        assert_eq!(req.otp, None);
    }

    #[test]
    fn six_digit_update_field_is_a_term_not_an_otp() {
        let network = MainNetwork;
        let term = Term::parse("123456").unwrap();
        let req = parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:123456")),
        )
        .unwrap();
        assert_eq!(req.term, Some(term));
        assert_eq!(req.otp, None);
    }

    #[test]
    fn update_and_release_accept_a_respond_otp() {
        let network = MainNetwork;
        let term = Term::parse("31536000").unwrap();

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:none:004206")),
        )
        .unwrap();
        assert_eq!(req.action, Action::Update);
        assert_eq!(req.term, None);
        assert_eq!(req.otp, Some(*b"004206"));

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:31536000:004206")),
        )
        .unwrap();
        assert_eq!(req.action, Action::Update);
        assert_eq!(req.term, Some(term));
        assert_eq!(req.otp, Some(*b"004206"));

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:004206")),
        )
        .unwrap();
        assert_eq!(req.action, Action::Release);
        assert_eq!(req.term, None);
        assert_eq!(req.otp, Some(*b"004206"));

        let req = parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:none:123456")),
        )
        .unwrap();
        assert_eq!(req.term, None);
        assert_eq!(req.otp, Some(*b"123456"));
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
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}:31536000:more"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:31536000"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:none"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}:none:004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}::004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:none:004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:none:00420"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:00420a"))
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
