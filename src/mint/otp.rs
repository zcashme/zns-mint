//! OTP authentication for ZNS locked-name transitions.
//!
use rand::Rng;
use subtle::ConstantTimeEq;
use time::Timestamp;
use zeroize::Zeroize;

use crate::mint::{Action, Challenge, Name, NameCommitment, UnifiedAddress};
use zcash_client_backend::data_api::wallet::{
    input_selection::GreedyInputSelector, ProposeTransferErrT,
};
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;

/// OTP validity window (30 minutes in seconds; §5.3: D_OTP)
pub const D_OTP: i64 = 1800;

/// A six-digit one-time passcode for update/release authorization.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct OtpCode(u32);

impl std::fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OtpCode(REDACTED)")
    }
}

impl OtpCode {
    /// Generates a new uniformly random six-digit decimal OTP.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen_range(0..1_000_000))
    }

    /// Returns the six ASCII decimal digits, including leading zeroes.
    pub fn digits(&self) -> [u8; 6] {
        let mut digits = [0u8; 6];
        let mut n = self.0;
        for i in (0..6).rev() {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        digits
    }

    /// Parses six ASCII decimal digits into an OTP.
    pub fn from_digits(digits: &[u8; 6]) -> Option<Self> {
        let s = std::str::from_utf8(digits).ok()?;
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<u32>().ok().map(Self)
    }

    /// Constructs a code from raw digits. Test-only: the mint's only
    /// production constructor is [`OtpCode::generate`].
    #[cfg(test)]
    pub fn for_test(digits: [u8; 6]) -> Self {
        Self::from_digits(&digits).expect("test digits are valid")
    }

    /// Reveals the digits. Test-only: registry tests push queue entries for
    /// codes the relay just generated, and compare them at verification.
    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 6] {
        self.digits()
    }
}

/// A pending OTP bound to one exact live Name Note and the requested action.
#[derive(Clone)]
pub struct OtpRequest {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    pub tip_rcm: NameCommitment,
    pub code: OtpCode,
    pub expires_at: Timestamp,
}

/// A time ordered list of pending OTP requests.
#[derive(Clone)]
pub struct OtpQueue(Vec<OtpRequest>);

impl Default for OtpQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpQueue {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a pending OTP request. No checks — every accepted relay
    /// gets an entry. Multiple entries per name are allowed.
    pub fn push(&mut self, req: OtpRequest) {
        self.0.push(req);
    }

    /// Whether the exact live Name Note already has an unexpired challenge
    /// for this action and target. Expired entries are discarded here so a
    /// later block may issue a fresh challenge.
    pub fn has_live(
        &mut self,
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
        tip_rcm: NameCommitment,
        mtp: Timestamp,
    ) -> bool {
        self.0.retain(|request| mtp < request.expires_at);
        self.0.iter().any(|request| {
            request.name == *name
                && request.action == action
                && request.ua == *ua
                && request.tip_rcm == tip_rcm
        })
    }

    /// Expired entries are pruned on every scan.
    pub fn verify_and_burn(
        &mut self,
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
        tip_rcm: NameCommitment,
        provided: &[u8; 6],
        mtp: Timestamp,
    ) -> bool {
        // Expire first: entries past their TTL never match and are dropped.
        self.0.retain(|req| mtp < req.expires_at);
        let Some(provided_code) = OtpCode::from_digits(provided) else {
            return false;
        };
        for i in 0..self.0.len() {
            let req = &self.0[i];
            if req.name == *name
                && req.action == action
                && &req.ua == ua
                && req.tip_rcm == tip_rcm
                && mtp < req.expires_at
                && bool::from(req.code.0.ct_eq(&provided_code.0))
            {
                self.0.remove(i);
                return true;
            }
        }
        false
    }
}

/// Value delivered by a relay so its controller can pay for the echo.
pub fn required_relay_value<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    target_height: zcash_protocol::consensus::BlockHeight,
) -> zcash_protocol::value::Zatoshis {
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    FeeRule::standard()
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            2,
        )
        .expect("ZIP-317 fee for two Ironwood actions is representable")
}

/// Minimum value of the echoed Treasury note.
pub fn required_echo_value<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    target_height: zcash_protocol::consensus::BlockHeight,
) -> zcash_protocol::value::Zatoshis {
    required_relay_value(network, target_height)
}

// ---------------------------------------------------------------------------
// OTP relay issuance (THIS FUNCTION COULD TAKE SOME SERIOUS WORK)
// ---------------------------------------------------------------------------

/// The outcome of issuing an OTP relay: the relay payment's result, plus the
/// pending challenge to push onto the queue once the relay is accepted for
/// broadcast.
pub struct RequestOutcome {
    pub result: Result<
        zcash_primitives::transaction::TxId,
        zcash_client_backend::data_api::wallet::ProposeTransferErrT<
            crate::wallet::Wallet,
            std::convert::Infallible,
            zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector<
                crate::wallet::Wallet,
            >,
            zcash_client_backend::fees::standard::SingleOutputChangeStrategy<crate::wallet::Wallet>,
        >,
    >,
    pub relay_otp: Option<OtpRequest>,
}

/// Builds, proves, signs, and records the OTP relay payment, returning its
/// txid and serialized hex for broadcast.
///
/// The relay is an ordinary outgoing Treasury payment to the controller's
/// Unified Address, carrying the OTP relay memo and one fee unit of
/// compensation. Upstream proposal and transaction construction own input
/// selection, fee computation, anchors and witnesses, proving, signing, and
/// sent-transaction recording — the stored transaction is what makes the
/// selected Treasury notes unavailable to later work before broadcast.
///
/// The spend policy and change strategy are Ironwood-only, so the constructed
/// transaction cannot carry Sapling material even though it is built by generic
/// upstream code and passed a real Sapling prover (which is never invoked).
fn build_relay_payment<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    wallet: &mut crate::wallet::Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    controller_ua: &UnifiedAddress,
    target_height: zcash_protocol::consensus::BlockHeight,
    memo: [u8; 512],
) -> Result<
    zcash_primitives::transaction::TxId,
    ProposeTransferErrT<
        crate::wallet::Wallet,
        std::convert::Infallible,
        GreedyInputSelector<crate::wallet::Wallet>,
        SingleOutputChangeStrategy<crate::wallet::Wallet>,
    >,
> {
    use zcash_client_backend::data_api::wallet::input_selection::{
        GreedyInputSelector, SpendPolicy,
    };
    use zcash_client_backend::data_api::wallet::{
        create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
    };
    use zcash_client_backend::fees::{
        standard::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule,
    };
    use zcash_client_backend::wallet::OvkPolicy;
    use zcash_protocol::ShieldedPool;

    // The controller's compensation funds the echo: the ZIP-317 fee of its
    // bundle shape (one Ironwood spend plus one output, padded to two
    // actions).
    let amount = required_relay_value(network, target_height);

    let recipient =
        zcash_keys::address::Address::Unified(controller_ua.clone()).to_zcash_address(network);
    let payment = zip321::Payment::new(
        recipient,
        Some(amount),
        Some(
            zcash_protocol::memo::MemoBytes::from_bytes(&memo[..])
                .expect("a zero-padded 512-byte memo is always a valid MemoBytes"),
        ),
        None,
        None,
        Vec::new(),
    )
    .expect("memo to a guarded Orchard UA with a nonzero fee cannot fail");
    let request =
        zip321::TransactionRequest::new(vec![payment]).expect("single-payment request cannot fail");

    let input_selector = GreedyInputSelector::new();
    let change_strategy = SingleOutputChangeStrategy::<crate::wallet::Wallet>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );
    let proposal = propose_transfer(
        wallet,
        network,
        crate::mint::TREASURY_ACCOUNT,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::new_symmetrical(std::num::NonZeroU32::MIN, false),
        &SpendPolicy::shielded_pools([ShieldedPool::Ironwood]),
        None,
        None, // transaction version implied by the target height: V6 / Ironwood
    )?;

    // Only the Treasury signs; the relay carries no Registry authority.
    // The Sapling provers are never invoked: the Ironwood-only spend policy
    // means `sapling_builder` is `None` in the upstream `Builder::build`.
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

    let txid = *txids.first();
    // Serialization and broadcast happen at the submission boundary
    // (`zcash::submit_transaction`); upstream returns txids only and stores
    // the built transaction in the wallet for later retrieval.
    Ok(txid)
}

/// Validates an OTP relay request (update or release without OTP) and issues
/// the challenge. Returns `None` if the request is invalid — a claim (claims
/// never relay), or a controller UA with no Orchard-family receiver to
/// deliver Ironwood value to.
///
/// The relay spends whatever confirmed Treasury Ironwood notes upstream
/// selects; the request note itself is not consumed. That is deliberate:
/// each accepted relay is a fresh, independently valid challenge, and any
/// re-delivery simply costs the Treasury float until housekeeping consumes
/// the request note — only the echoed challenge is burned from the queue.
#[allow(clippy::too_many_arguments)]
pub fn issue_relay<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    name: &Name,
    action: Action,
    requested_ua: &UnifiedAddress,
    controller_ua: &UnifiedAddress,
    tip_rcm: NameCommitment,
    target_height: zcash_protocol::consensus::BlockHeight,
    mtp: Timestamp,
    wallet: &mut crate::wallet::Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
) -> Option<RequestOutcome> {
    use time::Duration;

    if action == Action::Claim
        || controller_ua.orchard().is_none()
        || (action == Action::Release && requested_ua != controller_ua)
    {
        return None;
    }

    let otp = OtpCode::generate();
    let challenge = Challenge {
        code: otp.clone(),
        name: name.clone(),
        action,
        ua: requested_ua.clone(),
    };
    let memo = challenge.encode(network)?;

    let result = build_relay_payment(
        network,
        wallet,
        treasury_keys,
        spend_prover,
        output_prover,
        controller_ua,
        target_height,
        memo,
    );

    Some(RequestOutcome {
        result,
        relay_otp: Some(OtpRequest {
            name: name.clone(),
            action,
            ua: requested_ua.clone(),
            tip_rcm,
            code: otp,
            expires_at: mtp + Duration::seconds(D_OTP),
        }),
    })
}
