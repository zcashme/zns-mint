//! OTP challenge machinery for ZNS name transitions.
//!
//! The OTP queue is a single-use TTL cache: each entry binds a 6-digit
//! passcode to a specific (name, action, target UA) and expires after
//! 30 minutes of chain MTP. Entries are pushed when a relay transaction
//! is accepted for broadcast and burned on first successful verification
//! — one-shot, never reusable. Expired entries are pruned on each
//! verification scan.
//!
//! Also home to the OTP relay memo codec
//! (`ZNS:otp:<otp>:<name>:<verb>:<ua>`) and relay issuance
//! ([`issue_relay`]): an ordinary Treasury payment to the current
//! controller, built by upstream wallet assembly (input selection, fee
//! computation, anchors and witnesses, proving, signing, and
//! sent-transaction recording). After NU6.3, upstream routes the
//! controller UA's Orchard receiver to the Ironwood pool, so the
//! delivered note is an Ironwood note. The relay never spends the request
//! note — intake dedup is not a protocol concern: a user may purchase as
//! many challenges as they like; only the echoed one is burned.

use std::fmt;

use rand::Rng;
use subtle::ConstantTimeEq;
use time::Timestamp;
use zeroize::Zeroize;

use crate::mint::{Action, Name, UnifiedAddress};

/// OTP validity window (whitepaper §5.3: D_OTP). 30 minutes in seconds.
pub const D_OTP: i64 = 1800;

// ---------------------------------------------------------------------------
// OtpCode
// ---------------------------------------------------------------------------

/// A six-digit decimal one-time passcode for update/release authorization.
///
/// Stored as a `u32` in the range `0..=999_999`. The canonical relay form is
/// six ASCII decimal digits, including leading zeroes.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OtpCode(u32);

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpCode(<redacted>)")
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
    ///
    /// Returns `None` if the input is not exactly six ASCII digits.
    pub fn from_digits(digits: &[u8; 6]) -> Option<Self> {
        let mut value = 0u32;
        for &b in digits {
            if !b.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)? + (b - b'0') as u32;
        }
        Some(Self(value))
    }

    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 6] {
        self.digits()
    }

    /// Constructs a code from raw digits. Test-only: the mint's only
    /// production constructor is [`OtpCode::generate`].
    #[cfg(test)]
    pub fn for_test(digits: [u8; 6]) -> Self {
        Self::from_digits(&digits).expect("test digits are valid")
    }
}

// ---------------------------------------------------------------------------
// OtpRequest — one pending OTP bound to a specific transition
// ---------------------------------------------------------------------------

/// A pending OTP bound to a specific (name, action, target UA).
///
/// Pushed onto the [`OtpQueue`] after the relay transaction is accepted.
/// Burned on first successful verification — one-shot, never reusable.
/// Expires after `D_OTP` seconds of chain MTP.
pub struct OtpRequest {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    pub code: OtpCode,
    pub expires_at: Timestamp,
}

// ---------------------------------------------------------------------------
// OtpQueue — single-use TTL cache of pending OTPs
// ---------------------------------------------------------------------------

/// A bag of pending OTP requests. Push appends with no checks; every
/// accepted relay gets an entry. Verification scans for a match on
/// (name, action, ua, code) plus the expiry check, and removes the
/// first match — burning it permanently.
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

    /// Scans for an entry matching (name, action, ua) with an unexpired
    /// timestamp and a code that equals `provided` under constant-time
    /// comparison. Removes and returns `true` on first match — the OTP
    /// is burned. Failed verification leaves the entry intact.
    /// Expired entries are pruned on every scan.
    pub fn verify_and_burn(
        &mut self,
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
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

// ---------------------------------------------------------------------------
// OTP relay memo encoding
// ---------------------------------------------------------------------------

/// Returns the canonical verb string for an action in the OTP relay grammar.
///
/// Only `Update` and `Release` are valid relay actions — claims do not use OTPs.
fn verb_str(action: Action) -> Option<&'static str> {
    match action {
        Action::Update => Some("update"),
        Action::Release => Some("release"),
        Action::Claim => None,
    }
}

/// Whether the fixed-width OTP relay form fits in one Zcash memo.
pub fn otp_relay_memo_fits<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    name: &Name,
    action: Action,
    ua: &UnifiedAddress,
) -> bool {
    let Some(verb) = verb_str(action) else {
        return false;
    };
    8usize // "ZNS:otp:"
        .checked_add(6) // six-digit OTP
        .and_then(|l| l.checked_add(1 + name.as_str().len()))
        .and_then(|l| l.checked_add(1 + verb.len()))
        .and_then(|l| l.checked_add(1 + ua.encode(network).len()))
        .is_some_and(|l| l <= 512)
}

/// Encodes an OTP relay memo: `ZNS:otp:<otp>:<name>:<verb>:<ua>`, zero-padded
/// to 512 bytes.
///
/// This memo is sent from the Treasury to the current controller's address so
/// only they can decrypt it and forward it back. Returns `None` if the action
/// is `Claim` (claims don't use OTPs) or if the encoded text exceeds 512 bytes.
pub fn encode_otp_relay_memo<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    name: &Name,
    action: Action,
    ua: &UnifiedAddress,
    otp: &OtpCode,
) -> Option<[u8; 512]> {
    let verb = verb_str(action)?;
    if !otp_relay_memo_fits(network, name, action, ua) {
        return None;
    }

    let ua_field = ua.encode(network);
    let otp_digits = otp.digits();
    let mut memo = [0u8; 512];
    let mut offset = 0usize;
    for field in [
        b"ZNS:otp:".as_slice(),
        otp_digits.as_slice(),
        b":".as_slice(),
        name.as_str().as_bytes(),
        b":".as_slice(),
        verb.as_bytes(),
        b":".as_slice(),
        ua_field.as_bytes(),
    ] {
        let end = offset + field.len();
        memo[offset..end].copy_from_slice(field);
        offset = end;
    }
    Some(memo)
}

/// Parses a 512-byte OTP relay memo and returns its fields if the grammar
/// matches `ZNS:otp:<otp>:<name>:<verb>:<ua>`. Returns `None` otherwise.
pub fn decode_otp_relay_memo(memo: &[u8; 512]) -> Option<(Name, Action, String, [u8; 6])> {
    let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
    if memo[end..].iter().any(|&b| b != 0) {
        return None;
    }
    let text = std::str::from_utf8(&memo[..end]).ok()?;

    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 || parts[0] != "ZNS" || parts[1] != "otp" {
        return None;
    }

    let digits = parts[2].as_bytes();
    if digits.len() != 6 || !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut otp = [0u8; 6];
    otp.copy_from_slice(digits);

    let name = Name::parse(parts[3])?;
    let action = match parts[4] {
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    let ua = parts[5].to_string();
    if ua.is_empty() {
        return None;
    }

    Some((name, action, ua, otp))
}

// ---------------------------------------------------------------------------
// OTP relay issuance
// ---------------------------------------------------------------------------

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
    controller_ua: &UnifiedAddress,
    target_height: zcash_protocol::consensus::BlockHeight,
    memo: [u8; 512],
) -> Result<(zcash_primitives::transaction::TxId, String), crate::mint::AssemblyError> {
    use zcash_client_backend::data_api::wallet::input_selection::{
        GreedyInputSelector, SpendPolicy,
    };
    use zcash_client_backend::data_api::wallet::{
        create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
    };
    use zcash_client_backend::data_api::WalletRead as _;
    use zcash_client_backend::fees::{
        standard::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule,
    };
    use zcash_client_backend::wallet::OvkPolicy;
    use zcash_protocol::ShieldedPool;

    // The controller's compensation funds the echo: the ZIP-317 fee of its
    // bundle shape (one Ironwood spend plus one output, padded to two
    // actions).
    let amount = {
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
            .map_err(|e| crate::mint::AssemblyError::UpstreamTransfer(format!("{e:?}")))?
    };

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
    .map_err(|e| crate::mint::AssemblyError::UpstreamTransfer(format!("{e:?}")))?;
    let request = zip321::TransactionRequest::new(vec![payment])
        .map_err(|e| crate::mint::AssemblyError::UpstreamTransfer(format!("{e:?}")))?;

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
    )
    .map_err(
        // The commitment-tree error type is free in `propose_transfer`'s
        // signature; the wallet's tree error is `Infallible`.
        |e: zcash_client_backend::data_api::wallet::ProposeTransferErrT<
            crate::wallet::Wallet,
            std::convert::Infallible,
            GreedyInputSelector<crate::wallet::Wallet>,
            SingleOutputChangeStrategy<crate::wallet::Wallet>,
        >| crate::mint::AssemblyError::UpstreamTransfer(format!("{e:?}")),
    )?;

    // Only the Treasury signs; the relay carries no Registry authority.
    // The Sapling prover is never invoked: the Ironwood-only spend policy
    // means `sapling_builder` is `None` in the upstream `Builder::build`.
    let (spend_prover, output_prover) = crate::mint::signer::sapling_provers();
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
    )
    .map_err(
        // `InputsErrT` and `ChangeErrT` are free in the signature; project
        // them from the concrete selector and change strategy.
        |e: zcash_client_backend::data_api::wallet::CreateErrT<
            crate::wallet::Wallet,
            <GreedyInputSelector<crate::wallet::Wallet> as zcash_client_backend::data_api::wallet::input_selection::InputSelector>::Error,
            StandardFeeRule,
            <SingleOutputChangeStrategy<crate::wallet::Wallet> as zcash_client_backend::fees::ChangeStrategy>::Error,
            zcash_client_backend::wallet::NoteId,
        >| crate::mint::AssemblyError::UpstreamTransfer(format!("{e:?}")),
    )?;

    let txid = *txids.first();
    let tx = wallet
        .get_transaction(txid)
        .ok()
        .flatten()
        .ok_or(crate::mint::AssemblyError::NoteNotFound)?;
    let hex = crate::mint::signer::serialize_tx(&tx)?;
    Ok((txid, hex))
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
    target_height: zcash_protocol::consensus::BlockHeight,
    mtp: Timestamp,
    wallet: &mut crate::wallet::Wallet,
    treasury_keys: &crate::key::TreasuryKeys,
) -> Option<crate::mint::RequestOutcome> {
    use crate::mint::{RequestOutcome, SubmissionKind};
    use time::Duration;

    if action == Action::Claim || controller_ua.orchard().is_none() {
        return None;
    }

    let otp = OtpCode::generate();
    let memo = encode_otp_relay_memo(network, name, action, requested_ua, &otp)?;

    let result = build_relay_payment(
        network,
        wallet,
        treasury_keys,
        controller_ua,
        target_height,
        memo,
    )
    .map(|(txid, hex)| (SubmissionKind::OtpRelay, txid, hex, Vec::new()));

    Some(RequestOutcome {
        result,
        relay_otp: Some(OtpRequest {
            name: name.clone(),
            action,
            ua: requested_ua.clone(),
            code: otp,
            expires_at: mtp + Duration::seconds(D_OTP),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;
    use zcash_protocol::consensus::MAIN_NETWORK;

    fn test_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(
            &MAIN_NETWORK,
            "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        ) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    fn test_name() -> Name {
        Name::parse("alice").unwrap()
    }

    #[test]
    fn round_trip_otp_relay_memo() {
        let name = test_name();
        let ua = test_ua();
        let otp = OtpCode::for_test(*b"004206");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp)
            .expect("memo fits");

        let (decoded_name, decoded_action, decoded_ua, decoded_otp) =
            decode_otp_relay_memo(&memo).expect("memo decodes");

        assert_eq!(decoded_name, name);
        assert_eq!(decoded_action, Action::Update);
        assert_eq!(decoded_ua, ua.encode(&MAIN_NETWORK));
        assert_eq!(decoded_otp, *b"004206");
    }

    #[test]
    fn otp_relay_memo_format_is_otp_name_verb_ua() {
        let name = test_name();
        let ua = test_ua();
        let otp = OtpCode::for_test(*b"004206");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp)
            .expect("memo fits");

        let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
        let text = std::str::from_utf8(&memo[..end]).unwrap();
        assert!(text.starts_with("ZNS:otp:004206:alice:update:"));
        assert!(text.ends_with(&ua.encode(&MAIN_NETWORK)));
    }

    #[test]
    fn otp_relay_rejects_the_legacy_otp_last_format() {
        let ua = test_ua();
        let legacy = format!("ZNS:otp:alice:update:{}:004206", ua.encode(&MAIN_NETWORK));
        let mut memo = [0u8; 512];
        memo[..legacy.len()].copy_from_slice(legacy.as_bytes());

        assert!(decode_otp_relay_memo(&memo).is_none());
    }

    #[test]
    fn otp_relay_memo_is_not_a_request_memo() {
        let name = test_name();
        let ua = test_ua();
        let otp = OtpCode::for_test(*b"123456");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp)
            .expect("memo fits");
        let result = crate::mint::treasury::parse_request(&MAIN_NETWORK, &memo);
        assert!(
            result.is_none(),
            "relay memo must not parse as a request memo"
        );
    }

    #[test]
    fn otp_relay_rejects_non_zero_bytes_after_nul_padding() {
        let name = test_name();
        let ua = test_ua();
        let otp = OtpCode::for_test(*b"004206");

        let mut memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp)
            .expect("memo fits");

        // Inject non-zero garbage after the NUL padding.
        // `encode_otp_relay_memo` zero-pads, so the first NUL is right after
        // the content.  Find it and write garbage further out.
        let first_nul = memo.iter().position(|&b| b == 0).unwrap();
        memo[first_nul + 10] = 0x42;

        // The post-NUL check must reject this.
        assert!(decode_otp_relay_memo(&memo).is_none());
    }

    #[test]
    fn generate_otp_is_six_digits() {
        let otp = OtpCode::generate();
        let digits = otp.digits();
        assert_eq!(digits.len(), 6);
        assert!(digits.iter().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn otp_queue_verify_and_burn() {
        let name = test_name();
        let ua = test_ua();
        // code is set in the OtpRequest below
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Correct code burns the entry
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
        // Second attempt fails — entry is gone
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_wrong_code_does_not_burn() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Wrong code — entry stays
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"999999", now));
        // Correct code still works
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_wrong_action_does_not_burn() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Wrong action — entry stays
        assert!(!queue.verify_and_burn(&name, Action::Release, &ua, b"004206", now));
        // Correct action still works
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_expired_does_not_burn() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now; // already expired

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: expires,
        });

        // Expired — never matches, and the entry is pruned by the scan.
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"004206", now));
    }

    #[test]
    fn otp_queue_multiple_entries_per_name() {
        let name = test_name();
        let ua = test_ua();
        let now = Timestamp::now();
        let expires = now + Duration::seconds(D_OTP);

        let mut queue = OtpQueue::new();
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"111111"),
            expires_at: expires,
        });
        queue.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"222222"),
            expires_at: expires,
        });

        // First code burns one entry, the other stays
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"111111", now));
        assert!(queue.verify_and_burn(&name, Action::Update, &ua, b"222222", now));
        assert!(!queue.verify_and_burn(&name, Action::Update, &ua, b"111111", now));
    }
}
