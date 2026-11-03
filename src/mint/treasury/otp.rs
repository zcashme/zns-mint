//! OTP auth for locked names.
//!
use rand::RngExt;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::mint::{Name, OtpMemo, Request};

/// Thirty minutes; §5.3: D_OTP.
pub const D_OTP: i64 = 1800;

/// Wrong OTP responses tolerated per challenge (§5: the deployment
/// fixes the maximum number of verification attempts).
pub const MAX_ATTEMPTS: u32 = 6;

/// A six-digit one-time passcode.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OtpCode(u32);

impl std::fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OtpCode(REDACTED)")
    }
}

impl OtpCode {
    /// Uniform random six digits.
    pub fn generate() -> Self {
        Self(rand::rand_core::UnwrapErr(rand::rngs::SysRng).random_range(0..1_000_000))
    }

    /// The buy code for this transaction and name. The same inputs always
    /// yield the same code, so a rescan matches the payment already sent.
    pub fn buy(key: &[u8], txid: &[u8; 32], name: &[u8]) -> Self {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"ZNS:buyotp");
        mac.update(txid);
        mac.update(name);
        Self::from_mac(mac)
    }

    /// The list challenge for this request. The same inputs yield the
    /// same code, so a rescan matches the controller's reply.
    pub fn list(key: &[u8], txid: &[u8; 32], name: &[u8], price: u64, pay_to: &[u8]) -> Self {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"ZNS:listotp");
        mac.update(txid);
        mac.update(name);
        mac.update(&price.to_be_bytes());
        mac.update(pay_to);
        Self::from_mac(mac)
    }

    /// The delist challenge for this request. The same inputs yield the
    /// same code, so a rescan matches the controller's reply.
    pub fn delist(key: &[u8], txid: &[u8; 32], name: &[u8]) -> Self {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"ZNS:delistotp");
        mac.update(txid);
        mac.update(name);
        Self::from_mac(mac)
    }

    fn from_mac(mac: hmac::Hmac<sha2::Sha256>) -> Self {
        use hmac::Mac;
        let digest = mac.finalize().into_bytes();
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        Self(n % 1_000_000)
    }

    /// The six ASCII digits.
    pub fn digits(&self) -> [u8; 6] {
        let mut digits = [0u8; 6];
        let mut n = self.0;
        for i in (0..6).rev() {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        digits
    }

    /// Parses six ASCII digits.
    pub fn from_digits(digits: &[u8; 6]) -> Option<Self> {
        let s = std::str::from_utf8(digits).ok()?;
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<u32>().ok().map(Self)
    }

    /// From raw digits; test-only.
    #[cfg(test)]
    pub fn for_test(digits: [u8; 6]) -> Self {
        Self::from_digits(&digits).expect("test digits are valid")
    }
}

/// An issued, pending challenge: the request it answers, and the
/// code that answers it.
#[derive(Clone)]
pub struct OtpChallenge {
    pub request: Request,
    pub code: OtpCode,
    pub expires_at: Timestamp,
    pub attempts: u32,
}

impl OtpChallenge {
    /// Checks the code and counts a failure if it is wrong.
    fn attempt(&mut self, code: &OtpCode) -> bool {
        let correct = bool::from(self.code.0.ct_eq(&code.0));
        if !correct {
            self.attempts += 1;
        }
        correct
    }

    /// The controller-facing projection. A list also carries the t1 and the price.
    pub fn memo(&self) -> OtpMemo {
        let listing = match &self.request {
            Request::List { pay_to, price, .. } => Some((*pay_to, *price)),
            _ => None,
        };
        OtpMemo {
            code: self.code.clone(),
            name: self.request.name().clone(),
            action: self.request.action(),
            ua: self.request.ua().clone(),
            listing,
        }
    }
}

/// Lifecycle state for a pending challenge entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChallengeState {
    /// Seen, its challenge memo not yet accepted by the node.
    Requested,
    /// The node accepted the challenge memo; an OTP response may arrive.
    Relayed,
}

/// A request opened from the mempool. The echo waits until the tip
/// pass accepts the mined request. A dead request keeps the entry, and
/// that challenge gets no second mempool relay.
#[derive(Clone)]
struct ZeroConf {
    txid: TxId,
    confirmed_at: Option<BlockHeight>,
    dead: bool,
}

/// What `complete` did with an echo.
#[derive(Clone)]
pub enum ChallengeAnswer {
    /// The code matched a relayed challenge whose request is mined.
    /// `at` is the block that owns the name note.
    Accepted {
        challenge: Box<OtpChallenge>,
        at: BlockHeight,
    },
    /// The echo names a relayed challenge whose request is still unmined.
    Held,
}

#[derive(Clone)]
struct Queued {
    challenge: OtpChallenge,
    state: ChallengeState,
    zero_conf: Option<ZeroConf>,
}

impl Queued {
    fn dead(&self) -> bool {
        self.zero_conf
            .as_ref()
            .is_some_and(|zero_conf| zero_conf.dead)
    }

    /// A block-path challenge is mined. A mempool one is mined once the
    /// tip pass has accepted its request.
    fn mined(&self) -> bool {
        self.zero_conf
            .as_ref()
            .is_none_or(|zero_conf| zero_conf.confirmed_at.is_some())
    }
}

/// Issued challenges, in order. Every challenge was issued against
/// its name's current record: the run loop drops a name's challenges
/// when it admits a transition for that name.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<Queued>,
}

impl Default for OtpQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpQueue {
    pub fn new() -> Self {
        Self {
            challenges: Vec::new(),
        }
    }

    /// Issues a challenge for `request` unless one is live. Its code is
    /// unique among the challenges a response could also name.
    pub fn admit(&mut self, request: Request, mtp: Timestamp) {
        self.push(request, mtp, None);
    }

    /// Opens a mempool challenge for `request`, bound to `txid`. A live
    /// challenge, or one already relayed from the mempool, is left as it is.
    pub fn admit_unmined(&mut self, request: Request, txid: TxId, mtp: Timestamp) -> bool {
        if self.mempool_blocked(&request) {
            return false;
        }
        self.push(
            request,
            mtp,
            Some(ZeroConf {
                txid,
                confirmed_at: None,
                dead: false,
            }),
        );
        true
    }

    /// A mempool relay must wait: a challenge for `request` is live, or
    /// this challenge was already relayed from the mempool.
    pub fn mempool_blocked(&self, request: &Request) -> bool {
        self.live(request) || self.zero_conf_used(request)
    }

    /// This challenge was already relayed from the mempool, including one
    /// whose request has since died.
    fn zero_conf_used(&self, request: &Request) -> bool {
        self.challenges
            .iter()
            .any(|queued| queued.challenge.request == *request && queued.zero_conf.is_some())
    }

    /// The tip pass accepted the mined request behind this mempool challenge.
    pub fn confirm_mined(&mut self, txid: TxId, height: BlockHeight) {
        for queued in &mut self.challenges {
            let Some(zero_conf) = queued.zero_conf.as_mut() else {
                continue;
            };
            if zero_conf.txid == txid && !zero_conf.dead {
                zero_conf.confirmed_at = Some(height);
            }
        }
    }

    /// The tip pass rejected `txid`. A sent mempool challenge stays, marked
    /// dead. One that was never sent is dropped.
    pub fn refuse_unmined(&mut self, txid: TxId) {
        self.invalidate_txid(txid);
    }

    /// `txid` left the mempool. A sent challenge stays marked dead, and
    /// the return is true once, for the lost-relay counter. An unsent
    /// challenge is dropped and the return is false.
    pub fn invalidate(&mut self, txid: TxId) -> bool {
        self.invalidate_txid(txid)
    }

    fn invalidate_txid(&mut self, txid: TxId) -> bool {
        let Some(index) = self.challenges.iter().position(|queued| {
            queued
                .zero_conf
                .as_ref()
                .is_some_and(|zero_conf| zero_conf.txid == txid && !zero_conf.dead)
        }) else {
            return false;
        };
        if self.challenges[index].state == ChallengeState::Relayed {
            if let Some(zero_conf) = self.challenges[index].zero_conf.as_mut() {
                zero_conf.dead = true;
            }
            true
        } else {
            self.challenges.remove(index);
            false
        }
    }

    fn live(&self, request: &Request) -> bool {
        self.challenges
            .iter()
            .any(|queued| queued.challenge.request == *request && !queued.dead())
    }

    fn push(&mut self, request: Request, mtp: Timestamp, zero_conf: Option<ZeroConf>) {
        if zero_conf.is_none() && self.live(&request) {
            return;
        }
        let code = loop {
            let code = OtpCode::generate();
            if !self.challenges.iter().any(|queued| {
                queued.challenge.request.name() == request.name()
                    && queued.challenge.request.action() == request.action()
                    && queued.challenge.request.ua() == request.ua()
                    && queued.challenge.code == code
            }) {
                break code;
            }
        };
        self.challenges.push(Queued {
            challenge: OtpChallenge {
                request,
                code,
                expires_at: mtp + Duration::seconds(D_OTP),
                attempts: 0,
            },
            state: ChallengeState::Requested,
            zero_conf,
        });
    }

    /// The node accepted `relayed`'s memo.
    pub fn challenge_issued(&mut self, relayed: &OtpChallenge) {
        for queued in &mut self.challenges {
            if queued.challenge.request == relayed.request && !queued.dead() {
                queued.state = ChallengeState::Relayed;
            }
        }
    }

    /// Challenges not yet relayed.
    pub fn requested(&self) -> Vec<OtpChallenge> {
        self.challenges
            .iter()
            .filter(|queued| queued.state == ChallengeState::Requested && !queued.dead())
            .map(|queued| queued.challenge.clone())
            .collect()
    }

    /// Drops every challenge whose window closed by `mtp`.
    pub fn expire(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|queued| mtp < queued.challenge.expires_at);
    }

    /// Drops every challenge for `name`, once a transition is admitted.
    pub fn drop_challenges(&mut self, name: &Name) {
        self.challenges
            .retain(|queued| queued.challenge.request.name() != name);
    }

    /// The right code removes and returns its mined challenge. A code
    /// that names an unmined mempool challenge is held, and counts no
    /// attempt. A wrong code counts against every mined challenge the
    /// response names. A dead request's echo counts nothing.
    pub fn complete(
        &mut self,
        response: &OtpMemo,
        echo_at: BlockHeight,
    ) -> Option<ChallengeAnswer> {
        let names = |queued: &Queued| {
            queued.challenge.request.name() == &response.name
                && queued.challenge.request.action() == response.action
                && queued.challenge.request.ua() == &response.ua
        };
        let answerable = |queued: &Queued| {
            queued.state == ChallengeState::Relayed && !queued.dead() && queued.mined()
        };
        let waiting = |queued: &Queued| {
            queued.state == ChallengeState::Relayed && !queued.dead() && !queued.mined()
        };
        let right = self.challenges.iter().position(|queued| {
            answerable(queued)
                && names(queued)
                && bool::from(queued.challenge.code.0.ct_eq(&response.code.0))
        });
        if let Some(index) = right {
            let mut queued = self.challenges.remove(index);
            let at = queued
                .zero_conf
                .as_ref()
                .and_then(|zero_conf| zero_conf.confirmed_at)
                .map(|mined| echo_at.max(mined))
                .unwrap_or(echo_at);
            return queued
                .challenge
                .attempt(&response.code)
                .then_some(ChallengeAnswer::Accepted {
                    challenge: Box::new(queued.challenge),
                    at,
                });
        }
        if self
            .challenges
            .iter()
            .any(|queued| waiting(queued) && names(queued))
        {
            return Some(ChallengeAnswer::Held);
        }
        self.challenges.retain_mut(|queued| {
            if !answerable(queued) || !names(queued) {
                return true;
            }
            queued.challenge.attempt(&response.code) || queued.challenge.attempts < MAX_ATTEMPTS
        });
        None
    }

    /// The name of every challenge still awaiting relay, borrowed.
    pub fn unrelayed(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|queued| queued.state == ChallengeState::Requested && !queued.dead())
            .map(|queued| queued.challenge.request.name())
    }

    /// The name of every relayed challenge, awaiting its response.
    pub fn relayed(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|queued| queued.state == ChallengeState::Relayed && !queued.dead())
            .map(|queued| queued.challenge.request.name())
    }
}

/// The one mempool relay for this transaction: the first update or
/// release `ready` accepts. A transparent spend relays nothing. Claims
/// are not challenged.
pub fn zero_conf_candidate<'a>(
    shielded_only: bool,
    requests: impl IntoIterator<Item = &'a Request>,
    ready: impl Fn(&Request) -> bool,
) -> Option<&'a Request> {
    if !shielded_only {
        return None;
    }
    requests.into_iter().find(|request| {
        matches!(request, Request::Update { .. } | Request::Release { .. }) && ready(request)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Term, UnifiedAddress};

    fn test_name(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    fn mainnet_ua() -> UnifiedAddress {
        let s = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";
        match zcash_keys::address::Address::decode(&zcash_protocol::consensus::MAIN_NETWORK, s) {
            Some(zcash_keys::address::Address::Unified(u)) => *u,
            _ => panic!("test UA"),
        }
    }

    fn t0() -> Timestamp {
        Timestamp::from_seconds(1_700_000_000).unwrap()
    }

    fn update(name: &str) -> Request {
        Request::Update {
            name: test_name(name),
            ua: mainnet_ua(),
            term: None,
        }
    }

    fn release(name: &str) -> Request {
        Request::Release {
            name: test_name(name),
            ua: mainnet_ua(),
        }
    }

    fn height() -> BlockHeight {
        BlockHeight::from_u32(1)
    }

    fn txid(byte: u8) -> TxId {
        TxId::from_bytes([byte; 32])
    }

    /// Admits `request` at `t0`, its code fixed to `code`.
    fn admit(q: &mut OtpQueue, request: Request, code: [u8; 6]) -> OtpChallenge {
        q.admit(request.clone(), t0());
        let queued = q
            .challenges
            .iter_mut()
            .find(|queued| queued.challenge.request == request)
            .unwrap();
        queued.challenge.code = OtpCode::for_test(code);
        queued.challenge.clone()
    }

    fn accepted(q: &mut OtpQueue, response: &OtpMemo) -> Option<OtpChallenge> {
        match q.complete(response, height()) {
            Some(ChallengeAnswer::Accepted { challenge, .. }) => Some(*challenge),
            _ => None,
        }
    }

    /// The controller's response to `challenge`, with `code`.
    fn response_for(challenge: &OtpChallenge, code: [u8; 6]) -> OtpMemo {
        OtpMemo {
            code: OtpCode::for_test(code),
            ..challenge.memo()
        }
    }

    /// The memo is the request less its term, with the code; the
    /// challenge expires `D_OTP` after admission.
    #[test]
    fn a_challenge_memo_and_expiry() {
        let mut q = OtpQueue::new();
        q.admit(update("alice"), t0());
        let pending = q.requested().remove(0);
        let memo = pending.memo();
        assert_eq!(memo.code, pending.code);
        assert_eq!(&memo.name, pending.request.name());
        assert_eq!(memo.action, pending.request.action());
        assert_eq!(&memo.ua, pending.request.ua());
        assert_eq!(pending.expires_at, t0() + Duration::seconds(D_OTP));
    }

    /// Admitting a transition for a name drops every challenge for it:
    /// a code issued against the old record answers nothing after.
    /// Other names stand.
    #[test]
    fn drop_challenges_retires_every_code_for_the_name() {
        let mut q = OtpQueue::new();
        let alice_update = admit(&mut q, update("alice"), *b"111111");
        let alice_release = admit(&mut q, release("alice"), *b"222222");
        let bob = admit(&mut q, update("bob"), *b"333333");
        for pending in [&alice_update, &alice_release, &bob] {
            q.challenge_issued(pending);
        }

        q.drop_challenges(&test_name("alice"));

        assert!(accepted(&mut q, &response_for(&alice_update, *b"111111")).is_none());
        assert!(accepted(&mut q, &response_for(&alice_release, *b"222222")).is_none());
        assert_eq!(q.relayed().collect::<Vec<_>>(), [bob.request.name()]);
        assert!(accepted(&mut q, &response_for(&bob, *b"333333")).is_some());
    }

    /// A challenge names its name as unrelayed until it is relayed, and
    /// as relayed after. Pruning clears both.
    #[test]
    fn a_relayed_challenge_names_its_name_until_expired() {
        let mut q = OtpQueue::new();
        let sent = admit(&mut q, update("alice"), *b"111111");
        let unsent = admit(&mut q, release("alice"), *b"222222");
        assert_eq!(q.relayed().count(), 0);
        assert_eq!(q.unrelayed().count(), 2);
        q.challenge_issued(&sent);
        assert_eq!(q.relayed().collect::<Vec<_>>(), [sent.request.name()]);
        assert_eq!(q.unrelayed().collect::<Vec<_>>(), [unsent.request.name()]);
        q.expire(sent.expires_at);
        assert_eq!(q.relayed().count(), 0);
        assert_eq!(q.unrelayed().count(), 0);
    }

    /// The right code answers once; the identical response after it
    /// answers nothing.
    #[test]
    fn respond_burns_once_and_then_nothing() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"123456");
        q.challenge_issued(&pending);

        let response = response_for(&pending, *b"123456");
        let matched = accepted(&mut q, &response).expect("live pending");
        assert_eq!(matched.request, pending.request);
        assert!(accepted(&mut q, &response).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// A repeat request shares its challenge; five wrong responses are
    /// tolerated and the sixth retires the challenge; a hit burns once.
    #[test]
    fn a_challenge_survives_a_repeat_and_retires_at_six() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"111111");
        q.admit(update("alice"), t0());
        assert_eq!(q.requested().len(), 1);
        q.challenge_issued(&pending);
        let other = admit(&mut q, release("alice"), *b"333333");
        q.challenge_issued(&other);

        // Five wrong responses against the check-in are tolerated: its
        // right code still answers.
        for n in 1..MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(accepted(&mut q, &response_for(&pending, wrong)).is_none());
        }
        let right = response_for(&pending, *b"111111");
        assert!(accepted(&mut q, &right).is_some());

        // The hit burns exactly once — and only the entry it answered.
        assert!(accepted(&mut q, &right).is_none());
        assert_eq!(q.relayed().collect::<Vec<_>>(), [other.request.name()]);

        // Six wrong responses retire the entry they name, and only it.
        for n in 1..=MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(accepted(&mut q, &response_for(&other, wrong)).is_none());
        }
        assert!(accepted(&mut q, &response_for(&other, *b"333333")).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// Two terms are two challenges; each code answers only its own.
    #[test]
    fn each_term_is_its_own_challenge() {
        let mut q = OtpQueue::new();
        let renewal = Request::Update {
            name: test_name("alice"),
            ua: mainnet_ua(),
            term: Some(Term::Years(5)),
        };
        let planted = admit(&mut q, update("alice"), *b"111111");
        let renewal = admit(&mut q, renewal, *b"222222");
        q.challenge_issued(&planted);
        q.challenge_issued(&renewal);

        let answered = accepted(&mut q, &response_for(&renewal, *b"222222")).unwrap();
        assert_eq!(answered.request, renewal.request);
        assert_eq!(answered.attempts, 0);
        assert_eq!(q.relayed().count(), 1);
        assert_eq!(q.challenges[0].challenge.attempts, 0);
    }

    /// Only `expire` closes a challenge's window.
    #[test]
    fn expire_is_owner_invoked() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"123456");
        q.challenge_issued(&pending);

        q.expire(pending.expires_at);
        assert!(accepted(&mut q, &response_for(&pending, *b"123456")).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// An unrelayed entry is never answered; it stays for the relay loop.
    #[test]
    fn respond_never_burns_an_unrelayed_entry() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"123456");

        assert!(accepted(&mut q, &response_for(&pending, *b"123456")).is_none());
        assert_eq!(q.requested().len(), 1);
    }

    /// A transparent spend is not relayed before it is mined. One
    /// transaction yields the first update or release that is ready,
    /// and a challenge already relayed from the mempool is skipped.
    #[test]
    fn one_shielded_transaction_relays_one_ready_challenge() {
        let batch = [update("alice"), update("bob"), release("carol")];
        assert!(zero_conf_candidate(false, &batch, |_| true).is_none());
        assert_eq!(
            zero_conf_candidate(true, &batch, |_| true).map(Request::name),
            Some(batch[0].name())
        );
        assert_eq!(
            zero_conf_candidate(true, &batch, |request| request.name().as_str() != "alice")
                .map(Request::name),
            Some(batch[1].name())
        );
        let claims = [Request::Claim {
            name: test_name("alice"),
            ua: mainnet_ua(),
            term: Term::Forever,
            code: None,
        }];
        assert!(zero_conf_candidate(true, &claims, |_| true).is_none());
    }

    /// The second request for a challenge waits for a block, including
    /// after the relayed request dies. A mined request still opens one.
    /// A request that dies before its challenge is sent does not use the relay.
    #[test]
    fn a_second_mempool_request_waits_after_the_first_dies() {
        let mut q = OtpQueue::new();
        let request = update("alice");
        assert!(q.admit_unmined(request.clone(), txid(1), t0()));
        assert!(!q.invalidate(txid(1)));
        assert!(q.admit_unmined(request.clone(), txid(2), t0()));
        let pending = q.requested().remove(0);
        q.challenge_issued(&pending);
        assert!(q.invalidate(txid(2)));
        assert!(!q.invalidate(txid(2)));
        assert!(!q.admit_unmined(request.clone(), txid(3), t0()));
        q.admit(request, t0());
        assert_eq!(q.requested().len(), 1);
    }

    /// An echo against an unmined request is held and counts no attempt.
    /// Once the request dies, the same echo counts nothing.
    #[test]
    fn an_unmined_echo_is_held_and_a_dead_one_is_refused() {
        let mut q = OtpQueue::new();
        let request = update("alice");
        assert!(q.admit_unmined(request.clone(), txid(1), t0()));
        q.challenges[0].challenge.code = OtpCode::for_test(*b"111111");
        let pending = q.challenges[0].challenge.clone();
        q.challenge_issued(&pending);
        let right = response_for(&pending, *b"111111");
        let wrong = response_for(&pending, *b"000000");

        assert!(matches!(
            q.complete(&wrong, height()),
            Some(ChallengeAnswer::Held)
        ));
        assert!(matches!(
            q.complete(&right, height()),
            Some(ChallengeAnswer::Held)
        ));
        assert_eq!(q.challenges[0].challenge.attempts, 0);

        q.confirm_mined(txid(1), BlockHeight::from_u32(5));
        assert!(accepted(&mut q, &wrong).is_none());
        assert_eq!(q.challenges[0].challenge.attempts, 1);
        let Some(ChallengeAnswer::Accepted { at, .. }) =
            q.complete(&right, BlockHeight::from_u32(2))
        else {
            panic!("mined echo should complete");
        };
        assert_eq!(at, BlockHeight::from_u32(5));

        assert!(q.admit_unmined(request.clone(), txid(4), t0()));
        q.challenges[0].challenge.code = OtpCode::for_test(*b"222222");
        let pending = q.challenges[0].challenge.clone();
        q.challenge_issued(&pending);
        let right = response_for(&pending, *b"222222");
        assert!(q.invalidate(txid(4)));
        assert!(q.complete(&right, height()).is_none());
        assert_eq!(q.challenges[0].challenge.attempts, 0);
        q.admit(request, t0());
        assert_eq!(q.requested().len(), 1);
    }
}
