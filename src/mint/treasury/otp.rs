//! OTP auth for locked names.
//!
use rand::RngExt;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zcash_primitives::transaction::TxId;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::mint::sale::{is_owner_listing, Ask, AuctionTerms, MarketRefusal};
use crate::mint::{Name, OtpMemo, Request, UnifiedAddress};

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

    /// The auction challenge for this request. The same inputs yield the
    /// same code, so a rescan matches the controller's reply.
    pub fn auction(
        key: &[u8],
        txid: &[u8; 32],
        name: &[u8],
        terms: &AuctionTerms,
        pay_to: &[u8],
    ) -> Self {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"ZNS:auctionotp");
        mac.update(txid);
        mac.update(name);
        mac.update(&terms.start_price.into_u64().to_be_bytes());
        mac.update(&terms.min_price.into_u64().to_be_bytes());
        mac.update(&u32::from(terms.start).to_be_bytes());
        mac.update(&u32::from(terms.end).to_be_bytes());
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

    /// The controller-facing projection. A list challenge carries the
    /// t1 and the price or the auction terms she is authorizing.
    pub fn memo(&self) -> OtpMemo {
        let (listing, auction) = match &self.request {
            Request::List(listed) => match &listed.ask {
                Ask::Flat(price) => (Some((listed.pay_to, *price)), None),
                Ask::Dutch(terms) => (None, Some((listed.pay_to, terms.clone()))),
            },
            Request::Claim { .. }
            | Request::Update { .. }
            | Request::Release { .. }
            | Request::Delist { .. }
            | Request::Buy { .. } => (None, None),
        };
        OtpMemo {
            code: self.code.clone(),
            name: self.request.name().clone(),
            action: self.request.action(),
            ua: self.request.ua().clone(),
            listing,
            auction,
        }
    }

    /// `owner` still holds the name on the terms this challenge names.
    pub fn held_by(&self, owner: &UnifiedAddress) -> bool {
        match &self.request {
            Request::List(listing) => is_owner_listing(owner, &listing.ua, &listing.pay_to),
            Request::Claim { .. }
            | Request::Update { .. }
            | Request::Release { .. }
            | Request::Delist { .. }
            | Request::Buy { .. } => self.request.ua() == owner,
        }
    }

    /// `response` repeats the t1 and the price or auction terms this
    /// challenge names, and no others.
    pub fn same_terms(&self, response: &OtpMemo) -> bool {
        match &self.request {
            Request::List(listing) => match &listing.ask {
                Ask::Flat(price) => {
                    response.auction.is_none()
                        && response.listing.as_ref().is_some_and(|(pay_to, quoted)| {
                            *pay_to == listing.pay_to && quoted == price
                        })
                }
                Ask::Dutch(terms) => response
                    .auction
                    .as_ref()
                    .is_some_and(|(pay_to, quoted)| *pay_to == listing.pay_to && quoted == terms),
            },
            Request::Claim { .. }
            | Request::Update { .. }
            | Request::Release { .. }
            | Request::Delist { .. }
            | Request::Buy { .. } => response.listing.is_none() && response.auction.is_none(),
        }
    }
}

/// Lifecycle state for a pending challenge entry.
#[derive(Clone, PartialEq, Eq)]
pub enum ChallengeState {
    /// Seen, its challenge memo not yet accepted by the node.
    Requested,
    /// The node accepted the challenge memo; an OTP response may arrive.
    Relayed,
}

/// Open challenges, in order. Update and release challenges carry the
/// txid of their request. List and delist challenges carry a code
/// derived from their request, so a scan opens the same one again.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<(OtpChallenge, ChallengeState, TxId)>,
    listing_challenges: Vec<(OtpChallenge, ChallengeState)>,
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
            listing_challenges: Vec::new(),
        }
    }

    /// A repeat keeps the open challenge; a code already open is refused.
    pub fn open_listing_challenge(
        &mut self,
        request: Request,
        code: OtpCode,
        mtp: Timestamp,
    ) -> Result<(), MarketRefusal> {
        if self
            .listing_challenges
            .iter()
            .any(|(challenge, _)| challenge.request == request)
        {
            return Ok(());
        }
        if self
            .listing_challenges
            .iter()
            .any(|(challenge, _)| challenge.code == code)
        {
            return Err(MarketRefusal::CodeTaken);
        }
        let challenge = OtpChallenge {
            request,
            code,
            expires_at: mtp + Duration::seconds(D_OTP),
            attempts: 0,
        };
        self.listing_challenges
            .push((challenge, ChallengeState::Requested));
        Ok(())
    }

    /// Spends the challenge the response answers and returns its
    /// request. A miss counts an attempt against every challenge it names.
    pub fn answer_listing_challenge(&mut self, response: &OtpMemo) -> Option<Request> {
        let named: Vec<usize> = self
            .listing_challenges
            .iter()
            .enumerate()
            .filter(|(_, (challenge, _))| {
                challenge.request.name() == &response.name
                    && challenge.request.ua() == &response.ua
                    && challenge.request.action() == response.action
            })
            .map(|(index, _)| index)
            .collect();
        if let Some(index) = named.iter().copied().find(|&index| {
            let (challenge, _) = &self.listing_challenges[index];
            bool::from(challenge.code.0.ct_eq(&response.code.0)) && challenge.same_terms(response)
        }) {
            let (challenge, _) = self.listing_challenges.remove(index);
            return Some(challenge.request);
        }
        for index in named.into_iter().rev() {
            let (challenge, _) = &mut self.listing_challenges[index];
            challenge.attempts += 1;
            if challenge.attempts >= MAX_ATTEMPTS {
                self.listing_challenges.remove(index);
            }
        }
        None
    }

    /// Unsent challenges for names `open` allows, whose owner still
    /// holds the name on their terms.
    pub fn unrelayed_listing_challenges(
        &self,
        open: impl Fn(&Name) -> bool,
        owner: impl Fn(&Name) -> Option<UnifiedAddress>,
    ) -> Vec<OtpChallenge> {
        self.listing_challenges
            .iter()
            .filter(|(challenge, state)| {
                *state == ChallengeState::Requested && open(challenge.request.name())
            })
            .filter(|(challenge, _)| {
                owner(challenge.request.name()).is_some_and(|ua| challenge.held_by(&ua))
            })
            .map(|(challenge, _)| challenge.clone())
            .collect()
    }

    /// The node accepted the memo.
    pub fn listing_challenge_relayed(&mut self, code: &OtpCode) {
        for (challenge, state) in &mut self.listing_challenges {
            if &challenge.code == code {
                *state = ChallengeState::Relayed;
            }
        }
    }

    /// Closes challenges whose owner changed.
    pub fn reconcile_listing_challenges(
        &mut self,
        owner: impl Fn(&Name) -> Option<UnifiedAddress>,
    ) {
        self.listing_challenges.retain(|(challenge, _)| {
            owner(challenge.request.name()).is_some_and(|ua| ua == *challenge.request.ua())
        });
    }

    pub fn close_listing_challenges_for(&mut self, name: &Name) {
        self.listing_challenges
            .retain(|(challenge, _)| challenge.request.name() != name);
    }

    /// Issues a challenge for `request` unless one is live. Its code is
    /// unique among the challenges a response could also name. A live
    /// challenge takes `txid`, so a mined repeat backs a code first sent
    /// for a request that never landed.
    pub fn admit(&mut self, request: Request, txid: TxId, mtp: Timestamp) {
        if let Some((_, _, backing)) = self
            .challenges
            .iter_mut()
            .find(|(challenge, _, _)| challenge.request == request)
        {
            *backing = txid;
            return;
        }
        let code = loop {
            let code = OtpCode::generate();
            if !self.challenges.iter().any(|(challenge, _, _)| {
                challenge.request.name() == request.name()
                    && challenge.request.action() == request.action()
                    && challenge.request.ua() == request.ua()
                    && challenge.code == code
            }) {
                break code;
            }
        };
        self.challenges.push((
            OtpChallenge {
                request,
                code,
                expires_at: mtp + Duration::seconds(D_OTP),
                attempts: 0,
            },
            ChallengeState::Requested,
            txid,
        ));
    }

    /// A challenge for `request` is live.
    pub fn holds(&self, request: &Request) -> bool {
        self.challenges
            .iter()
            .any(|(challenge, _, _)| challenge.request == *request)
    }

    /// Points a live challenge for `request` at `txid`. A request with
    /// no challenge is left alone.
    pub fn rebind(&mut self, request: &Request, txid: TxId) -> bool {
        let Some((_, _, backing)) = self
            .challenges
            .iter_mut()
            .find(|(challenge, _, _)| challenge.request == *request)
        else {
            return false;
        };
        *backing = txid;
        true
    }

    /// The txid a relayed challenge with this code would spend. The
    /// challenge stays.
    pub fn backing(&self, response: &OtpMemo) -> Option<TxId> {
        self.challenges.iter().find_map(|(challenge, state, txid)| {
            (*state == ChallengeState::Relayed
                && challenge.request.name() == &response.name
                && challenge.request.action() == response.action
                && challenge.request.ua() == &response.ua
                && bool::from(challenge.code.0.ct_eq(&response.code.0)))
            .then_some(*txid)
        })
    }

    /// The node accepted `relayed`'s memo.
    pub fn challenge_issued(&mut self, relayed: &OtpChallenge) {
        for (challenge, state, _) in &mut self.challenges {
            if challenge.request == relayed.request {
                *state = ChallengeState::Relayed;
            }
        }
    }

    /// Challenges not yet relayed.
    pub fn requested(&self) -> Vec<OtpChallenge> {
        self.challenges
            .iter()
            .filter(|(_, state, _)| *state == ChallengeState::Requested)
            .map(|(challenge, _, _)| challenge.clone())
            .collect()
    }

    /// Drops every challenge whose window closed by `mtp`.
    pub fn expire(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|(challenge, _, _)| mtp < challenge.expires_at);
        self.listing_challenges
            .retain(|(challenge, _)| mtp < challenge.expires_at);
    }

    /// Drops every challenge for `name`, once a transition is admitted.
    pub fn drop_challenges(&mut self, name: &Name) {
        self.challenges
            .retain(|(challenge, _, _)| challenge.request.name() != name);
    }

    /// The right code removes and returns its challenge, with the txid
    /// of the request it answers. A wrong one counts against every
    /// challenge the response names.
    pub fn complete(&mut self, response: &OtpMemo) -> Option<(OtpChallenge, TxId)> {
        let named = |challenge: &OtpChallenge, state: &ChallengeState| {
            *state == ChallengeState::Relayed
                && challenge.request.name() == &response.name
                && challenge.request.action() == response.action
                && challenge.request.ua() == &response.ua
        };
        let right = self.challenges.iter().position(|(challenge, state, _)| {
            named(challenge, state) && bool::from(challenge.code.0.ct_eq(&response.code.0))
        });
        if let Some(index) = right {
            let (mut challenge, _, txid) = self.challenges.remove(index);
            return challenge
                .attempt(&response.code)
                .then_some((challenge, txid));
        }
        self.challenges.retain_mut(|(challenge, state, _)| {
            if !named(challenge, state) {
                return true;
            }
            challenge.attempt(&response.code) || challenge.attempts < MAX_ATTEMPTS
        });
        None
    }

    /// The name of every challenge still awaiting relay, borrowed.
    pub fn unrelayed(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|(_, state, _)| *state == ChallengeState::Requested)
            .map(|(challenge, _, _)| challenge.request.name())
    }

    /// The name of every relayed challenge, awaiting its response.
    pub fn relayed(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|(_, state, _)| *state == ChallengeState::Relayed)
            .map(|(challenge, _, _)| challenge.request.name())
    }
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

    fn txid(byte: u8) -> TxId {
        TxId::from_bytes([byte; 32])
    }

    /// Admits `request` at `t0`, its code fixed to `code`.
    fn admit(q: &mut OtpQueue, request: Request, code: [u8; 6]) -> OtpChallenge {
        q.admit(request.clone(), txid(1), t0());
        let (challenge, _, _) = q
            .challenges
            .iter_mut()
            .find(|(challenge, _, _)| challenge.request == request)
            .unwrap();
        challenge.code = OtpCode::for_test(code);
        challenge.clone()
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
        q.admit(update("alice"), txid(1), t0());
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

        assert!(q
            .complete(&response_for(&alice_update, *b"111111"))
            .is_none());
        assert!(q
            .complete(&response_for(&alice_release, *b"222222"))
            .is_none());
        assert_eq!(q.relayed().collect::<Vec<_>>(), [bob.request.name()]);
        assert!(q.complete(&response_for(&bob, *b"333333")).is_some());
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
        let (matched, _) = q.complete(&response).expect("live pending");
        assert_eq!(matched.request, pending.request);
        assert!(q.complete(&response).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// A repeat request shares its challenge; five wrong responses are
    /// tolerated and the sixth retires the challenge; a hit burns once.
    #[test]
    fn a_challenge_survives_a_repeat_and_retires_at_six() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"111111");
        q.admit(update("alice"), txid(1), t0());
        assert_eq!(q.requested().len(), 1);
        q.challenge_issued(&pending);
        let other = admit(&mut q, release("alice"), *b"333333");
        q.challenge_issued(&other);

        // Five wrong responses against the check-in are tolerated: its
        // right code still answers.
        for n in 1..MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(q.complete(&response_for(&pending, wrong)).is_none());
        }
        let right = response_for(&pending, *b"111111");
        assert!(q.complete(&right).is_some());

        // The hit burns exactly once — and only the entry it answered.
        assert!(q.complete(&right).is_none());
        assert_eq!(q.relayed().collect::<Vec<_>>(), [other.request.name()]);

        // Six wrong responses retire the entry they name, and only it.
        for n in 1..=MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(q.complete(&response_for(&other, wrong)).is_none());
        }
        assert!(q.complete(&response_for(&other, *b"333333")).is_none());
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

        let (answered, _) = q.complete(&response_for(&renewal, *b"222222")).unwrap();
        assert_eq!(answered.request, renewal.request);
        assert_eq!(answered.attempts, 0);
        assert_eq!(q.relayed().count(), 1);
        assert_eq!(q.challenges[0].0.attempts, 0);
    }

    /// A repeat request keeps the code and hands the challenge its txid:
    /// a code first sent for a request that never landed is answered
    /// against the repeat.
    #[test]
    fn a_repeat_request_backs_the_live_code() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, release("alice"), *b"111111");
        q.challenge_issued(&pending);
        q.admit(release("alice"), txid(2), t0());

        let (answered, backing) = q.complete(&response_for(&pending, *b"111111")).unwrap();
        assert!(answered.code == pending.code);
        assert_eq!(backing, txid(2));
    }

    /// Only `expire` closes a challenge's window.
    #[test]
    fn expire_is_owner_invoked() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"123456");
        q.challenge_issued(&pending);

        q.expire(pending.expires_at);
        assert!(q.complete(&response_for(&pending, *b"123456")).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// An unrelayed entry is never answered; it stays for the relay loop.
    #[test]
    fn respond_never_burns_an_unrelayed_entry() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"123456");

        assert!(q.complete(&response_for(&pending, *b"123456")).is_none());
        assert_eq!(q.requested().len(), 1);
    }

    /// Reading the txid leaves the challenge. Rebinding points it at
    /// the mined repeat. Completing then spends it.
    #[test]
    fn backing_reads_the_txid_and_rebind_points_at_the_repeat() {
        let mut q = OtpQueue::new();
        let pending = admit(&mut q, update("alice"), *b"111111");
        let response = response_for(&pending, *b"111111");
        assert!(q.backing(&response).is_none());
        q.challenge_issued(&pending);
        assert_eq!(q.backing(&response), Some(txid(1)));
        assert!(q.rebind(&pending.request, txid(2)));
        assert_eq!(q.backing(&response), Some(txid(2)));
        assert_eq!(q.relayed().count(), 1);
        assert!(!q.rebind(&release("alice"), txid(3)));
        assert_eq!(q.challenges.len(), 1);
        assert!(q.complete(&response).is_some());
        assert!(q.backing(&response).is_none());
    }
}
