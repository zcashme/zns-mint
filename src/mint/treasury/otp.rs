//! OTP auth for locked names.
//!
use rand::RngExt;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zeroize::Zeroize;

use crate::mint::{Name, OtpMemo, Request};

/// Thirty minutes; §5.3: D_OTP.
pub const D_OTP: i64 = 1800;

/// Wrong OTP responses tolerated per challenge (§5: the deployment
/// fixes the maximum number of verification attempts).
pub const MAX_ATTEMPTS: u32 = 6;

/// A six-digit one-time passcode.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
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

    /// The controller-facing projection: code, name, action, ua.
    pub fn memo(&self) -> OtpMemo {
        OtpMemo {
            code: self.code.clone(),
            name: self.request.name().clone(),
            action: self.request.action(),
            ua: self.request.ua().clone(),
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

/// Issued challenges, in order. Every challenge was issued against
/// its name's current record: the run loop drops a name's challenges
/// when it admits a transition for that name.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<(OtpChallenge, ChallengeState)>,
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
        if self
            .challenges
            .iter()
            .any(|(challenge, _)| challenge.request == request)
        {
            return;
        }
        let code = loop {
            let code = OtpCode::generate();
            if !self.challenges.iter().any(|(challenge, _)| {
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
        ));
    }

    /// The node accepted `relayed`'s memo.
    pub fn challenge_issued(&mut self, relayed: &OtpChallenge) {
        for (challenge, state) in &mut self.challenges {
            if challenge.request == relayed.request {
                *state = ChallengeState::Relayed;
            }
        }
    }

    /// Challenges not yet relayed.
    pub fn requested(&self) -> Vec<OtpChallenge> {
        self.challenges
            .iter()
            .filter(|(_, state)| *state == ChallengeState::Requested)
            .map(|(challenge, _)| challenge.clone())
            .collect()
    }

    /// Drops every challenge whose window closed by `mtp`.
    pub fn expire(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|(challenge, _)| mtp < challenge.expires_at);
    }

    /// Drops every challenge for `name`, once a transition is admitted.
    pub fn drop_challenges(&mut self, name: &Name) {
        self.challenges
            .retain(|(challenge, _)| challenge.request.name() != name);
    }

    /// The right code removes and returns its challenge. A wrong one
    /// counts against every challenge the response names.
    pub fn complete(&mut self, response: &OtpMemo) -> Option<OtpChallenge> {
        let named = |challenge: &OtpChallenge, state: &ChallengeState| {
            *state == ChallengeState::Relayed
                && challenge.request.name() == &response.name
                && challenge.request.action() == response.action
                && challenge.request.ua() == &response.ua
        };
        let right = self.challenges.iter().position(|(challenge, state)| {
            named(challenge, state) && bool::from(challenge.code.0.ct_eq(&response.code.0))
        });
        if let Some(index) = right {
            let mut challenge = self.challenges.remove(index).0;
            return challenge.attempt(&response.code).then_some(challenge);
        }
        self.challenges.retain_mut(|(challenge, state)| {
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
            .filter(|(_, state)| *state == ChallengeState::Requested)
            .map(|(challenge, _)| challenge.request.name())
    }

    /// The name of every relayed challenge, awaiting its response.
    pub fn relayed(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|(_, state)| *state == ChallengeState::Relayed)
            .map(|(challenge, _)| challenge.request.name())
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

    /// Admits `request` at `t0`, its code fixed to `code`.
    fn admit(q: &mut OtpQueue, request: Request, code: [u8; 6]) -> OtpChallenge {
        q.admit(request.clone(), t0());
        let (challenge, _) = q
            .challenges
            .iter_mut()
            .find(|(challenge, _)| challenge.request == request)
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
        let matched = q.complete(&response).expect("live pending");
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
        q.admit(update("alice"), t0());
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

        let answered = q.complete(&response_for(&renewal, *b"222222")).unwrap();
        assert_eq!(answered.request, renewal.request);
        assert_eq!(answered.attempts, 0);
        assert_eq!(q.relayed().count(), 1);
        assert_eq!(q.challenges[0].0.attempts, 0);
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
}
