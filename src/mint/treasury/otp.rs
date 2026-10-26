//! OTP auth for locked names.
//!
use rand::RngExt;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zeroize::Zeroize;

use crate::mint::{Action, Name, OtpMemo, Request, UnifiedAddress};

/// Thirty minutes; §5.3: D_OTP.
pub const D_OTP: i64 = 1800;

/// Wrong OTP responses tolerated per challenge (§5: the deployment
/// fixes the maximum number of verification attempts).
pub const MAX_ATTEMPTS: u32 = 6;

/// Wrong OTP responses counted against a challenge's code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attempts(u32);

impl Attempts {
    /// Counts one more wrong response; true when the challenge retires.
    fn count(&mut self) -> bool {
        self.0 += 1;
        self.0 >= MAX_ATTEMPTS
    }
}

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
}

impl OtpChallenge {
    /// Issues a challenge: draws a fresh code, expires after `D_OTP`.
    pub fn issue(request: Request, mtp_now: Timestamp) -> Self {
        Self {
            request,
            code: OtpCode::generate(),
            expires_at: mtp_now + Duration::seconds(D_OTP),
        }
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
    challenges: Vec<(OtpChallenge, ChallengeState, Attempts)>,
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

    /// Where the OTP for a name, verb and requested address sits:
    /// the one definition of "the same OTP". Every phase looks up
    /// through it.
    fn index_of(&self, name: &Name, action: Action, ua: &UnifiedAddress) -> Option<usize> {
        self.challenges.iter().position(|(challenge, _, _)| {
            challenge.request.name() == name
                && challenge.request.action() == action
                && challenge.request.ua() == ua
        })
    }

    /// One live entry per pending transition: a repeat request
    /// receives the existing entry.
    pub fn admit(&mut self, challenge: OtpChallenge) -> OtpChallenge {
        let request = &challenge.request;
        if let Some(index) = self.index_of(request.name(), request.action(), request.ua()) {
            return self.challenges[index].0.clone();
        }
        self.challenges.push((
            challenge.clone(),
            ChallengeState::Requested,
            Attempts::default(),
        ));
        challenge
    }

    /// Marks a request as relayed after the node accepts its challenge.
    pub fn challenge_issued(&mut self, challenge: &OtpChallenge) -> bool {
        let request = &challenge.request;
        let Some(index) = self.index_of(request.name(), request.action(), request.ua()) else {
            return false;
        };
        let state = &mut self.challenges[index].1;
        if *state != ChallengeState::Requested {
            return false;
        }
        *state = ChallengeState::Relayed;
        true
    }

    /// Returns queued requests that still need a challenge submission.
    pub fn requested(&self) -> Vec<OtpChallenge> {
        self.challenges
            .iter()
            .filter(|(_, state, _)| *state == ChallengeState::Requested)
            .map(|(challenge, _, _)| challenge.clone())
            .collect()
    }

    /// Drops expired challenges. The run loop calls this each wake-up.
    pub fn prune(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|(challenge, _, _)| mtp < challenge.expires_at);
    }

    /// Drops every challenge for `name`: a transition for it was
    /// admitted, and no code issued before it may answer after it.
    pub fn drop_challenges(&mut self, name: &Name) {
        self.challenges
            .retain(|(challenge, _, _)| challenge.request.name() != name);
    }

    /// The relayed challenge an OTP response answers when its code is
    /// right, removed: one code, one use. A wrong code counts one
    /// attempt against the challenge the response names and retires
    /// it at [`MAX_ATTEMPTS`].
    pub fn answer(&mut self, returned: &OtpMemo) -> Option<OtpChallenge> {
        let index = self.index_of(&returned.name, returned.action, &returned.ua)?;
        let (challenge, state, attempts) = &mut self.challenges[index];
        if *state != ChallengeState::Relayed {
            return None;
        }
        if bool::from(challenge.code.0.ct_eq(&returned.code.0)) {
            return Some(self.challenges.remove(index).0);
        }
        if attempts.count() {
            self.challenges.remove(index);
        }
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
    use crate::mint::Term;

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

    fn challenge(request: Request, code: [u8; 6]) -> OtpChallenge {
        OtpChallenge {
            request,
            code: OtpCode::for_test(code),
            expires_at: t0() + Duration::seconds(D_OTP),
        }
    }

    /// The controller's response to `challenge`, with `code`.
    fn response_for(challenge: &OtpChallenge, code: [u8; 6]) -> OtpMemo {
        OtpMemo {
            code: OtpCode::for_test(code),
            ..challenge.memo()
        }
    }

    #[test]
    fn the_birth_shares_one_code_and_expires_after_d_otp() {
        let request = Request::Update {
            name: test_name("alice"),
            ua: mainnet_ua(),
            term: Some(Term::Years(1)),
        };
        let pending = OtpChallenge::issue(request.clone(), t0());

        // One code in two bodies: the memo is the controller's whole
        // view of the record — four fields, nothing private.
        let memo = pending.memo();
        assert_eq!(memo.code, pending.code);
        assert_eq!(&memo.name, request.name());
        assert_eq!(memo.action, request.action());
        assert_eq!(&memo.ua, request.ua());
        // The pending alone carries the expiry and the request.
        assert_eq!(
            pending.expires_at,
            Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap()
        );
        assert_eq!(pending.request, request);
    }

    /// Admitting a transition for a name drops every challenge for it:
    /// a code issued against the old record answers nothing after.
    /// Other names stand.
    #[test]
    fn drop_challenges_retires_every_code_for_the_name() {
        let mut q = OtpQueue::new();
        let alice_update = challenge(update("alice"), *b"111111");
        let alice_release = challenge(release("alice"), *b"222222");
        let bob = challenge(update("bob"), *b"333333");
        for pending in [&alice_update, &alice_release, &bob] {
            q.admit(pending.clone());
            assert!(q.challenge_issued(pending));
        }

        q.drop_challenges(&test_name("alice"));

        assert!(q.answer(&response_for(&alice_update, *b"111111")).is_none());
        assert!(q
            .answer(&response_for(&alice_release, *b"222222"))
            .is_none());
        assert_eq!(q.relayed().collect::<Vec<_>>(), [bob.request.name()]);
        assert!(q.answer(&response_for(&bob, *b"333333")).is_some());
    }

    /// A challenge names its name as unrelayed until it is relayed, and
    /// as relayed after. Pruning clears both.
    #[test]
    fn a_relayed_challenge_names_its_name_until_pruned() {
        let mut q = OtpQueue::new();
        let sent = challenge(update("alice"), *b"111111");
        let unsent = challenge(release("alice"), *b"222222");
        q.admit(sent.clone());
        q.admit(unsent.clone());
        assert_eq!(q.relayed().count(), 0);
        assert_eq!(q.unrelayed().count(), 2);
        assert!(q.challenge_issued(&sent));
        assert_eq!(q.relayed().collect::<Vec<_>>(), [sent.request.name()]);
        assert_eq!(q.unrelayed().collect::<Vec<_>>(), [unsent.request.name()]);
        q.prune(sent.expires_at);
        assert_eq!(q.relayed().count(), 0);
        assert_eq!(q.unrelayed().count(), 0);
    }

    /// The right code answers once; the identical response after it
    /// answers nothing.
    #[test]
    fn respond_burns_once_and_then_nothing() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"123456");
        q.admit(pending.clone());
        assert!(q.challenge_issued(&pending));

        let response = response_for(&pending, *b"123456");
        let matched = q.answer(&response).expect("live pending");
        assert_eq!(matched.request, pending.request);
        assert!(q.answer(&response).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// One entry per transition; a repeat shares it; five wrong
    /// responses are tolerated and the sixth retires the entry they
    /// name, alone; a hit burns once.
    #[test]
    fn a_challenge_survives_a_repeat_and_retires_at_six() {
        let mut q = OtpQueue::new();

        // A first request opens one entry for its transition.
        let check_in = challenge(update("alice"), *b"111111");
        let pending = q.admit(check_in.clone());

        // A repeat request receives the same entry — same code.
        let again = q.admit(challenge(update("alice"), *b"222222"));
        assert_eq!(again.code, pending.code);
        assert!(q.challenge_issued(&pending));

        // A different transition opens its own entry, its own code.
        let other = q.admit(challenge(release("alice"), *b"333333"));
        assert!(q.challenge_issued(&other));
        assert_ne!(other.code, pending.code);

        // Five wrong responses against the check-in are tolerated: its
        // right code still answers.
        for n in 1..MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(q.answer(&response_for(&pending, wrong)).is_none());
        }
        let right = response_for(&pending, *b"111111");
        assert!(q.answer(&right).is_some());

        // The hit burns exactly once — and only the entry it answered.
        assert!(q.answer(&right).is_none());
        assert_eq!(q.relayed().collect::<Vec<_>>(), [other.request.name()]);

        // Six wrong responses retire the entry they name, and only it.
        for n in 1..=MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(q.answer(&response_for(&other, wrong)).is_none());
        }
        assert!(q.answer(&response_for(&other, *b"333333")).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// Only `prune` expires a challenge.
    #[test]
    fn prune_is_owner_invoked() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"123456");
        q.admit(pending.clone());
        assert!(q.challenge_issued(&pending));

        q.prune(pending.expires_at);
        assert!(q.answer(&response_for(&pending, *b"123456")).is_none());
        assert_eq!(q.relayed().count(), 0);
    }

    /// An unrelayed entry is never answered; it stays for the relay loop.
    #[test]
    fn respond_never_burns_an_unrelayed_entry() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"123456");
        q.admit(pending.clone());

        assert!(q.answer(&response_for(&pending, *b"123456")).is_none());
        assert_eq!(q.requested().len(), 1);
    }
}
