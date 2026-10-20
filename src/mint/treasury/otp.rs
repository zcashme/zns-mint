//! OTP auth for locked names.
//!
use rand::RngExt;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zeroize::Zeroize;

use crate::mint::{Action, Name, NameCommitment, OtpMemo, Term, UnifiedAddress};

/// Thirty minutes; §5.3: D_OTP.
pub const D_OTP: i64 = 1800;

/// Wrong echoes tolerated per challenge (§5: the deployment fixes
/// the maximum number of verification attempts).
pub const MAX_ATTEMPTS: u32 = 6;

/// Wrong echoes counted against a challenge's code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attempts(u32);

impl Attempts {
    /// Counts one more wrong echo; true when the challenge retires.
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

/// An issued, pending challenge.
#[derive(Clone)]
pub struct OtpChallenge {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    pub term: Option<Term>,
    pub tip_rcm: NameCommitment,
    pub code: OtpCode,
    pub expires_at: Timestamp,
}

impl OtpChallenge {
    /// Issues a challenge: draws a fresh code, expires after `D_OTP`.
    pub fn issue(
        name: Name,
        action: Action,
        ua: UnifiedAddress,
        tip_rcm: NameCommitment,
        term: Option<Term>,
        mtp_now: Timestamp,
    ) -> Self {
        Self {
            name,
            action,
            ua,
            term,
            tip_rcm,
            code: OtpCode::generate(),
            expires_at: mtp_now + Duration::seconds(D_OTP),
        }
    }

    /// The controller-facing projection: code, name, action, ua.
    pub fn memo(&self) -> OtpMemo {
        OtpMemo {
            code: self.code.clone(),
            name: self.name.clone(),
            action: self.action,
            ua: self.ua.clone(),
        }
    }

    /// Whether this challenge is for the given transition: the name,
    /// the verb, and the requested address. A challenge is identified
    /// by its transition; `tip_rcm` and `code` are what it verifies.
    fn is_for(&self, name: &Name, action: Action, ua: &UnifiedAddress) -> bool {
        self.name == *name && self.action == action && self.ua == *ua
    }

    fn same_transition(&self, other: &OtpChallenge) -> bool {
        self.is_for(&other.name, other.action, &other.ua)
    }

    fn answered_by(&self, echo: &OtpMemo) -> bool {
        self.is_for(&echo.name, echo.action, &echo.ua)
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

/// One queued challenge and where it stands.
#[derive(Clone)]
struct Entry {
    challenge: OtpChallenge,
    state: ChallengeState,
    attempts: Attempts,
}

impl Entry {
    fn new(challenge: OtpChallenge) -> Self {
        Self {
            challenge,
            state: ChallengeState::Requested,
            attempts: Attempts::default(),
        }
    }

    fn is_relayed(&self) -> bool {
        self.state == ChallengeState::Relayed
    }
}

/// Issued challenges, in order.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<Entry>,
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

    /// One live entry per pending transition. A repeat request — the
    /// same transition against the same record — receives the existing
    /// entry: same code, same deadline, attempts kept. A request against
    /// a newer record finds the entry stale and replaces it: the old
    /// challenge could neither be relayed nor answered any more.
    pub fn admit(&mut self, request: OtpChallenge) -> OtpChallenge {
        match self
            .challenges
            .iter_mut()
            .find(|entry| entry.challenge.same_transition(&request))
        {
            Some(entry) if entry.challenge.tip_rcm == request.tip_rcm => entry.challenge.clone(),
            Some(entry) => {
                *entry = Entry::new(request.clone());
                request
            }
            None => {
                self.challenges.push(Entry::new(request.clone()));
                request
            }
        }
    }

    /// Marks a request as relayed after the node accepts its challenge.
    pub fn challenge_issued(&mut self, request: &OtpChallenge) -> bool {
        match self
            .challenges
            .iter_mut()
            .find(|entry| entry.challenge.same_transition(request))
        {
            Some(entry) if entry.state == ChallengeState::Requested => {
                entry.state = ChallengeState::Relayed;
                true
            }
            _ => false,
        }
    }

    /// Returns queued requests that still need a challenge submission.
    pub fn requested(&self) -> Vec<OtpChallenge> {
        self.challenges
            .iter()
            .filter(|entry| entry.state == ChallengeState::Requested)
            .map(|entry| entry.challenge.clone())
            .collect()
    }

    /// Drops expired challenges. The run loop calls this each wake-up.
    pub fn prune(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|entry| mtp < entry.challenge.expires_at);
    }

    /// The relayed challenge an echo answers when its code is right.
    /// The entry must have been issued against the current record
    /// (`tip_rcm`); a stale one answers nothing and counts nothing. A
    /// wrong code counts one attempt against the transition the echo
    /// names and retires it at [`MAX_ATTEMPTS`].
    pub fn answer(&mut self, returned: &OtpMemo, tip_rcm: NameCommitment) -> Option<OtpChallenge> {
        let index = self
            .challenges
            .iter()
            .position(|entry| entry.is_relayed() && entry.challenge.answered_by(returned))?;
        let entry = &mut self.challenges[index];
        if entry.challenge.tip_rcm != tip_rcm {
            return None;
        }
        if bool::from(entry.challenge.code.0.ct_eq(&returned.code.0)) {
            return Some(entry.challenge.clone());
        }
        if entry.attempts.count() {
            self.challenges.remove(index);
        }
        None
    }

    /// Consumes the answered challenge: one code, one use. Only the
    /// entry for that transition goes; its neighbours stand.
    pub fn consume(&mut self, answered: &OtpChallenge) -> bool {
        let before = self.challenges.len();
        self.challenges
            .retain(|entry| !(entry.is_relayed() && entry.challenge.same_transition(answered)));
        self.challenges.len() != before
    }

    /// The name of every challenge still awaiting relay, borrowed.
    pub fn unrelayed(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|entry| entry.state == ChallengeState::Requested)
            .map(|entry| &entry.challenge.name)
    }

    /// The name of every relayed challenge, awaiting its echo.
    pub fn relayed(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|entry| entry.is_relayed())
            .map(|entry| &entry.challenge.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::NameCommitment;

    fn test_name(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    fn commitment(seed: u8) -> NameCommitment {
        // Any [u8; 32] whose top two bits are 0 is a valid Pallas base
        // element; putting the seed in the low byte keeps the number small.
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        NameCommitment::from_bytes(&bytes).unwrap()
    }

    fn t0() -> Timestamp {
        Timestamp::from_seconds(1_700_000_000).unwrap()
    }

    /// A challenge for alice, `action`, the test UA, issued against
    /// `commitment(seed)` with `code`.
    fn challenge(action: Action, seed: u8, code: [u8; 6]) -> OtpChallenge {
        OtpChallenge {
            name: test_name("alice"),
            action,
            ua: mainnet_ua(),
            term: None,
            tip_rcm: commitment(seed),
            code: OtpCode::for_test(code),
            expires_at: t0() + Duration::seconds(D_OTP),
        }
    }

    /// The echo a controller sends back for `challenge`, carrying a
    /// code of the caller's choosing.
    fn echo_for(challenge: &OtpChallenge, code: [u8; 6]) -> OtpMemo {
        OtpMemo {
            code: OtpCode::for_test(code),
            name: challenge.name.clone(),
            action: challenge.action,
            ua: challenge.ua.clone(),
        }
    }

    #[test]
    fn the_birth_shares_one_code_and_expires_after_d_otp() {
        let alice = test_name("alice");
        let rcm = commitment(1);

        let pending = OtpChallenge::issue(
            alice,
            Action::Update,
            mainnet_ua(),
            rcm,
            Some(Term::Years(1)),
            t0(),
        );

        // One code in two bodies: the memo is the controller's whole
        // view of the record — four fields, nothing private.
        let challenge = pending.memo();
        assert_eq!(challenge.code, pending.code);
        assert_eq!(challenge.name, pending.name);
        assert_eq!(challenge.action, pending.action);
        assert_eq!(challenge.ua, pending.ua);
        // The pending alone carries the expiry and the term.
        assert_eq!(
            pending.expires_at,
            Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap()
        );
        assert_eq!(pending.term, Some(Term::Years(1)));
        assert_eq!(pending.tip_rcm, rcm);
    }

    fn mainnet_ua() -> UnifiedAddress {
        let s = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";
        match zcash_keys::address::Address::decode(&zcash_protocol::consensus::MAIN_NETWORK, s) {
            Some(zcash_keys::address::Address::Unified(u)) => *u,
            _ => panic!("test UA"),
        }
    }

    /// The record moved on under a live challenge: a request for the
    /// same transition against the new record replaces the stale entry
    /// — new code, new deadline — and the old code answers nothing.
    #[test]
    fn a_request_against_a_newer_record_replaces_the_stale_challenge() {
        let mut q = OtpQueue::new();
        let mut old = challenge(Action::Update, 1, *b"111111");
        old.term = Some(Term::Years(1));
        let mut new = challenge(Action::Update, 2, *b"222222");
        new.term = Some(Term::Years(5));
        new.expires_at = old.expires_at + Duration::seconds(60);

        q.admit(old.clone());
        assert!(q.challenge_issued(&old));

        // Same transition, newer record: the stale entry is replaced,
        // and the replacement starts over — unrelayed.
        let admitted = q.admit(new.clone());
        assert_eq!(admitted.code, new.code);
        assert_eq!(admitted.term, Some(Term::Years(5)));
        assert_eq!(admitted.expires_at, new.expires_at);
        assert_eq!(q.challenges.len(), 1);
        assert_eq!(q.requested().len(), 1);
        assert!(q.challenge_issued(&new));

        // The old code is dead against the new record; the new code
        // answers, but only against the record it was issued for.
        assert!(q
            .answer(&echo_for(&old, *b"111111"), commitment(2))
            .is_none());
        assert!(q
            .answer(&echo_for(&new, *b"222222"), commitment(1))
            .is_none());
        let matched = q
            .answer(&echo_for(&new, *b"222222"), commitment(2))
            .expect("the live challenge answers");
        assert_eq!(matched.term, Some(Term::Years(5)));
        assert_eq!(matched.tip_rcm, commitment(2));
    }

    /// A repeat request — same transition, same record — receives the
    /// existing entry: its code, its deadline, and its attempt count.
    #[test]
    fn a_repeat_keeps_the_code_the_deadline_and_the_attempts() {
        let mut q = OtpQueue::new();
        let first = challenge(Action::Update, 1, *b"111111");
        q.admit(first.clone());
        assert!(q.challenge_issued(&first));

        // Two wrong echoes are charged to the entry.
        for wrong in [*b"000001", *b"000002"] {
            assert!(q.answer(&echo_for(&first, wrong), first.tip_rcm).is_none());
        }

        // The repeat arrives with a fresh code and a later deadline;
        // neither replaces what stands.
        let mut again = challenge(Action::Update, 1, *b"222222");
        again.expires_at = first.expires_at + Duration::seconds(60);
        let received = q.admit(again);
        assert_eq!(received.code, first.code);
        assert_eq!(received.expires_at, first.expires_at);
        assert_eq!(q.challenges.len(), 1);
        assert_eq!(q.requested().len(), 0, "a relayed entry stays relayed");

        // The budget carried over: four more wrong echoes retire it.
        for wrong in [*b"000003", *b"000004", *b"000005", *b"000006"] {
            assert!(q.answer(&echo_for(&first, wrong), first.tip_rcm).is_none());
        }
        assert!(q
            .answer(&echo_for(&first, *b"111111"), first.tip_rcm)
            .is_none());
        assert!(q.challenges.is_empty());
    }

    /// A challenge names its name as unrelayed until it is relayed, and
    /// as relayed after. Pruning clears both.
    #[test]
    fn a_relayed_challenge_names_its_name_until_pruned() {
        let mut q = OtpQueue::new();
        let sent = challenge(Action::Update, 1, *b"111111");
        let unsent = challenge(Action::Release, 1, *b"222222");
        q.admit(sent.clone());
        q.admit(unsent.clone());
        assert_eq!(q.relayed().count(), 0);
        assert_eq!(q.unrelayed().count(), 2);
        assert!(q.challenge_issued(&sent));
        assert_eq!(q.relayed().collect::<Vec<_>>(), [&sent.name]);
        assert_eq!(q.unrelayed().collect::<Vec<_>>(), [&unsent.name]);
        q.prune(sent.expires_at);
        assert_eq!(q.relayed().count(), 0);
        assert_eq!(q.unrelayed().count(), 0);
    }

    /// A relayed challenge burns exactly once: `answer` finds it,
    /// `consume` removes it, and no later echo — even the identical
    /// one — can claim it again.
    #[test]
    fn respond_burns_once_and_then_nothing() {
        let mut q = OtpQueue::new();
        let pending = challenge(Action::Update, 1, *b"123456");
        q.admit(pending.clone());
        q.challenges[0].state = ChallengeState::Relayed;

        let echo = echo_for(&pending, *b"123456");
        let matched = q.answer(&echo, pending.tip_rcm).expect("live pending");
        assert_eq!(matched.tip_rcm, pending.tip_rcm);

        assert!(q.consume(&matched));
        assert!(q.answer(&echo, pending.tip_rcm).is_none());
        assert!(!q.consume(&matched));
    }

    /// The queue's contract in one walk: one live entry per pending
    /// transition; a repeat request receives it; a different transition
    /// opens its own entry with its own code; five wrong echoes are
    /// tolerated and the sixth retires the entry they name, alone; and
    /// a hit burns exactly once.
    #[test]
    fn a_challenge_survives_a_repeat_and_retires_at_six() {
        let mut q = OtpQueue::new();

        // A first request opens one entry for its transition.
        let check_in = challenge(Action::Update, 1, *b"111111");
        let pending = q.admit(check_in.clone());

        // A repeat request receives the same entry — same code.
        let again = q.admit(challenge(Action::Update, 1, *b"222222"));
        assert_eq!(again.code, pending.code);
        assert!(q.challenge_issued(&pending));

        // A different transition — here the release of the same name —
        // opens its own entry, its own code.
        let release = challenge(Action::Release, 1, *b"333333");
        let other = q.admit(release.clone());
        assert!(q.challenge_issued(&other));
        assert_ne!(other.code, pending.code);
        assert_eq!(q.challenges.len(), 2);

        // Five wrong echoes against the check-in are tolerated: its
        // right code still answers.
        for n in 1..MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(q
                .answer(&echo_for(&pending, wrong), check_in.tip_rcm)
                .is_none());
        }
        let right = echo_for(&pending, *b"111111");
        let answered = q.answer(&right, check_in.tip_rcm).expect("still answers");

        // The hit burns exactly once — and only the entry it answered:
        // the neighbour stands.
        assert!(q.consume(&answered));
        assert!(q.answer(&right, check_in.tip_rcm).is_none());
        assert_eq!(q.relayed().collect::<Vec<_>>(), [&other.name]);

        // Six wrong echoes retire the entry they name, and only it.
        for n in 1..=MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(q
                .answer(&echo_for(&other, wrong), release.tip_rcm)
                .is_none());
        }
        assert!(q
            .answer(&echo_for(&other, *b"333333"), release.tip_rcm)
            .is_none());
        assert!(q.challenges.is_empty());
    }

    /// Freshness is the owner's prune, not the scans': an expired
    /// challenge still matches until the owner prunes, and prune
    /// alone removes it.
    #[test]
    fn prune_is_owner_invoked() {
        let mut q = OtpQueue::new();
        let pending = challenge(Action::Update, 1, *b"123456");
        q.admit(pending.clone());
        q.challenges[0].state = ChallengeState::Relayed;

        let echo = echo_for(&pending, *b"123456");
        assert!(q.answer(&echo, pending.tip_rcm).is_some());
        q.prune(t0() + Duration::seconds(D_OTP + 1));
        assert!(q.answer(&echo, pending.tip_rcm).is_none());
    }

    /// `consume` burns only relayed challenges: a key to a never-relayed
    /// entry is refused, and the entry stays queued for the relay loop.
    #[test]
    fn respond_never_burns_an_unrelayed_entry() {
        let mut q = OtpQueue::new();
        let pending = challenge(Action::Update, 1, *b"123456");
        q.admit(pending.clone());
        // Still `Requested`: the challenge memo was never accepted.

        assert!(!q.consume(&pending));
        assert_eq!(q.requested().len(), 1);
    }
}
