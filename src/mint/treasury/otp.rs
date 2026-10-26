//! OTP auth for locked names.
//!
use rand::RngExt;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
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

/// Where a challenge is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeState {
    /// The request paid the fee; the node has not accepted the relay.
    Requested,
    /// The node accepted the relay; the controller may respond.
    Relayed,
}

/// A right-code OTP response, held for the tip pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtpResponse {
    pub txid: TxId,
    pub paid: Zatoshis,
    pub height: BlockHeight,
}

/// Every pending challenge, in request order: state, wrong attempts,
/// and the right response waiting for the tip pass.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<(OtpChallenge, ChallengeState, Attempts, Option<OtpResponse>)>,
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
        self.challenges.iter().position(|(challenge, _, _, _)| {
            challenge.request.name() == name
                && challenge.request.action() == action
                && challenge.request.ua() == ua
        })
    }

    fn index_of_challenge(&self, challenge: &OtpChallenge) -> Option<usize> {
        let request = &challenge.request;
        self.index_of(request.name(), request.action(), request.ua())
    }

    /// One live entry per pending transition: a repeat request
    /// receives the existing entry.
    pub fn admit(&mut self, challenge: OtpChallenge) -> OtpChallenge {
        if let Some(index) = self.index_of_challenge(&challenge) {
            return self.challenges[index].0.clone();
        }
        self.challenges.push((
            challenge.clone(),
            ChallengeState::Requested,
            Attempts::default(),
            None,
        ));
        challenge
    }

    /// Every challenge still to be relayed.
    pub fn unrelayed(&self) -> Vec<OtpChallenge> {
        self.challenges
            .iter()
            .filter(|(_, state, _, _)| *state == ChallengeState::Requested)
            .map(|(challenge, _, _, _)| challenge.clone())
            .collect()
    }

    /// The node accepted the relay. False when the challenge is gone
    /// or already relayed.
    pub fn relayed(&mut self, challenge: &OtpChallenge) -> bool {
        let Some(index) = self.index_of_challenge(challenge) else {
            return false;
        };
        let state = &mut self.challenges[index].1;
        if *state != ChallengeState::Requested {
            return false;
        }
        *state = ChallengeState::Relayed;
        true
    }

    /// A response, at block application. A right code on a relayed
    /// challenge is held for the tip pass, the first one holding; a
    /// wrong code counts an attempt and retires the challenge at
    /// [`MAX_ATTEMPTS`]; anything else is ignored.
    pub fn respond(&mut self, returned: &OtpMemo, txid: TxId, paid: Zatoshis, height: BlockHeight) {
        let Some(index) = self.index_of(&returned.name, returned.action, &returned.ua) else {
            return;
        };
        let (challenge, state, attempts, response) = &mut self.challenges[index];
        if *state != ChallengeState::Relayed {
            return;
        }
        if bool::from(challenge.code.0.ct_eq(&returned.code.0)) {
            response.get_or_insert(OtpResponse { txid, paid, height });
            return;
        }
        if attempts.count() {
            self.challenges.remove(index);
        }
    }

    /// Every held response with its challenge, in request order. The
    /// challenges stay relayed until the law consumes them.
    pub fn take_responses(&mut self) -> Vec<(OtpChallenge, OtpResponse)> {
        self.challenges
            .iter_mut()
            .filter_map(|(challenge, _, _, response)| {
                response
                    .take()
                    .map(|response| (challenge.clone(), response))
            })
            .collect()
    }

    /// The law accepted: one code, one use. False when the challenge
    /// is gone or was never relayed.
    pub fn consume(&mut self, answered: &OtpChallenge) -> bool {
        let Some(index) = self.index_of_challenge(answered) else {
            return false;
        };
        if self.challenges[index].1 != ChallengeState::Relayed {
            return false;
        }
        self.challenges.remove(index);
        true
    }

    /// Drops expired challenges. The run loop calls this each wake-up.
    pub fn prune(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|(challenge, _, _, _)| mtp < challenge.expires_at);
    }

    /// Drops every challenge for `name`: a transition for it was
    /// admitted, and no code issued before it may answer after it.
    pub fn drop_challenges(&mut self, name: &Name) {
        self.challenges
            .retain(|(challenge, _, _, _)| challenge.request.name() != name);
    }

    /// The challenge's state; `None` once it is gone.
    pub fn state_of(&self, challenge: &OtpChallenge) -> Option<ChallengeState> {
        self.index_of_challenge(challenge)
            .map(|index| self.challenges[index].1)
    }

    /// Names the mint holds the next move on: unrelayed, or answered.
    pub fn working(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|(_, state, _, response)| {
                *state == ChallengeState::Requested || response.is_some()
            })
            .map(|(challenge, _, _, _)| challenge.request.name())
    }

    /// Names the controller holds the next move on: relayed, unanswered.
    pub fn awaiting(&self) -> impl Iterator<Item = &Name> {
        self.challenges
            .iter()
            .filter(|(_, state, _, response)| {
                *state == ChallengeState::Relayed && response.is_none()
            })
            .map(|(challenge, _, _, _)| challenge.request.name())
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

    fn paid(zats: u64) -> Zatoshis {
        Zatoshis::const_from_u64(zats)
    }

    fn height(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    fn response_txid(n: u8) -> TxId {
        TxId::from_bytes([n; 32])
    }

    /// Admits and relays `challenge`.
    fn relay(q: &mut OtpQueue, challenge: &OtpChallenge) {
        q.admit(challenge.clone());
        assert!(q.relayed(challenge));
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

    /// A transition admitted for a name drops every challenge for it.
    #[test]
    fn drop_challenges_retires_every_code_for_the_name() {
        let mut q = OtpQueue::new();
        let alice = challenge(update("alice"), *b"111111");
        let bob = challenge(update("bob"), *b"333333");
        relay(&mut q, &alice);
        relay(&mut q, &bob);
        q.respond(
            &response_for(&alice, *b"111111"),
            response_txid(0),
            paid(0),
            height(10),
        );

        q.drop_challenges(&test_name("alice"));

        assert_eq!(q.state_of(&alice), None);
        assert_eq!(q.state_of(&bob), Some(ChallengeState::Relayed));
        assert!(q.take_responses().is_empty());
    }

    /// Unrelayed and answered are the mint's move; relayed is the controller's.
    #[test]
    fn working_and_awaiting_follow_the_challenge() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"111111");
        q.admit(pending.clone());
        assert_eq!(q.working().count(), 1);
        assert_eq!(q.awaiting().count(), 0);

        assert!(q.relayed(&pending));
        assert!(!q.relayed(&pending));
        assert_eq!(q.working().count(), 0);
        assert_eq!(q.awaiting().count(), 1);

        q.respond(
            &response_for(&pending, *b"111111"),
            response_txid(0),
            paid(0),
            height(10),
        );
        assert_eq!(q.working().count(), 1);
        assert_eq!(q.awaiting().count(), 0);
    }

    /// A right response is held once for the tip pass; `consume` burns the challenge.
    #[test]
    fn respond_burns_once_and_then_nothing() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"123456");
        relay(&mut q, &pending);
        let response = response_for(&pending, *b"123456");

        q.respond(&response, response_txid(7), paid(5_000), height(42));
        let taken = q.take_responses();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0.request, pending.request);
        assert_eq!(
            taken[0].1,
            OtpResponse {
                txid: response_txid(7),
                paid: paid(5_000),
                height: height(42),
            }
        );
        assert!(q.take_responses().is_empty());

        assert!(q.consume(&pending));
        q.respond(&response, response_txid(0), paid(5_000), height(43));
        assert!(q.take_responses().is_empty());
        assert!(!q.consume(&pending));
    }

    /// The first right response holds until the tip pass takes it; a
    /// refused one leaves the challenge answerable.
    #[test]
    fn the_first_right_response_holds() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"123456");
        relay(&mut q, &pending);
        let right = response_for(&pending, *b"123456");

        q.respond(&right, response_txid(0), paid(1), height(10));
        q.respond(&right, response_txid(0), paid(2), height(11));
        assert_eq!(q.take_responses()[0].1.paid, paid(1));

        // Refused by the law: not consumed, so the next one is held.
        q.respond(&right, response_txid(0), paid(2), height(12));
        assert_eq!(q.take_responses()[0].1.paid, paid(2));
    }

    /// One entry per transition; a repeat shares it; six wrong
    /// responses retire it; a hit burns once.
    #[test]
    fn a_challenge_survives_a_repeat_and_retires_at_six() {
        let mut q = OtpQueue::new();

        // A first request opens one entry for its transition.
        let check_in = challenge(update("alice"), *b"111111");
        let pending = q.admit(check_in.clone());

        // A repeat request receives the same entry — same code.
        let again = q.admit(challenge(update("alice"), *b"222222"));
        assert_eq!(again.code, pending.code);
        assert!(q.relayed(&pending));

        // A different transition opens its own entry, its own code.
        let other = q.admit(challenge(release("alice"), *b"333333"));
        assert!(q.relayed(&other));
        assert_ne!(other.code, pending.code);

        // Five wrong responses against the check-in are tolerated: its
        // right code still answers.
        for n in 1..MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            q.respond(
                &response_for(&pending, wrong),
                response_txid(0),
                paid(0),
                height(10),
            );
        }
        assert_eq!(q.state_of(&pending), Some(ChallengeState::Relayed));
        let right = response_for(&pending, *b"111111");
        q.respond(&right, response_txid(0), paid(0), height(10));
        let taken = q.take_responses();
        assert_eq!(taken.len(), 1);
        let answered = &taken[0].0;

        // The hit burns exactly once — and only the entry it answered.
        assert!(q.consume(answered));
        q.respond(&right, response_txid(0), paid(0), height(11));
        assert!(q.take_responses().is_empty());
        assert_eq!(q.awaiting().collect::<Vec<_>>(), [other.request.name()]);

        // Six wrong responses retire the entry they name, and only it.
        for n in 1..=MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            q.respond(
                &response_for(&other, wrong),
                response_txid(0),
                paid(0),
                height(11),
            );
        }
        q.respond(
            &response_for(&other, *b"333333"),
            response_txid(0),
            paid(0),
            height(11),
        );
        assert!(q.take_responses().is_empty());
        assert_eq!(q.awaiting().count(), 0);
    }

    /// Only `prune` expires a challenge, and it takes the response with it.
    #[test]
    fn prune_is_owner_invoked() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"123456");
        relay(&mut q, &pending);

        let response = response_for(&pending, *b"123456");
        q.respond(&response, response_txid(0), paid(0), height(10));
        q.prune(t0() + Duration::seconds(D_OTP + 1));
        assert!(q.take_responses().is_empty());
        assert_eq!(q.state_of(&pending), None);
    }

    /// An unrelayed entry is neither answered nor burned; a stranger's
    /// response is ignored.
    #[test]
    fn respond_never_burns_an_unrelayed_entry() {
        let mut q = OtpQueue::new();
        let pending = challenge(update("alice"), *b"123456");
        q.admit(pending.clone());

        q.respond(
            &response_for(&pending, *b"123456"),
            response_txid(0),
            paid(0),
            height(10),
        );
        assert!(q.take_responses().is_empty());
        assert!(!q.consume(&pending));
        assert_eq!(q.unrelayed().len(), 1);

        let stranger = challenge(update("bob"), *b"654321");
        q.respond(
            &response_for(&stranger, *b"654321"),
            response_txid(0),
            paid(0),
            height(10),
        );
        assert!(q.take_responses().is_empty());
        assert_eq!(q.state_of(&stranger), None);
    }
}
