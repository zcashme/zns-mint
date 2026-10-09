//! OTP auth for locked names.
//!
use rand::Rng;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zcash_primitives::transaction::TxId;
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
        Self(rand::rngs::OsRng.gen_range(0..1_000_000))
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
}

/// Lifecycle state for a pending challenge entry.
#[derive(Clone, PartialEq, Eq)]
pub enum ChallengeState {
    /// Seen, its challenge memo not yet accepted by the node.
    Requested,
    /// The node accepted the challenge memo; an OTP response may arrive.
    Relayed,
}

/// Issued challenges, in order.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<(OtpChallenge, ChallengeState, TxId, Attempts)>,
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

    /// One live entry per pending transition: a repeat request
    /// receives the existing entry, stamped with the newest txid.
    pub fn admit(&mut self, request: OtpChallenge, txid: TxId) -> OtpChallenge {
        if let Some((existing, _, entry_txid, _)) =
            self.challenges.iter_mut().find(|(existing, _, _, _)| {
                existing.name == request.name
                    && existing.action == request.action
                    && existing.ua == request.ua
                    && existing.tip_rcm == request.tip_rcm
            })
        {
            *entry_txid = txid;
            return existing.clone();
        }
        self.challenges.push((
            request.clone(),
            ChallengeState::Requested,
            txid,
            Attempts::default(),
        ));
        request
    }

    /// Removes a challenge whose request transaction was invalidated,
    /// unless already relayed. Follows the newest backing txid.
    pub fn invalidate(&mut self, txid: TxId) {
        self.challenges.retain(|(_, state, existing_txid, _)| {
            *existing_txid != txid || matches!(state, ChallengeState::Relayed)
        });
    }

    /// Marks a request as relayed after the node accepts its challenge.
    pub fn challenge_issued(&mut self, request: &OtpChallenge) -> bool {
        if let Some((_, state, _, _)) = self.challenges.iter_mut().find(|(existing, _, _, _)| {
            existing.name == request.name
                && existing.action == request.action
                && existing.ua == request.ua
                && existing.term == request.term
                && existing.tip_rcm == request.tip_rcm
                && existing.code == request.code
        }) {
            if matches!(state, ChallengeState::Requested) {
                *state = ChallengeState::Relayed;
                return true;
            }
        }
        false
    }

    pub fn is_relayed(&self, request: &OtpChallenge) -> bool {
        self.challenges.iter().any(|(existing, state, _, _)| {
            existing.name == request.name
                && existing.action == request.action
                && existing.ua == request.ua
                && existing.term == request.term
                && existing.tip_rcm == request.tip_rcm
                && existing.code == request.code
                && matches!(state, ChallengeState::Relayed)
        })
    }

    /// Returns queued requests that still need a challenge submission.
    pub fn requested(&self) -> Vec<OtpChallenge> {
        self.challenges
            .iter()
            .filter(|(_, state, _, _)| matches!(state, ChallengeState::Requested))
            .map(|(request, _, _, _)| request.clone())
            .collect()
    }

    /// Drops expired challenges. The run loop calls this each wake-up.
    pub fn prune(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|(request, _, _, _)| mtp < request.expires_at);
    }

    /// The relayed challenge an echo answers when its code is right;
    /// a wrong code counts one attempt against the transition the
    /// echo names and retires it at [`MAX_ATTEMPTS`].
    pub fn answer(&mut self, returned: &OtpMemo, tip_rcm: NameCommitment) -> Option<OtpChallenge> {
        let index = self.challenges.iter().position(|(request, state, _, _)| {
            matches!(state, ChallengeState::Relayed)
                && request.name == returned.name
                && request.action == returned.action
                && request.ua == returned.ua
                && request.tip_rcm == tip_rcm
        })?;
        let (request, _, _, attempts) = &mut self.challenges[index];
        if bool::from(request.code.0.ct_eq(&returned.code.0)) {
            return Some(request.clone());
        }
        if attempts.count() {
            self.challenges.remove(index);
        }
        None
    }

    /// Consumes the answered challenge: one code, one use. The
    /// transition is the key — a txid can back several challenges,
    /// and consuming one must not evict its neighbors.
    pub fn consume(&mut self, answered: &OtpChallenge) -> bool {
        let before = self.challenges.len();
        self.challenges.retain(|(existing, state, _, _)| {
            !(matches!(state, ChallengeState::Relayed)
                && existing.name == answered.name
                && existing.action == answered.action
                && existing.ua == answered.ua
                && existing.tip_rcm == answered.tip_rcm)
        });
        self.challenges.len() != before
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

    fn test_txid(seed: u8) -> TxId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        TxId::from_bytes(bytes)
    }

    fn transition_challenge(seed: u8, code: [u8; 6]) -> OtpChallenge {
        OtpChallenge {
            name: test_name("alice"),
            action: Action::Update,
            ua: mainnet_ua(),
            term: None,
            tip_rcm: commitment(seed),
            code: OtpCode::for_test(code),
            expires_at: Timestamp::from_seconds(1_700_000_000).unwrap() + Duration::seconds(D_OTP),
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
        let ua = match zcash_keys::address::Address::decode(
            &zcash_protocol::consensus::MAIN_NETWORK,
            "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k",
        ) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        };
        let alice = test_name("alice");
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();

        let pending = OtpChallenge::issue(alice, Action::Update, ua, rcm, Some(Term::Years(1)), t0);

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
            Some(zcash_keys::address::Address::Unified(u)) => u,
            _ => panic!("test UA"),
        }
    }

    /// Two challenges share a code across a commitment change:
    /// `answer` must resolve by `tip_rcm`, not just by code.
    #[test]
    fn answer_scopes_by_tip_rcm() {
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let ua = mainnet_ua();
        let old_rcm = commitment(1);
        let new_rcm = commitment(2);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let shared = OtpCode::for_test(*b"123456");

        q.admit(
            OtpChallenge {
                name: alice.clone(),
                action: Action::Update,
                ua: ua.clone(),
                term: Some(Term::Years(1)),
                tip_rcm: old_rcm,
                code: shared.clone(),
                expires_at: t0 + Duration::seconds(D_OTP),
            },
            test_txid(1),
        );
        q.challenges[0].1 = ChallengeState::Relayed;
        q.admit(
            OtpChallenge {
                name: alice.clone(),
                action: Action::Update,
                ua: ua.clone(),
                term: Some(Term::Years(5)),
                tip_rcm: new_rcm,
                code: shared.clone(),
                expires_at: t0 + Duration::seconds(D_OTP),
            },
            test_txid(2),
        );
        q.challenges[1].1 = ChallengeState::Relayed;

        let echo = OtpMemo {
            code: shared.clone(),
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
        };

        // The echo picked up at the new tip resolves to the new-tip
        // pending — its term is Years(5), not Years(1).
        let matched = q.answer(&echo, new_rcm).expect("new-tip pending");
        assert_eq!(matched.term, Some(Term::Years(5)));
        assert_eq!(matched.tip_rcm, new_rcm);

        // And re-scoping to the old commitment resolves to the old
        // pending, not the new one — the two are strictly separated.
        let matched = q.answer(&echo, old_rcm).expect("old-tip pending");
        assert_eq!(matched.term, Some(Term::Years(1)));
        assert_eq!(matched.tip_rcm, old_rcm);

        // A commitment that never issued a challenge finds nothing,
        // even though the code and other fields all match a live entry.
        let stale = commitment(3);
        assert!(q.answer(&echo, stale).is_none());
    }

    /// A relayed challenge burns exactly once: `answer` finds it,
    /// `consume` removes it, and no later echo — even the identical
    /// one — can claim it again.
    #[test]
    fn respond_burns_once_and_then_nothing() {
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let ua = mainnet_ua();
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let code = OtpCode::for_test(*b"123456");

        q.admit(
            OtpChallenge {
                name: alice.clone(),
                action: Action::Update,
                ua: ua.clone(),
                term: Some(Term::Years(1)),
                tip_rcm: rcm,
                code: code.clone(),
                expires_at: t0 + Duration::seconds(D_OTP),
            },
            test_txid(1),
        );
        q.challenges[0].1 = ChallengeState::Relayed;

        let echo = OtpMemo {
            code: code.clone(),
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
        };

        let matched = q.answer(&echo, rcm).expect("live pending");
        assert_eq!(matched.tip_rcm, rcm);

        assert!(q.consume(&matched));
        assert!(q.answer(&echo, rcm).is_none());
        assert!(!q.consume(&matched));
    }

    /// The queue's contract in one walk: one live entry per pending
    /// transition; a repeat request receives it and cannot be retired
    /// by an invalidated earlier request; five wrong echoes are
    /// tolerated and the sixth retires the entry they name, alone;
    /// and a hit burns exactly once.
    #[test]
    fn a_challenge_survives_a_repeat_and_retires_at_six() {
        let mut q = OtpQueue::new();

        // A first request opens one entry for its transition.
        let check_in = transition_challenge(1, *b"111111");
        let pending = q.admit(check_in.clone(), test_txid(1));

        // A repeat request receives the same entry — same code — and
        // moves it to the newest txid: invalidating the first request
        // cannot retire the challenge the second backs. Proven while
        // the entry is still Requested — invalidate removes only
        // Requested entries — by relaying after the invalidation.
        let again = q.admit(transition_challenge(1, *b"222222"), test_txid(2));
        assert_eq!(again.code, pending.code);
        q.invalidate(test_txid(1));
        assert!(q.challenge_issued(&pending));
        assert!(q.is_relayed(&pending));

        // A different transition opens its own entry, its own code —
        // here under the same txid, as one transaction carrying two
        // requests would produce.
        let rebind = transition_challenge(2, *b"333333");
        let other = q.admit(rebind.clone(), test_txid(2));
        assert!(q.challenge_issued(&other));
        assert_ne!(other.code, pending.code);

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
        // the neighbor that shares its txid stands.
        assert!(q.consume(&answered));
        assert!(q.answer(&right, check_in.tip_rcm).is_none());
        assert!(q.is_relayed(&other));

        // Six wrong echoes retire the entry they name, and only it.
        for n in 1..=MAX_ATTEMPTS {
            let wrong: [u8; 6] = format!("{n:06}").as_bytes().try_into().unwrap();
            assert!(q.answer(&echo_for(&other, wrong), rebind.tip_rcm).is_none());
        }
        assert!(q
            .answer(&echo_for(&other, *b"333333"), rebind.tip_rcm)
            .is_none());
    }

    /// Freshness is the owner's prune, not the scans': an expired
    /// challenge still matches until the owner prunes, and prune
    /// alone removes it.
    #[test]
    fn prune_is_owner_invoked() {
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let ua = mainnet_ua();
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let code = OtpCode::for_test(*b"123456");

        q.admit(
            OtpChallenge {
                name: alice.clone(),
                action: Action::Update,
                ua: ua.clone(),
                term: None,
                tip_rcm: rcm,
                code: code.clone(),
                expires_at: t0 + Duration::seconds(D_OTP),
            },
            test_txid(1),
        );
        q.challenges[0].1 = ChallengeState::Relayed;

        let echo = OtpMemo {
            code: code.clone(),
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
        };

        assert!(q.answer(&echo, rcm).is_some());
        q.prune(t0 + Duration::seconds(D_OTP + 1));
        assert!(q.answer(&echo, rcm).is_none());
    }

    /// `consume` burns only relayed challenges: a key to a never-relayed
    /// entry is refused, and the entry stays queued for the relay loop.
    #[test]
    fn respond_never_burns_an_unrelayed_entry() {
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let ua = mainnet_ua();
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();

        let challenge = OtpChallenge {
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
            term: None,
            tip_rcm: rcm,
            code: OtpCode::for_test(*b"123456"),
            expires_at: t0 + Duration::seconds(D_OTP),
        };
        q.admit(challenge.clone(), test_txid(1));
        // Still `Requested`: the challenge memo was never accepted.

        assert!(!q.consume(&challenge));
        assert_eq!(q.requested().len(), 1);
    }
}
