//! OTP auth for locked names.
//!
use rand::Rng;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zeroize::Zeroize;

use crate::mint::{Action, Challenge, Name, NameCommitment, Term, UnifiedAddress};

/// Thirty minutes; §5.3: D_OTP.
pub const D_OTP: i64 = 1800;

/// Lifecycle of an issued challenge — explicit state instead of implicit
/// presence/absence in the queue. See #157.
pub enum ChallengeStatus {
    Relayed,
    AwaitingResponse,
    Closed,
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
        Self(rand::thread_rng().gen_range(0..1_000_000))
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

    /// Reveals digits; test-only.
    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 6] {
        self.digits()
    }
}

/// An issued, pending challenge.
#[derive(Clone)]
pub struct OtpRequest {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    pub term: Option<Term>,
    pub tip_rcm: NameCommitment,
    pub code: OtpCode,
    pub expires_at: Timestamp,
}

impl OtpRequest {
    /// A challenge and the pending it arms are born together — one code
    /// in two bodies: the `Challenge` whose memo carries it to the
    /// controller, and this request, which expires it after D_OTP.
    /// Encoding stays with the caller: how a lane answers an
    /// unencodable challenge is lane policy, not birth.
    pub fn pending_challenge(
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
        tip_rcm: NameCommitment,
        term: Option<Term>,
        mtp_now: Timestamp,
    ) -> (Challenge, Self) {
        let code = OtpCode::generate();
        (
            Challenge {
                code: code.clone(),
                name: name.clone(),
                action,
                ua: ua.clone(),
            },
            Self {
                name: name.clone(),
                action,
                ua: ua.clone(),
                term,
                tip_rcm,
                code,
                expires_at: mtp_now + Duration::seconds(D_OTP),
            },
        )
    }
}

/// Issued challenges, in order, plus a rate-limit ledger for liveness
/// challenges.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<OtpRequest>,
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

    /// Issues a challenge, no checks.
    pub fn issue(&mut self, req: OtpRequest) {
        self.challenges.push(req);
    }

    /// A challenge already issued?
    pub fn pending(
        &mut self,
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
        tip_rcm: NameCommitment,
        mtp: Timestamp,
    ) -> bool {
        self.challenges.retain(|request| mtp < request.expires_at);
        self.challenges.iter().any(|request| {
            request.name == *name
                && request.action == action
                && request.ua == *ua
                && request.tip_rcm == tip_rcm
        })
    }

    /// The pending challenge this return matches at `tip_rcm`. Without
    /// the commitment binding a six-digit code collision across two
    /// live challenges could let `awaiting` return one pending while
    /// `accept` binds the other.
    pub fn awaiting(
        &mut self,
        returned: &Challenge,
        tip_rcm: NameCommitment,
        mtp: Timestamp,
    ) -> Option<OtpRequest> {
        self.challenges.retain(|request| mtp < request.expires_at);
        self.challenges
            .iter()
            .find(|request| {
                request.name == returned.name
                    && request.action == returned.action
                    && request.ua == returned.ua
                    && request.tip_rcm == tip_rcm
                    && bool::from(request.code.0.ct_eq(&returned.code.0))
            })
            .cloned()
    }

    /// Accepts a returned OTP once.
    pub fn accept(
        &mut self,
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
        tip_rcm: NameCommitment,
        provided: &[u8; 6],
        mtp: Timestamp,
    ) -> bool {
        // Expired entries never match.
        self.challenges.retain(|req| mtp < req.expires_at);
        let Some(provided_code) = OtpCode::from_digits(provided) else {
            return false;
        };
        for i in 0..self.challenges.len() {
            let req = &self.challenges[i];
            if req.name == *name
                && req.action == action
                && &req.ua == ua
                && req.tip_rcm == tip_rcm
                && mtp < req.expires_at
                && bool::from(req.code.0.ct_eq(&provided_code.0))
            {
                self.challenges.remove(i);
                return true;
            }
        }
        false
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

        let (challenge, pending) = OtpRequest::pending_challenge(
            &alice,
            Action::Update,
            &ua,
            rcm,
            Some(Term::Years(1)),
            t0,
        );

        // One code in two bodies — the invariant the run loop used to
        // maintain by hand, twice.
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

    #[test]
    fn liveness_ledger_marks_and_clears_by_cooldown() {
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let cooldown = Duration::seconds(3600);

        // Fresh record: no throttle.
        assert!(!q.liveness_recently_issued(&alice, rcm, t0, cooldown));

        // Marked: throttle holds through the cooldown window.
        q.mark_liveness_issued(alice.clone(), rcm, t0);
        assert!(q.liveness_recently_issued(&alice, rcm, t0, cooldown));
        assert!(q.liveness_recently_issued(&alice, rcm, t0 + Duration::seconds(1_800), cooldown));

        // Exactly at cooldown: released (the guard is strict `<`).
        assert!(!q.liveness_recently_issued(&alice, rcm, t0 + Duration::seconds(3_600), cooldown));
    }

    #[test]
    fn liveness_ledger_scopes_by_commitment() {
        // A fresh update produces a new NameCommitment and must NOT inherit
        // the previous record's throttle — the mint may challenge the new
        // record immediately.
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let old_rcm = commitment(1);
        let new_rcm = commitment(2);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let cooldown = Duration::seconds(3600);

        q.mark_liveness_issued(alice.clone(), old_rcm, t0);
        assert!(q.liveness_recently_issued(&alice, old_rcm, t0, cooldown));
        assert!(!q.liveness_recently_issued(&alice, new_rcm, t0, cooldown));
    }

    #[test]
    fn liveness_ledger_scopes_by_name() {
        // Different names never share a throttle entry.
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let bob = test_name("bob");
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let cooldown = Duration::seconds(3600);

        q.mark_liveness_issued(alice.clone(), rcm, t0);
        assert!(!q.liveness_recently_issued(&bob, rcm, t0, cooldown));
    }

    #[test]
    fn liveness_ledger_is_independent_of_challenge_queue() {
        // The rate-limit ledger is not the OTP-code queue: `pending` and
        // `accept` are unaffected by `mark_liveness_issued`.
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let cooldown = Duration::seconds(3600);

        q.mark_liveness_issued(alice.clone(), rcm, t0);
        // Ledger throttles, but the code queue is empty.
        assert!(q.liveness_recently_issued(&alice, rcm, t0, cooldown));
        // No pending challenge for this record.
        let ua_str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";
        let ua = match zcash_keys::address::Address::decode(
            &zcash_protocol::consensus::MAIN_NETWORK,
            ua_str,
        ) {
            Some(zcash_keys::address::Address::Unified(u)) => u,
            _ => panic!("test UA"),
        };
        assert!(!q.pending(&alice, Action::Update, &ua, rcm, t0));
    }

    fn mainnet_ua() -> UnifiedAddress {
        let s = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";
        match zcash_keys::address::Address::decode(&zcash_protocol::consensus::MAIN_NETWORK, s) {
            Some(zcash_keys::address::Address::Unified(u)) => u,
            _ => panic!("test UA"),
        }
    }

    /// Two challenges share a code across a commitment change:
    /// `awaiting` must resolve by `tip_rcm`, not just by code.
    #[test]
    fn awaiting_scopes_by_tip_rcm() {
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let ua = mainnet_ua();
        let old_rcm = commitment(1);
        let new_rcm = commitment(2);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let shared = OtpCode::for_test(*b"123456");

        q.issue(OtpRequest {
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
            term: Some(Term::Years(1)),
            tip_rcm: old_rcm,
            code: shared.clone(),
            expires_at: t0 + Duration::seconds(D_OTP),
        });
        q.issue(OtpRequest {
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
            term: Some(Term::Years(5)),
            tip_rcm: new_rcm,
            code: shared.clone(),
            expires_at: t0 + Duration::seconds(D_OTP),
        });

        let echo = Challenge {
            code: shared.clone(),
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
        };

        // The echo picked up at the new tip resolves to the new-tip
        // pending — its term is Years(5), not Years(1).
        let matched = q.awaiting(&echo, new_rcm, t0).expect("new-tip pending");
        assert_eq!(matched.term, Some(Term::Years(5)));
        assert_eq!(matched.tip_rcm, new_rcm);

        // And re-scoping to the old commitment resolves to the old
        // pending, not the new one — the two are strictly separated.
        let matched = q.awaiting(&echo, old_rcm, t0).expect("old-tip pending");
        assert_eq!(matched.term, Some(Term::Years(1)));
        assert_eq!(matched.tip_rcm, old_rcm);

        // A commitment that never issued a challenge finds nothing,
        // even though the code and other fields all match a live entry.
        let stale = commitment(3);
        assert!(q.awaiting(&echo, stale, t0).is_none());
    }
}
