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


}

/// An issued, pending challenge.
#[derive(Clone)]
pub struct OtpRequest {
    pub challenge: Challenge,
    pub tip_rcm: NameCommitment,
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
        let challenge = Challenge {
            code: code.clone(),
            name: name.clone(),
            action,
            term,
            ua: ua.clone(),
        };
        (
            challenge.clone(),
            Self {
                challenge,
                tip_rcm,
                expires_at: mtp_now + Duration::seconds(D_OTP),
            },
        )
    }
}

/// Issued challenges, in order, plus a rate-limit ledger for liveness
/// challenges.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<(OtpRequest, ChallengeStatus)>,
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
        self.challenges.push((req, ChallengeStatus::Relayed));
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
        self.challenges.retain(|(request, status)| {
            *status != ChallengeStatus::Closed && mtp < request.expires_at
        });
        self.challenges.iter().any(|(request, status)| {
            (*status == ChallengeStatus::Relayed || *status == ChallengeStatus::AwaitingResponse)
                && request.challenge.name == *name
                && request.challenge.action == action
                && request.challenge.ua == *ua
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
        self.challenges.retain(|(request, status)| {
            *status != ChallengeStatus::Closed && mtp < request.expires_at
        });
        self.challenges
            .iter()
            .find(|(request, status)| {
                *status != ChallengeStatus::Closed
                    && request.challenge.name == returned.name
                    && request.challenge.action == returned.action
                    && request.challenge.ua == returned.ua
                    && request.tip_rcm == tip_rcm
                    && bool::from(request.challenge.code.0.ct_eq(&returned.code.0))
            })
            .map(|(request, _)| request.clone())
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
        // Expired or closed entries never match.
        self.challenges.retain(|(req, status)| *status != ChallengeStatus::Closed && mtp < req.expires_at);
        let Some(provided_code) = OtpCode::from_digits(provided) else {
            return false;
        };
        for i in 0..self.challenges.len() {
            let (req, status) = &self.challenges[i];
            if req.challenge.name == *name
                && req.challenge.action == action
                && &req.challenge.ua == ua
                && req.tip_rcm == tip_rcm
                && mtp < req.expires_at
                && bool::from(req.challenge.code.0.ct_eq(&provided_code.0))
            {
                self.challenges[i].1 = ChallengeStatus::Closed;
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
        assert_eq!(challenge.code, pending.challenge.code);
        assert_eq!(challenge.name, pending.challenge.name);
        assert_eq!(challenge.action, pending.challenge.action);
        assert_eq!(challenge.ua, pending.challenge.ua);
        // The pending alone carries the expiry and the term (now embedded in challenge).
        assert_eq!(
            pending.expires_at,
            Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap()
        );
        assert_eq!(pending.challenge.term, Some(Term::Years(1)));
        assert_eq!(pending.tip_rcm, rcm);
    }






}
