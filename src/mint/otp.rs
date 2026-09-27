//! OTP auth for locked names.
//!
use rand::Rng;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
use zcash_primitives::transaction::TxId;
use zeroize::Zeroize;

use crate::mint::{Action, Challenge, Name, NameCommitment, Term, UnifiedAddress};

/// Thirty minutes; §5.3: D_OTP.
pub const D_OTP: i64 = 1800;

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
    challenges: Vec<(OtpRequest, ChallengeState, TxId)>,
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

    /// Admits a request once per transaction. The same txid is seen at
    /// mempool admission and block confirmation; confirmation reuses its
    /// queue entry instead of creating another challenge.
    pub fn admit_request(&mut self, request: OtpRequest, txid: TxId) -> OtpRequest {
        if let Some((existing, _, _)) = self
            .challenges
            .iter()
            .find(|(_, _, existing_txid)| *existing_txid == txid)
        {
            return existing.clone();
        }
        self.challenges
            .push((request.clone(), ChallengeState::Requested, txid));
        request
    }

    /// Removes an invalidated mempool request, if its challenge has not
    /// already been sent.
    pub fn invalidate(&mut self, txid: TxId) {
        self.challenges.retain(|(_, state, existing_txid)| {
            *existing_txid != txid || matches!(state, ChallengeState::Relayed)
        });
    }

    /// Marks a request as relayed after the node accepts its challenge.
    pub fn challenge_issued(&mut self, request: &OtpRequest) -> bool {
        if let Some((_, state, _)) = self.challenges.iter_mut().find(|(existing, _, _)| {
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

    pub fn is_relayed(&self, request: &OtpRequest) -> bool {
        self.challenges.iter().any(|(existing, state, _)| {
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
    pub fn requested(&self) -> Vec<OtpRequest> {
        self.challenges
            .iter()
            .filter(|(_, state, _)| matches!(state, ChallengeState::Requested))
            .map(|(request, _, _)| request.clone())
            .collect()
    }

    /// Drops expired challenges. Owner-invoked: the run loop prunes at
    /// the top of every wake-up, before any lane matches the store.
    pub fn prune(&mut self, mtp: Timestamp) {
        self.challenges
            .retain(|(request, _, _)| mtp < request.expires_at);
    }

    /// The pending challenge this return matches at `tip_rcm`, paired
    /// with the burn key for [`OtpQueue::respond`]. Without the
    /// commitment binding, a six-digit code collision across two live
    /// challenges could let one echo resolve to the wrong pending.
    /// Freshness is the owner's `prune`, not this scan.
    pub fn awaiting(
        &self,
        returned: &Challenge,
        tip_rcm: NameCommitment,
    ) -> Option<(TxId, OtpRequest)> {
        self.challenges
            .iter()
            .find(|(request, state, _)| {
                matches!(state, ChallengeState::Relayed)
                    && request.name == returned.name
                    && request.action == returned.action
                    && request.ua == returned.ua
                    && request.tip_rcm == tip_rcm
                    && bool::from(request.code.0.ct_eq(&returned.code.0))
            })
            .map(|(req, _, txid)| (*txid, req.clone()))
    }

    /// Burns a relayed challenge once, by the key [`OtpQueue::awaiting`]
    /// handed out: the entry is removed, so no later echo can claim it.
    /// Returns whether an entry was removed.
    pub fn respond(&mut self, txid: TxId) -> bool {
        let before = self.challenges.len();
        self.challenges
            .retain(|(_, _, existing_txid)| *existing_txid != txid);
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

        q.admit_request(
            OtpRequest {
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
        q.admit_request(
            OtpRequest {
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

        let echo = Challenge {
            code: shared.clone(),
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
        };

        // The echo picked up at the new tip resolves to the new-tip
        // pending — its term is Years(5), not Years(1).
        let (_, matched) = q.awaiting(&echo, new_rcm).expect("new-tip pending");
        assert_eq!(matched.term, Some(Term::Years(5)));
        assert_eq!(matched.tip_rcm, new_rcm);

        // And re-scoping to the old commitment resolves to the old
        // pending, not the new one — the two are strictly separated.
        let (_, matched) = q.awaiting(&echo, old_rcm).expect("old-tip pending");
        assert_eq!(matched.term, Some(Term::Years(1)));
        assert_eq!(matched.tip_rcm, old_rcm);

        // A commitment that never issued a challenge finds nothing,
        // even though the code and other fields all match a live entry.
        let stale = commitment(3);
        assert!(q.awaiting(&echo, stale).is_none());
    }

    /// A relayed challenge burns exactly once: `awaiting` finds it,
    /// `respond` removes it, and no later echo — even the identical
    /// one — can claim it again.
    #[test]
    fn respond_burns_once_and_then_nothing() {
        let mut q = OtpQueue::new();
        let alice = test_name("alice");
        let ua = mainnet_ua();
        let rcm = commitment(1);
        let t0 = Timestamp::from_seconds(1_700_000_000).unwrap();
        let code = OtpCode::for_test(*b"123456");

        q.admit_request(
            OtpRequest {
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

        let echo = Challenge {
            code: code.clone(),
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
        };

        let (key, matched) = q.awaiting(&echo, rcm).expect("live pending");
        assert_eq!(matched.tip_rcm, rcm);

        assert!(q.respond(key));
        assert!(q.awaiting(&echo, rcm).is_none());
        assert!(!q.respond(key));
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

        q.admit_request(
            OtpRequest {
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

        let echo = Challenge {
            code: code.clone(),
            name: alice.clone(),
            action: Action::Update,
            ua: ua.clone(),
        };

        assert!(q.awaiting(&echo, rcm).is_some());
        q.prune(t0 + Duration::seconds(D_OTP + 1));
        assert!(q.awaiting(&echo, rcm).is_none());
    }
}
