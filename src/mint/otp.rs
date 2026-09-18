//! OTP auth for locked names.
//!
use std::collections::BTreeMap;

use rand::Rng;
use subtle::ConstantTimeEq;
use time::{Duration, Timestamp};
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

/// Issued challenges, in order, plus a rate-limit ledger for liveness
/// challenges.
#[derive(Clone)]
pub struct OtpQueue {
    challenges: Vec<OtpRequest>,
    liveness_issued: BTreeMap<(Name, [u8; 32]), Timestamp>,
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
            liveness_issued: BTreeMap::new(),
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

    /// The pending challenge this return matches.
    pub fn awaiting(&mut self, returned: &Challenge, mtp: Timestamp) -> Option<OtpRequest> {
        self.challenges.retain(|request| mtp < request.expires_at);
        self.challenges
            .iter()
            .find(|request| {
                request.name == returned.name
                    && request.action == returned.action
                    && request.ua == returned.ua
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

    /// True while a liveness challenge issued for this current record is
    /// still inside its cooldown window. Prunes elapsed entries.
    ///
    /// Independent of `pending`: the OTP code's own TTL is `D_OTP`, but the
    /// rate limit on issuing a *new* code lives here.
    pub fn liveness_recently_issued(
        &mut self,
        name: &Name,
        tip_rcm: NameCommitment,
        mtp: Timestamp,
        cooldown: Duration,
    ) -> bool {
        self.liveness_issued
            .retain(|_, last| mtp - *last < cooldown);
        self.liveness_issued
            .contains_key(&(name.clone(), tip_rcm.to_bytes()))
    }

    /// Records a liveness challenge issuance for rate-limiting. The key is
    /// the current record's `(name, rcm)`; a subsequent accepted update
    /// (new commitment) leaves the old entry stale, and it lapses on the
    /// next `liveness_recently_issued` prune.
    pub fn mark_liveness_issued(&mut self, name: Name, tip_rcm: NameCommitment, mtp: Timestamp) {
        self.liveness_issued.insert((name, tip_rcm.to_bytes()), mtp);
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
        let ua_str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";
        let ua = match zcash_keys::address::Address::decode(
            &zcash_protocol::consensus::MAIN_NETWORK,
            ua_str,
        ) {
            Some(zcash_keys::address::Address::Unified(u)) => u,
            _ => panic!("test UA"),
        };
        assert!(!q.pending(&alice, Action::Update, &ua, rcm, t0));
    }
}
