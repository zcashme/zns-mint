//! OTP auth for locked names.
//!
use rand::Rng;
use subtle::ConstantTimeEq;
use time::Timestamp;
use zeroize::Zeroize;

use crate::mint::{Action, Challenge, Name, NameCommitment, UnifiedAddress};

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
    pub tip_rcm: NameCommitment,
    pub code: OtpCode,
    pub expires_at: Timestamp,
    /// Extension the sentence omits.
    pub extend_years: Option<u64>,
}

/// Issued challenges, in order.
#[derive(Clone)]
pub struct OtpQueue(Vec<OtpRequest>);

impl Default for OtpQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpQueue {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Issues a challenge, no checks.
    pub fn issue(&mut self, req: OtpRequest) {
        self.0.push(req);
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
        self.0.retain(|request| mtp < request.expires_at);
        self.0.iter().any(|request| {
            request.name == *name
                && request.action == action
                && request.ua == *ua
                && request.tip_rcm == tip_rcm
        })
    }

    /// The challenge a return closes.
    pub fn awaiting(&mut self, returned: &Challenge, mtp: Timestamp) -> Option<OtpRequest> {
        self.0.retain(|request| mtp < request.expires_at);
        self.0
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
        self.0.retain(|req| mtp < req.expires_at);
        let Some(provided_code) = OtpCode::from_digits(provided) else {
            return false;
        };
        for i in 0..self.0.len() {
            let req = &self.0[i];
            if req.name == *name
                && req.action == action
                && &req.ua == ua
                && req.tip_rcm == tip_rcm
                && mtp < req.expires_at
                && bool::from(req.code.0.ct_eq(&provided_code.0))
            {
                self.0.remove(i);
                return true;
            }
        }
        false
    }
}

/// The echo's fee, relayed.
pub fn required_relay_value<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    target_height: zcash_protocol::consensus::BlockHeight,
) -> zcash_protocol::value::Zatoshis {
    use zcash_client_backend::fees::StandardFeeRule;
    use zcash_primitives::transaction::fees::FeeRule as _;

    StandardFeeRule::Zip317
        .fee_required(
            network,
            target_height,
            std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            2,
        )
        .expect("ZIP-317 fee for two Ironwood actions is representable")
}
