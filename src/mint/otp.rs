//! OTP authentication for ZNS locked-name transitions.
//!
use rand::Rng;
use subtle::ConstantTimeEq;
use time::Timestamp;
use zeroize::Zeroize;

use crate::mint::{Action, Name, NameCommitment, UnifiedAddress};

/// OTP validity window (30 minutes in seconds; §5.3: D_OTP)
pub const D_OTP: i64 = 1800;

/// A six-digit one-time passcode for update/release authorization.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct OtpCode(u32);

impl std::fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OtpCode(REDACTED)")
    }
}

impl OtpCode {
    /// Generates a new uniformly random six-digit decimal OTP.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen_range(0..1_000_000))
    }

    /// Returns the six ASCII decimal digits, including leading zeroes.
    pub fn digits(&self) -> [u8; 6] {
        let mut digits = [0u8; 6];
        let mut n = self.0;
        for i in (0..6).rev() {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        digits
    }

    /// Parses six ASCII decimal digits into an OTP.
    pub fn from_digits(digits: &[u8; 6]) -> Option<Self> {
        let s = std::str::from_utf8(digits).ok()?;
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<u32>().ok().map(Self)
    }

    /// Constructs a code from raw digits. Test-only: the mint's only
    /// production constructor is [`OtpCode::generate`].
    #[cfg(test)]
    pub fn for_test(digits: [u8; 6]) -> Self {
        Self::from_digits(&digits).expect("test digits are valid")
    }

    /// Reveals the digits. Test-only: registry tests push queue entries for
    /// codes the relay just generated, and compare them at verification.
    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 6] {
        self.digits()
    }
}

/// A pending OTP bound to one exact live Name Note and the requested action.
#[derive(Clone)]
pub struct OtpRequest {
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    pub tip_rcm: NameCommitment,
    pub code: OtpCode,
    pub expires_at: Timestamp,
}

/// A time ordered list of pending OTP requests.
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

    /// Appends a pending OTP request. No checks — every accepted relay
    /// gets an entry. Multiple entries per name are allowed.
    pub fn push(&mut self, req: OtpRequest) {
        self.0.push(req);
    }

    /// Whether the exact live Name Note already has an unexpired challenge
    /// for this action and target. Expired entries are discarded here so a
    /// later block may issue a fresh challenge.
    pub fn has_live(
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

    /// Expired entries are pruned on every scan.
    pub fn verify_and_burn(
        &mut self,
        name: &Name,
        action: Action,
        ua: &UnifiedAddress,
        tip_rcm: NameCommitment,
        provided: &[u8; 6],
        mtp: Timestamp,
    ) -> bool {
        // Expire first: entries past their TTL never match and are dropped.
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

/// Value delivered by a relay so its controller can pay for the echo.
pub fn required_relay_value<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    target_height: zcash_protocol::consensus::BlockHeight,
) -> zcash_protocol::value::Zatoshis {
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    FeeRule::standard()
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
