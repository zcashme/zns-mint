//! OTP challenge machinery for ZNS name transitions.
//!
//! Kernel-level state shared by both authorities: `PendingOtps` is a field of
//! [`crate::mint::OperationalState`], the Registry's `authorize_update`/
//! `authorize_release` consume challenges from it, and the Treasury's OTP
//! relay delivers the codes it generates. Also home to the OTP relay memo
//! codec (`ZNS:otp:<otp>:<name>:<verb>:<ua>`).

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zcash_protocol::consensus::BlockHeight;
use zeroize::Zeroize;

use crate::mint::{Action, Name, NameCommitment, UnifiedAddress};
use crate::mint::registry::Registry;

// ---------------------------------------------------------------------------
// OTP challenge state
// ---------------------------------------------------------------------------

/// OTPs are scoped to the exact requested transition.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChallengeKey {
    name: Name,
    action: Action,
    ua: UnifiedAddress,
    record_commitment: [u8; 32],
}

impl fmt::Debug for ChallengeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeKey(<redacted>)")
    }
}

impl ChallengeKey {
    pub fn new(
        name: Name,
        action: Action,
        ua: UnifiedAddress,
        record_commitment: NameCommitment,
    ) -> Self {
        Self {
            name,
            action,
            ua,
            record_commitment: record_commitment.to_bytes(),
        }
    }

    fn matches_registry(&self, registry: &Registry) -> bool {
        registry
            .record(&self.name)
            .is_some_and(|record| record.commitment.to_bytes() == self.record_commitment)
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OtpSecret([u8; 16]);

/// A newly issued OTP held only long enough to construct its relay memo.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OtpCode([u8; 16]);

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpCode(<redacted>)")
    }
}

impl OtpCode {
    /// Generates a new OTP without recording it as deliverable.
    ///
    /// The orchestrator records the code only after the relay transaction has
    /// been assembled and definitively accepted for broadcast.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn lowercase_hex(&self) -> [u8; 32] {
        let mut encoded = [0u8; 32];
        for (index, byte) in self.0.iter().copied().enumerate() {
            let hi = byte >> 4;
            let lo = byte & 0x0f;
            // Constant-time hex encoding to avoid cache-timing side-channels.
            // If n < 10, (n + 6) >> 4 is 0. If n >= 10, it's 1.
            // We add 48 (b'0') for 0..9, and 48 + 39 = 87 (b'a' - 10) for 10..15.
            encoded[index * 2] = hi + 48 + (((hi + 6) >> 4) * 39);
            encoded[index * 2 + 1] = lo + 48 + (((lo + 6) >> 4) * 39);
        }
        encoded
    }

    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 16] {
        self.0
    }

    /// Constructs a code from raw bytes. Test-only: the mint's only
    /// production constructor is [`OtpCode::generate`].
    #[cfg(test)]
    pub fn for_test(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

pub struct OtpEntry {
    otp: OtpSecret,
    expires_at: BlockHeight,
}

pub struct PendingOtps {
    pending: HashMap<ChallengeKey, OtpEntry>,
    /// Challenges currently reserved by an in-flight OTP relay transaction.
    /// The orchestrator owns the lifecycle: reserve when the relay is queued,
    /// release on confirm/fail/rewind. A challenge can be issued (in `pending`)
    /// without being reserved.
    reserved: BTreeSet<ChallengeKey>,
}

impl Default for PendingOtps {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingOtps {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            reserved: BTreeSet::new(),
        }
    }

    /// Reserve a challenge for an in-flight OTP relay transaction.
    ///
    /// Returns `true` if the challenge was free and is now reserved; returns
    /// `false` if another relay is already in flight for it.
    pub fn reserve_challenge(&mut self, key: &ChallengeKey) -> bool {
        self.reserved.insert(key.clone())
    }

    /// Release a previously reserved challenge.
    pub fn release_challenge(&mut self, key: &ChallengeKey) {
        self.reserved.remove(key);
    }

    /// True if the challenge is currently reserved by an in-flight relay.
    pub fn is_challenge_reserved(&self, key: &ChallengeKey) -> bool {
        self.reserved.contains(key)
    }

    /// All currently reserved challenges.
    pub fn reserved_challenges(&self) -> &BTreeSet<ChallengeKey> {
        &self.reserved
    }

    /// Release every challenge in `keys` from the reserved set.
    pub fn release_all(&mut self, keys: &BTreeSet<ChallengeKey>) {
        self.reserved.retain(|key| !keys.contains(key));
    }

    /// Discards every relay reservation and deliverable OTP bound to a name
    /// tip that is no longer canonical after a reorg.
    pub fn invalidate_changed_tips(&mut self, registry: &Registry) {
        self.pending.retain(|key, _| key.matches_registry(registry));
        self.reserved.retain(|key| key.matches_registry(registry));
    }

    /// Issues a new highly secure 128-bit hex OTP, valid for the configured
    /// number of blocks from `current_height`.
    pub fn record_issued(
        &mut self,
        key: ChallengeKey,
        otp: &OtpCode,
        current_height: BlockHeight,
    ) {
        self.pending.insert(
            key,
            OtpEntry {
                otp: OtpSecret(otp.0),
                expires_at: current_height + Self::OTP_VALIDITY_BLOCKS,
            },
        );
    }

    /// Verifies and burns the OTP if it is valid.
    pub fn verify(
        &mut self,
        key: &ChallengeKey,
        provided: &[u8; 16],
        current_height: BlockHeight,
    ) -> bool {
        self.prune(current_height);

        if let Some(entry) = self.pending.get(key) {
            if bool::from(entry.otp.0.ct_eq(provided)) {
                self.pending.remove(key); // Burn it!
                return true;
            }
        }
        false
    }

    /// Removes expired OTPs to prevent memory exhaustion.
    /// Prunes expired OTPs and returns how many were removed.
    pub fn prune(&mut self, current_height: BlockHeight) -> usize {
        let before = self.pending.len();
        self.pending
            .retain(|_, entry| u32::from(entry.expires_at) >= u32::from(current_height));
        before - self.pending.len()
    }

    /// Whether an unexpired OTP exists for this challenge.
    pub fn contains(&self, key: &ChallengeKey) -> bool {
        self.pending.contains_key(key)
    }

    /// Configured OTP validity window, in blocks.
    ///
    /// 24 blocks ≈ 30 minutes at 75s block time.
    pub const OTP_VALIDITY_BLOCKS: u32 = 24;
}

// ---------------------------------------------------------------------------
// OTP relay memo encoding
// ---------------------------------------------------------------------------

/// Returns the canonical verb string for an action in the OTP relay grammar.
///
/// Only `Update` and `Release` are valid relay actions — claims do not use OTPs.
fn verb_str(action: Action) -> Option<&'static str> {
    match action {
        Action::Update => Some("update"),
        Action::Release => Some("release"),
        Action::Claim => None,
    }
}

/// Whether the fixed-width OTP relay form fits in one Zcash memo.
pub fn otp_relay_memo_fits(name: &Name, action: Action, ua: &UnifiedAddress) -> bool {
    let Some(verb) = verb_str(action) else {
        return false;
    };
    8usize
        .checked_add(name.as_str().len())
        .and_then(|length| length.checked_add(1 + verb.len()))
        .and_then(|length| length.checked_add(1 + ua.as_str().len()))
        .and_then(|length| length.checked_add(1 + 32))
        .is_some_and(|length| length <= 512)
}

/// Encodes an OTP relay memo: `ZNS:otp:<otp>:<name>:<verb>:<ua>`, zero-padded
/// to 512 bytes.
///
/// This memo is sent from the Treasury to the current controller's address so
/// only they can decrypt it and echo the OTP back. Returns `None` if the action
/// is `Claim` (claims don't use OTPs) or if the encoded text exceeds 512 bytes.
pub fn encode_otp_relay_memo(
    name: &Name,
    action: Action,
    ua: &UnifiedAddress,
    otp: &OtpCode,
) -> Option<[u8; 512]> {
    let verb = verb_str(action)?;
    if !otp_relay_memo_fits(name, action, ua) {
        return None;
    }

    let mut memo = [0u8; 512];
    let mut otp_hex = otp.lowercase_hex();
    let mut offset = 0usize;
    for field in [
        b"ZNS:otp:".as_slice(),
        otp_hex.as_slice(),
        b":".as_slice(),
        name.as_str().as_bytes(),
        b":".as_slice(),
        verb.as_bytes(),
        b":".as_slice(),
        ua.as_str().as_bytes(),
    ] {
        let end = offset + field.len();
        memo[offset..end].copy_from_slice(field);
        offset = end;
    }
    otp_hex.zeroize();
    Some(memo)
}
