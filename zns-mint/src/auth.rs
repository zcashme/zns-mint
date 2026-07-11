//! In-band OTP authorization policy for update/release requests.
//!
//! OTPs are transported by shielded memos:
//!
//! 1. user -> Treasury: `ZNS:update:<name>:<ua>` or `ZNS:release:<name>:<ua>`
//! 2. Treasury -> current controller: `ZNS:otp:<name>:<verb>:<ua>:<otp>`
//! 3. user -> Treasury: same request with `:<otp>` appended
use std::collections::HashMap;

use rand::{rngs::OsRng, RngCore};

use crate::mint::Action;

/// OTPs are scoped to the exact requested transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OtpKey {
    pub name: String,
    pub action: Action,
    pub ua: String,
}

impl OtpKey {
    pub fn new(name: &str, action: Action, ua: &str) -> Self {
        Self {
            name: name.to_string(),
            action,
            ua: ua.to_string(),
        }
    }
}
use zcash_protocol::consensus::BlockHeight;

pub struct OtpEntry {
    pub otp: String,
    pub expires_at: BlockHeight,
}

pub struct OtpStore {
    store: HashMap<OtpKey, OtpEntry>,
}

impl OtpStore {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    /// Issues a new highly secure 256-bit hex OTP, valid for 50 blocks.
    pub fn issue(&mut self, key: OtpKey, current_height: BlockHeight) -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let otp = hex::encode(bytes);

        self.store.insert(key, OtpEntry {
            otp: otp.clone(),
            expires_at: current_height + 50,
        });
        
        otp
    }

    /// Verifies and burns the OTP if it is valid.
    pub fn verify(&mut self, key: &OtpKey, otp: &str, current_height: BlockHeight) -> bool {
        self.prune(current_height);

        if let Some(entry) = self.store.get(key) {
            if entry.otp == otp {
                self.store.remove(key); // Burn it!
                return true;
            }
        }
        false
    }

    /// Removes expired OTPs to prevent memory exhaustion.
    pub fn prune(&mut self, current_height: BlockHeight) {
        self.store.retain(|_, entry| u32::from(entry.expires_at) >= u32::from(current_height));
    }
}
