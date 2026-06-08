//! ZNS action kinds and the rcm-chain sentinel — pure domain types.
//!
//! These are the canonical strings and constant that feed the `(ψ, rcm)`
//! derivation. They are defined here, independently of `zns-verify`'s copy: the
//! registry (producer) and the verification kernel (consumer) keep separate
//! implementations of the spec so the two can cross-check each other. The
//! canonical bytes must match the spec (DESIGN §4) and never change without a
//! domain-tag bump.

/// Lifecycle event for a registered name.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// First registration of a name. Has no predecessor in the chain;
    /// `prev_rcm` is [`ZERO_PREV_RCM`].
    Claim,
    /// Rebinds a name to a new UA — both "rotate my own UA" and handing the
    /// name to another party; the protocol does not distinguish them.
    Update,
    /// Terminates a name's chain. The UA field is empty by convention.
    Release,
}

impl Action {
    /// The canonical ASCII bytes for this action, as fed into the derivation.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Action::Claim => b"claim",
            Action::Update => b"update",
            Action::Release => b"release",
        }
    }

    /// Parse the canonical ASCII form (case-sensitive).
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"claim" => Some(Action::Claim),
            b"update" => Some(Action::Update),
            b"release" => Some(Action::Release),
            _ => None,
        }
    }
}

/// The `prev_rcm` for the first action in a name's chain (the CLAIM). A CLAIM
/// has no predecessor, so its `prev_rcm` is the all-zero 32-byte string.
pub const ZERO_PREV_RCM: [u8; 32] = [0u8; 32];
