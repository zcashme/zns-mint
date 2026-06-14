//! The bank-grade spend gate.
//!
//! Everything the signer will authorize passes through here. The design goal is
//! that a **fully compromised host is worthless**: the host proposes only
//! *intent*; the signer derives keys, builds outputs, and signs. Value can
//! only ever go to:
//!
//! 1. value-0 Name Note or change to registry self-address, or
//! 2. sweep to the single policy-fixed cold address.
//!
//! The host controls when to drain excess hot float (infrequent balance-based
//! checks + note selection). The signer enforces destinations, fee/low
//! watermark limits, and the mint velocity/replay guard.
//!
//! Policy constants are attested with the binary; the spend key is held only
//! inside the signer (see [`Signer`]).

use std::collections::HashSet;

use orchard::{tree::Anchor, tree::MerklePath, Address, Note};
use zns_core::Action;

// ── policy constants (attested in production) ────────────────────────────────

/// The bounds within which the signer is allowed to act. Cloning is cheap; the
/// addresses are the only places value may ever land.
#[derive(Clone)]
pub struct SpendPolicy {
    /// Registry self-address: the recipient of every Name Note and all change.
    pub registry_addr: Address,
    /// The *only* external address funds may ever leave to (cold treasury).
    pub cold_addr: Address,
    /// Maximum fee the signer will pay for one mint (caps fee-burn griefing).
    pub max_fee_zat: u64,
    /// Hot-float target (retained for API; current host drain uses
    /// high_watermark + note selection, not this).
    /// Sweep to cold once the hot balance exceeds this.
    pub high_watermark_zat: u64,
    /// Refuse to mint below this (request a cold→hot top-up instead).
    pub low_watermark_zat: u64,
    /// Max mints authorized per rolling window.
    /// (This still exists to bound relay griefing and rapid mint spam from a compromised host.)
    pub max_mints_per_window: u32,
}

// ── what the (untrusted) host proposes ───────────────────────────────────────

/// The pure *intent* the host proposes — no crypto material. The policy gate
/// operates entirely on this plus the funding value, which keeps it trivially
/// testable and makes explicit that the host never supplies an output address
/// or `(rcm, ψ)`.
#[derive(Clone)]
pub struct MintIntent {
    pub action: Action,
    pub name: String,
    /// The Unified Address to bind (data inside the commitment, not a recipient).
    pub ua: String,
    pub prev_rcm: [u8; 32],
    /// Fee the host computed; the signer re-checks `≤ max_fee` and recomputes change.
    pub fee_zat: u64,
    /// Dedup key — the on-chain request note that triggered this.
    pub request_id: RequestId,
}

/// A full request: [`MintIntent`] plus the funding material selected from the
/// WalletDb. The funding note is only ever touched by the bundle builder.
pub struct MintProposal {
    pub intent: MintIntent,
    pub funding: FundingInput,
}

/// A spendable treasury note plus the witness/anchor proving it (from WalletDb).
pub struct FundingInput {
    pub note: Note,
    pub merkle_path: MerklePath,
    pub anchor: Anchor,
}

/// Identifies the request note so a given request is minted at most once.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RequestId {
    pub txid: [u8; 32],
    pub action_index: u32,
}

// ── validated plans the builder executes ─────────────────────────────────────

/// A mint the signer has authored and authorized. Every field here is
/// signer-derived or policy-bounded; the builder turns it into a bundle.
#[derive(Debug)]
pub struct MintPlan {
    pub action: Action,
    pub name: String,
    pub ua: String,
    pub prev_rcm: [u8; 32],
    pub fee_zat: u64,
    /// `funding.value − fee` (the Name Note is value 0), back to `registry_addr`.
    pub change_zat: u64,
}

// ── rejections ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// Name fails the registry character/length rules.
    NameInvalid(&'static str),
    /// CLAIM/UPDATE require a non-empty UA to bind.
    EmptyUa,
    /// Proposed fee exceeds `max_fee_zat`.
    FeeTooHigh { fee: u64, max: u64 },
    /// Funding note can't cover the fee.
    InsufficientFunding { have: u64, need: u64 },
    /// Hot balance is below the low watermark — minting is paused.
    BelowLowWatermark { balance: u64, low: u64 },
    /// This request was already minted.
    Replay(RequestId),
    /// Per-window mint (or relay) cap exceeded.
    VelocityExceeded,
}

// ── the gate ─────────────────────────────────────────────────────────────────

impl SpendPolicy {
    /// Validate an [`MintIntent`] against the funding value and current hot
    /// balance, and author the [`MintPlan`]. Pure — no crypto, no I/O. The
    /// recipients are *not* in the result because they are fixed
    /// (`registry_addr`); the builder reads them from `self`.
    pub fn evaluate_mint(
        &self,
        intent: &MintIntent,
        funding_value_zat: u64,
        hot_balance_zat: u64,
    ) -> Result<MintPlan, PolicyError> {
        validate_name(&intent.name)?;
        if matches!(intent.action, Action::Claim | Action::Update) && intent.ua.is_empty() {
            return Err(PolicyError::EmptyUa);
        }
        if intent.fee_zat > self.max_fee_zat {
            return Err(PolicyError::FeeTooHigh {
                fee: intent.fee_zat,
                max: self.max_fee_zat,
            });
        }
        if hot_balance_zat < self.low_watermark_zat {
            return Err(PolicyError::BelowLowWatermark {
                balance: hot_balance_zat,
                low: self.low_watermark_zat,
            });
        }
        let change = funding_value_zat.checked_sub(intent.fee_zat).ok_or(
            PolicyError::InsufficientFunding {
                have: funding_value_zat,
                need: intent.fee_zat,
            },
        )?;
        Ok(MintPlan {
            action: intent.action,
            name: intent.name.clone(),
            ua: intent.ua.clone(),
            prev_rcm: intent.prev_rcm,
            fee_zat: intent.fee_zat,
            change_zat: change,
        })
    }

    /// Returns full hot balance if above high_watermark (candidate for
    /// host drain); None otherwise.
    pub fn evaluate_sweep(&self, hot_balance_zat: u64) -> Option<u64> {
        if hot_balance_zat <= self.high_watermark_zat {
            return None;
        }
        Some(hot_balance_zat)
    }
}

/// The relay's fee/dust unit, mirroring the daemon's ZIP-317 fee. The signer
/// caps each at `min(max_fee_zat, RELAY_UNIT_ZAT)` so one policy knob bounds
/// the relay leak (see `Signer::sign_relay`).
pub const RELAY_UNIT_ZAT: u64 = 10_000;

/// Registry name rules — delegates to the producer's **authoritative**
/// validator (`zns_core::memo::validate_name`, the DNS-label rule the kernel
/// mirrors byte-for-byte), so the gate and the parser can never disagree
/// about which names exist. A second rule set here would mean names the
/// parser accepts start failing the day the gate is wired.
pub fn validate_name(name: &str) -> Result<(), PolicyError> {
    zns_core::memo::validate_name(name)
        .map_err(|_| PolicyError::NameInvalid("violates the registry name grammar"))
}

// ── stateful guard: replay + mint velocity ───────────────────────────────────

/// Per-window replay (permanent) + mint velocity limits. Window
/// advanced by caller. (Host controls sweep rate.)
#[derive(Default)]
pub struct SpendGuard {
    minted: HashSet<RequestId>,
    mints_this_window: u32,
}

impl SpendGuard {
    /// Reset the per-window counters (call at each window boundary). The
    /// `minted` set persists across windows (replay protection is permanent).
    pub fn roll_window(&mut self) {
        self.mints_this_window = 0;
    }

    /// Admit mint: replay + per-window velocity.
    pub fn admit_mint(&mut self, policy: &SpendPolicy, id: RequestId) -> Result<(), PolicyError> {
        if self.minted.contains(&id) {
            return Err(PolicyError::Replay(id));
        }
        if self.mints_this_window >= policy.max_mints_per_window {
            return Err(PolicyError::VelocityExceeded);
        }
        self.minted.insert(id);
        self.mints_this_window += 1;
        Ok(())
    }

    /// Undo prior admit on build failure.
    pub fn rollback_mint(&mut self, id: RequestId) {
        if self.minted.remove(&id) {
            self.mints_this_window = self.mints_this_window.saturating_sub(1);
        }
    }

    /// Admit sweep (no-op for rate; host controls).
    pub fn admit_sweep(&mut self, _policy: &SpendPolicy, _amount_zat: u64) -> Result<(), PolicyError> {
        Ok(())
    }

    pub fn rollback_sweep(&mut self, _amount_zat: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SpendPolicy {
        let addr = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_zip32_seed(&[7u8; 32], 1, zip32::AccountId::ZERO)
                .unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);
        SpendPolicy {
            registry_addr: addr,
            cold_addr: addr,
            max_fee_zat: 10_000,
            target_float_zat: 1_000_000,
            high_watermark_zat: 5_000_000,
            low_watermark_zat: 100_000,
            max_mints_per_window: 3,
        }
    }

    #[test]
    fn name_rules_match_the_canonical_validator() {
        // The DNS-label rule (zns_core::memo::validate_name): ≤ 63 bytes,
        // a-z 0-9 -, no edge hyphens. Interior double hyphens are legal.
        assert!(validate_name("alice").is_ok());
        assert!(validate_name("a-b-1").is_ok());
        assert!(validate_name("a--b").is_ok());
        assert!(validate_name(&"x".repeat(63)).is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("-a").is_err());
        assert!(validate_name("a-").is_err());
        assert!(validate_name("Alice").is_err());
        assert!(validate_name(&"x".repeat(64)).is_err());
    }

    fn intent(fee: u64) -> MintIntent {
        MintIntent {
            action: Action::Claim,
            name: "alice".into(),
            ua: "u1xxx".into(),
            prev_rcm: [0u8; 32],
            fee_zat: fee,
            request_id: RequestId {
                txid: [0u8; 32],
                action_index: 0,
            },
        }
    }

    #[test]
    fn mint_gate() {
        let p = policy();
        // happy path: change = funding − fee, recipients are implicit (self).
        let plan = p.evaluate_mint(&intent(5_000), 50_000, 1_000_000).unwrap();
        assert_eq!(plan.change_zat, 45_000);
        assert_eq!(plan.fee_zat, 5_000);
        // fee above the cap → refused before any build.
        assert!(matches!(
            p.evaluate_mint(&intent(20_000), 50_000, 1_000_000),
            Err(PolicyError::FeeTooHigh { .. })
        ));
        // funding can't cover the fee.
        assert!(matches!(
            p.evaluate_mint(&intent(5_000), 1_000, 1_000_000),
            Err(PolicyError::InsufficientFunding { .. })
        ));
        // hot balance below the low watermark → minting paused.
        assert!(matches!(
            p.evaluate_mint(&intent(5_000), 50_000, 50_000),
            Err(PolicyError::BelowLowWatermark { .. })
        ));
        // illegal name.
        let bad = MintIntent {
            name: "Alice".into(),
            ..intent(5_000)
        };
        assert!(matches!(
            p.evaluate_mint(&bad, 50_000, 1_000_000),
            Err(PolicyError::NameInvalid(_))
        ));
        // empty UA for a CLAIM.
        let no_ua = MintIntent {
            ua: String::new(),
            ..intent(5_000)
        };
        assert!(matches!(
            p.evaluate_mint(&no_ua, 50_000, 1_000_000),
            Err(PolicyError::EmptyUa)
        ));
    }

    #[test]
    fn sweep_watermark() {
        let p = policy();
        assert_eq!(p.evaluate_sweep(4_000_000), None);
        assert_eq!(p.evaluate_sweep(5_000_000), None);
        assert_eq!(p.evaluate_sweep(8_000_000), Some(8_000_000));
    }

    #[test]
    fn velocity_and_replay() {
        let p = policy();
        let mut g = SpendGuard::default();
        let id = |n: u32| RequestId {
            txid: [0; 32],
            action_index: n,
        };

        assert!(g.admit_mint(&p, id(0)).is_ok());
        assert_eq!(g.admit_mint(&p, id(0)), Err(PolicyError::Replay(id(0)))); // replay
        assert!(g.admit_mint(&p, id(1)).is_ok());
        assert!(g.admit_mint(&p, id(2)).is_ok());
        assert_eq!(g.admit_mint(&p, id(3)), Err(PolicyError::VelocityExceeded)); // 4th in window
        g.roll_window();
        assert!(g.admit_mint(&p, id(3)).is_ok()); // new window resets the counter
        assert_eq!(g.admit_mint(&p, id(0)), Err(PolicyError::Replay(id(0)))); // but replay is permanent
    }

    #[test]
    fn admit_sweep_succeeds() {
        let p = policy();
        let mut g = SpendGuard::default();
        assert!(g.admit_sweep(&p, 6_000_000).is_ok());
        assert!(g.admit_sweep(&p, 5_000_000).is_ok());
    }
}
