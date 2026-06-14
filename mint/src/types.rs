//! Public data types used by the registry orchestration surface.
//!
//! These are intentionally not stored inside the core store/processor so they
//! can vary per call (different signers, different treasury notes, different
//! heights) or be supplied by the caller for testing/hot-swap.

use std::sync::Arc;

use orchard::{self, tree::Anchor};
use zcash_protocol::consensus::{BranchId, Network};

/// Contextual data the caller supplies to processing methods.
/// The signing authority and current block height.
///
/// These are intentionally not stored inside the registry handle so that the
/// registry can be used with different key configurations at runtime (e.g.
/// hot-swap, testing).
#[derive(Clone)]
pub struct MintContext {
    /// The policy-gated signing authority. The only path to a signature; the
    /// registry proposes intent, never touches key material.
    pub signer: Arc<zns_mint::Signer>,
    /// Current spendable treasury balance, for the signer's low-watermark
    /// pause. The daemon refreshes it each poll from funding selection.
    pub hot_balance_zat: u64,
    /// Orchard commitment-tree anchor. A value-0 Name Note only requires the
    /// empty-tree anchor (`Anchor::empty_tree()`).
    pub anchor: Anchor,
    /// The current Zcash block height (used for DB records).
    pub height: u32,
    /// Block height at which built transactions expire (0 = no expiry).
    pub expiry_height: u32,
    /// The network the registry operates on — needed to decode owner UAs.
    pub network: Network,
    /// Orchard circuit version to prove against.
    pub circuit_version: orchard::circuit::OrchardCircuitVersion,
    /// Consensus branch id for the target chain's active upgrade.
    pub branch_id: BranchId,
    /// Treasury spend material for funded sends. `None` means unfunded mode
    /// (testing); relays then fail with a clear "no treasury funding
    /// configured" error rather than silently no-op'ing.
    pub treasury: Option<Arc<Treasury>>,
}

/// Treasury spend material: a registry note with its witness and anchor,
/// selected by the daemon from note-state. **No key material** — signing
/// authority lives exclusively in the [`zns_mint::Signer`]. Change always
/// returns to the registry self-address (a policy constant).
pub struct Treasury {
    /// The treasury note being spent, with its Merkle witness and anchor.
    pub funding: zns_mint::FundingInput,
}

impl Treasury {
    /// An owned [`zns_mint::FundingInput`] for a proposal (the note and
    /// anchor are `Copy`; only the witness clones).
    pub fn funding_input(&self) -> zns_mint::FundingInput {
        zns_mint::FundingInput {
            note: self.funding.note,
            merkle_path: self.funding.merkle_path.clone(),
            anchor: self.funding.anchor,
        }
    }
}

/// Registry table counts, served by the control plane's `status` method.
#[derive(Debug, Clone, Copy)]
pub struct RegistryStats {
    /// Currently registered names.
    pub names: u64,
    /// Pending (unconfirmed, unexpired-or-not-yet-purged) OTP challenges.
    pub pending_challenges: u64,
    /// In-flight mint intents awaiting persistence or reconciliation.
    pub mint_intents: u64,
}

/// The outcome of processing a single incoming note.
#[derive(Debug)]
pub enum ProcessResult {
    /// The note was not a ZNS memo (or was a sent / OVK note); skipped.
    Skipped(String),
    /// Action processed successfully.
    Ok(ActionOutcome),
    /// An error occurred while processing this note.
    Err(String, String),
}

/// What happened when an action was dispatched.
#[derive(Debug)]
pub enum ActionOutcome {
    /// A Name Note was minted (CLAIM or confirmed UPDATE/RELEASE).
    Minted {
        name: String,
        action: zns_core::Action,
    },
    /// An OTP challenge was issued; waiting for the confirm note.
    ChallengeIssued { name: String, send_to: String },
}
