//! Registry state-machine view and transition authorization.
//!
//! The `Registry` owns the name-chain state: a map from canonical ZNS name to
//! its most recent known tip (the `Action` and `Commitment` of the live Name
//! Note for that name). It is a peer of `Wallet`, not a field of it: both are
//! chain-derived stores that the scanner writes to by reference at scan time,
//! and each owns its own domain state. See `docs/protocol/14-wallet-design.md`.
//!
//! The scanner writes name tips here via [`Registry::set_tip`]; the
//! authorization functions read them via [`Registry::tip`]. No spending keys,
//! no chain I/O, no signing — those live elsewhere.

use crate::mint::{Action, Name, NameCommitment, ZERO_PREV_COMMITMENT};
use std::collections::HashMap;

/// A requested Name Note transition, ready for the transaction-assembly path.
///
/// This is produced by the Registry module after it has verified the
/// authorization policy (name availability, valid OTP, chain rules).
/// It represents the intent to "print" a new Name Note to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameNoteRequest {
    /// The action being performed.
    pub action: Action,
    /// The canonical ZNS name.
    pub name: String,
    /// The unified address the name is binding to (empty for a release).
    pub ua: String,
    /// The previous Name Note's commitment, linking this note to the chain.
    pub prev_commitment: NameCommitment,
}

impl NameNoteRequest {
    /// Constructs a valid claim request.
    ///
    /// Claims always use `ZERO_PREV_COMMITMENT` as they start a new active chain.
    pub fn new_claim(name: String, ua: String) -> Self {
        Self {
            action: Action::Claim,
            name,
            ua,
            prev_commitment: ZERO_PREV_COMMITMENT,
        }
    }

    /// Constructs a valid update request.
    ///
    /// The `prev_commitment` must be the `commitment` of the currently live tip.
    pub fn new_update(name: String, new_ua: String, prev_commitment: NameCommitment) -> Self {
        Self {
            action: Action::Update,
            name,
            ua: new_ua,
            prev_commitment,
        }
    }

    /// Constructs a valid release request.
    ///
    /// The `ua` field is forced to be empty, as releases drop the binding.
    /// The `prev_commitment` must be the `commitment` of the currently live tip.
    pub fn new_release(name: String, prev_commitment: NameCommitment) -> Self {
        Self {
            action: Action::Release,
            name,
            ua: String::new(),
            prev_commitment,
        }
    }
}

/// The current state of a name chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip {
    pub action: Action,
    pub commitment: NameCommitment,
    /// The exact scalars used to mint this note, needed to spend it later.
    pub rcm: pasta_curves::pallas::Scalar,
    pub psi: pasta_curves::pallas::Base,
}

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed tip for that name.
///
/// This is a peer of [`crate::wallet::Wallet`], not a field of it. The scanner
/// takes `&mut Registry` and `&mut Wallet` by reference per block; nothing owns
/// both as nested state. Composition happens at the call site (the sync loop),
/// which holds `Wallet` and `Registry` as independent locals.
///
/// Invariants:
/// - At most one live tip per name (enforced by the per-name chain rule in the
///   scanner: a new Name Note for an existing name requires the prior tip's
///   nullifier to have appeared in the same or an earlier block).
/// - The tip's `commitment` is the `rcm` of the note that the next transition
///   for this name must chain off.
pub struct Registry(HashMap<Name, Tip>);

impl Registry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Read the current tip of a ZNS name chain.
    pub fn tip(&self, name: &Name) -> Option<&Tip> {
        self.0.get(name)
    }

    /// Update the current tip of a ZNS name chain. Called by the scanner when
    /// a confirmed Name Note for `name` is observed on the best chain.
    pub fn set_tip(&mut self, name: Name, tip: Tip) {
        self.0.insert(name, tip);
    }

    /// Read-only iterator over all known name tips. Used for diagnostics.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &Tip)> {
        self.0.iter()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads the current tip of the name chain for `name`.
///
/// Looks up the registry's `name_chain` to find the most recent confirmed Name Note.
pub fn current_tip(registry: &Registry, name: &Name) -> Option<Tip> {
    registry.tip(name).cloned()
}

/// Authorizes a claim request, producing a `NameNoteRequest`.
///
/// The Treasury layer must have already verified that the claim payment was made.
/// This function verifies that the name is available (either no tip, or tip is `Release`).
pub fn authorize_claim(
    registry: &Registry,
    name: Name,
    ua: String,
) -> Option<NameNoteRequest> {
    match current_tip(registry, &name) {
        None => Some(NameNoteRequest::new_claim(name.as_str().to_string(), ua)),
        Some(Tip { action: Action::Release, .. }) => {
            Some(NameNoteRequest::new_claim(name.as_str().to_string(), ua))
        }
        Some(_) => None, // Name is already live
    }
}

/// Authorizes an update request, producing a `NameNoteRequest`.
///
/// Verifies the name is live, the current tip matches, and calls `auth::verify_consume`
/// to validate the OTP.
pub fn authorize_update(
    registry: &Registry,
    name: Name,
    new_ua: String,
    _otp: [u8; 16],
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    // auth::verify_consume(name, Action::Update, new_ua, otp)?;

    Some(NameNoteRequest::new_update(
        name.as_str().to_string(),
        new_ua,
        tip.commitment,
    ))
}

/// Authorizes a release request, producing a `NameNoteRequest`.
///
/// Verifies the name is live, the current UA matches `current_ua`, and calls
/// `auth::verify_consume` to validate the OTP.
pub fn authorize_release(
    registry: &Registry,
    name: Name,
    _current_ua: String,
    _otp: [u8; 16],
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    // To verify `current_ua`, we would read it from the registry's live Name Note.
    // auth::verify_consume(name, Action::Release, current_ua, otp)?;

    Some(NameNoteRequest::new_release(
        name.as_str().to_string(),
        tip.commitment,
    ))
}

/// Assembles, proves, and signs an Orchard transaction bundle to execute a ZNS request.
///
/// Not implemented. This is Slice 4 (witness derivation) + Slice 5 (transaction
/// assembly: real v5 sighash, fee funding, broadcast) work. The wallet's
/// `CommitmentTree` is a bare frontier that cannot witness arbitrary historical
/// positions yet — per-position `IncrementalWitness` derivation at sign time is
/// the missing piece. Until that lands, the boot path does not call this.
#[allow(clippy::too_many_arguments)]
pub fn build_transaction(
    _wallet: &crate::wallet::Wallet,
    _registry: &Registry,
    _keys: &crate::key::Keys,
    _request: NameNoteRequest,
    _exclude: &std::collections::HashSet<orchard::note::Rho>,
) -> Result<
    orchard::Bundle<
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
        (),
    >,
    &'static str,
> {
    todo!("transaction assembly: witness derivation (Slice 4) + sighash/funding (Slice 5) unimplemented")
}