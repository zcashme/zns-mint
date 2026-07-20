//! Name-chain state machine: the registry of ZNS name tips and the
//! cryptographic newtypes for the ZNS commitment scalars.

use crate::mint::{Action, Name, NameCommitment};
use std::collections::BTreeMap;
use zcash_protocol::consensus::BlockHeight;

// ---------------------------------------------------------------------------
// Newtypes for the ZNS commitment scalars
// ---------------------------------------------------------------------------

/// The `rcm` trapdoor — the note commitment randomness that makes a Name
/// Note's commitment unique and unpredictable.
///
/// Derived by [`crate::mint::zns_psi_rcm`] and fed to the orchard fork's
/// `add_zns_spend` / `add_zns_output`. Stored in [`Tip`] so the Registry can
/// spend a Name Note later. Newtype over `pallas::Scalar` to distinguish it
/// from arbitrary scalars (binding nonces, spend-auth randomizers, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rcm(pasta_curves::pallas::Scalar);

impl Rcm {
    pub fn from_scalar(s: pasta_curves::pallas::Scalar) -> Self {
        Self(s)
    }

    pub fn as_scalar(&self) -> &pasta_curves::pallas::Scalar {
        &self.0
    }

    pub fn into_scalar(self) -> pasta_curves::pallas::Scalar {
        self.0
    }
}

/// The `ψ` (psi) value — the ZNS payload commitment that binds the Name Note
/// to its `(name, action, ua, prev_rcm)` inputs.
///
/// Derived alongside [`Rcm`] by [`crate::mint::zns_psi_rcm`]. The orchard fork
/// computes `cmx` from `(rcm, ψ)` instead of the standard `(recipient, value,
/// rcm)` derivation. Newtype over `pallas::Base` to distinguish it from
/// arbitrary base field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psi(pasta_curves::pallas::Base);

impl Psi {
    pub fn from_base(b: pasta_curves::pallas::Base) -> Self {
        Self(b)
    }

    pub fn as_base(&self) -> &pasta_curves::pallas::Base {
        &self.0
    }

    pub fn into_base(self) -> pasta_curves::pallas::Base {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Tip — the current state of a name chain
// ---------------------------------------------------------------------------

/// The current state of a name chain: the most recent confirmed Name Note's
/// action, commitment, and the exact scalars needed to spend it later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip {
    pub action: Action,
    pub commitment: NameCommitment,
    /// The `rcm` trapdoor used to mint this Name Note. Needed to spend it
    /// via `add_zns_spend`.
    pub rcm: Rcm,
    /// The `ψ` payload commitment used to mint this Name Note. Needed to
    /// spend it via `add_zns_spend`.
    pub psi: Psi,
}

// ---------------------------------------------------------------------------
// Registry — name-chain state with reorg undo
// ---------------------------------------------------------------------------

/// An undo-log entry: records what the tip was before a `set_tip` so a reorg
/// can rewind the registry to a prior height.
#[derive(Debug, Clone)]
pub struct RegistryHistoryRecord {
    pub height: BlockHeight,
    pub name: Name,
    pub prev_tip: Option<Tip>,
}

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed tip for that name, plus an undo log for reorgs.
pub struct Registry {
    tips: BTreeMap<Name, Tip>,
    history: Vec<RegistryHistoryRecord>,
}

impl Registry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            tips: BTreeMap::new(),
            history: Vec::new(),
        }
    }

    /// Read the current tip of a ZNS name chain.
    pub fn tip(&self, name: &Name) -> Option<&Tip> {
        self.tips.get(name)
    }

    /// Update the current tip of a ZNS name chain. Called by the scanner when
    /// a confirmed Name Note for `name` is observed on the best chain.
    pub fn set_tip(&mut self, name: Name, tip: Tip, height: BlockHeight) {
        let prev_tip = self.tips.insert(name.clone(), tip);
        self.history.push(RegistryHistoryRecord {
            height,
            name,
            prev_tip,
        });
    }

    /// Read-only iterator over all known name tips. Used for diagnostics.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &Tip)> {
        self.tips.iter()
    }

    /// Rewinds the registry state back to the specified height (linear undo).
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        while let Some(record) = self.history.last() {
            if record.height <= height {
                break;
            }
            let record = self.history.pop().unwrap();
            match record.prev_tip {
                Some(old_tip) => {
                    self.tips.insert(record.name, old_tip);
                }
                None => {
                    self.tips.remove(&record.name);
                }
            }
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
