//! ZNS mint wallet.
//!
pub mod selection;

use std::collections::HashMap;

use incrementalmerkletree::{frontier::CommitmentTree, Position};
use orchard::tree::MerkleHashOrchard;
use zcash_keys::keys::UnifiedFullViewingKey;
use zip32::AccountId;

/// An unspent Orchard note held by the wallet.
#[derive(Clone)]
pub struct SpendableNote {
    pub note: orchard::note::Note,
    pub account_id: AccountId,
    pub position: Position,
    pub confirmed_height: zcash_protocol::consensus::BlockHeight,
    // is_change: arguably policy, not fact — pending selection-policy decision.
}

/// The in-memory ZNS wallet engine: a notes table and a tree.
pub struct Wallet {
    // Identity / scanning inputs (read-only after boot).
    ufvk_map: HashMap<AccountId, UnifiedFullViewingKey>,

    // Table 1 — Notes. Outer map routes by account (set at decrypt time);
    // inner map keyed by note identity (rho is the natural choice: it is
    // the note's protocol-level identity and the preimage the nullifier
    // is derived from). No hot query uses this key directly.
    notes: HashMap<AccountId, HashMap<[u8; 32], SpendableNote>>,

    // Nullifier index — the one hot point-query (scanner spend-detection).
    // Mirrors the SQLite `nf BLOB UNIQUE` column: the nullifier is an
    // index, not the row identity.
    nf_index: HashMap<[u8; 32], (AccountId, [u8; 32])>,

    // Table 2 — Tree. The running Orchard commitment tree. Scanner
    // appends per block; signer reads at sign time to build a witness
    // from (position, tree). No per-note living IncrementalWitness —
    // witnesses are derived on demand, matching librustzcash.
    tree: CommitmentTree<MerkleHashOrchard, 32>,
}

impl Wallet {
    /// Create a new, empty wallet.
    pub fn new(ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>) -> Self {
        Self {
            ufvk_map: ufvks.into_iter().collect(),
            notes: HashMap::new(),
            nf_index: HashMap::new(),
            tree: CommitmentTree::empty(),
        }
    }

    /// Read-only access to an account's spendable notes.
    /// Used by treasury/registry to apply selection policy.
    pub fn notes_for(&self, account: AccountId) -> impl Iterator<Item = &SpendableNote> {
        self.notes
            .get(&account)
            .into_iter()
            .flat_map(|m| m.values())
    }

    /// The total value of an account's spendable notes in zatoshis.
    pub fn balance(&self, account: AccountId) -> u64 {
        self.notes_for(account)
            .map(|n| n.note.value().inner())
            .sum()
    }

    /// Insert a newly scanned note into the wallet.
    pub fn insert_note(&mut self, note: SpendableNote) {
        let account = note.account_id;
        let rho = note.note.rho().to_bytes();
        let fvk = self
            .ufvk_map
            .get(&account)
            .expect("missing ufvk for account");
        let nullifier = note
            .note
            .nullifier(fvk.orchard().expect("missing orchard fvk"));

        self.nf_index.insert(nullifier.to_bytes(), (account, rho));
        self.notes.entry(account).or_default().insert(rho, note);
    }

    /// Mark a note as spent by removing it from the unspent map, if it exists.
    pub fn spend_note(&mut self, nullifier: &[u8; 32]) -> Option<SpendableNote> {
        if let Some((account, rho)) = self.nf_index.remove(nullifier) {
            if let Some(account_notes) = self.notes.get_mut(&account) {
                return account_notes.remove(&rho);
            }
        }
        None
    }

    /// Append an Orchard commitment to the wallet's tree.
    pub fn append_commitment(&mut self, commitment: MerkleHashOrchard) -> Position {
        self.tree
            .append(commitment)
            .expect("tree capacity exceeded");
        // The position is zero-indexed, so size - 1 is the position of the new leaf.
        Position::from(self.tree.size() as u64 - 1)
    }
}
