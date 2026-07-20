use std::collections::BTreeMap;
use zip32::AccountId;

use super::transaction::{
    ReceivedIronwoodNote, ReceivedOrchardNote, ReceivedSaplingNote, TransactionRecord,
};

#[derive(Default)]
pub struct UnspentNotes {
    pub orchard: BTreeMap<AccountId, BTreeMap<orchard::note::Rho, ReceivedOrchardNote>>,
    pub ironwood: BTreeMap<AccountId, BTreeMap<orchard::note::Rho, ReceivedIronwoodNote>>,
    /// Sapling positions are unique within the global Sapling tree, so they
    /// are stable note identities without inventing a local placeholder key.
    pub sapling:
        BTreeMap<AccountId, BTreeMap<incrementalmerkletree::Position, ReceivedSaplingNote>>,
}

#[derive(Default)]
pub struct NullifierIndex {
    // Maps Orchard Nullifier to the AccountId and Rho that holds it.
    pub orchard: BTreeMap<orchard::note::Nullifier, (AccountId, orchard::note::Rho)>,
    // Maps Ironwood Nullifier to the AccountId and Rho that holds it.
    // Same Nullifier type as Orchard but tracked separately to avoid cross-pool collision.
    pub ironwood: BTreeMap<orchard::note::Nullifier, (AccountId, orchard::note::Rho)>,
    // Maps Sapling Nullifier to the AccountId and tree position that identify
    // the unspent note.
    pub sapling: BTreeMap<sapling::Nullifier, (AccountId, incrementalmerkletree::Position)>,
}

#[derive(Default)]
pub struct WalletBalance {
    pub unspent: UnspentNotes,
    pub nullifiers: NullifierIndex,
    pub transactions: Vec<TransactionRecord>,
}

impl WalletBalance {
    pub fn get_orchard_note_by_nf(
        &self,
        nf: &orchard::note::Nullifier,
    ) -> Option<&ReceivedOrchardNote> {
        let (account, rho) = self.nullifiers.orchard.get(nf)?;
        self.unspent.orchard.get(account)?.get(rho)
    }

    pub fn get_sapling_note_by_nf(&self, nf: &sapling::Nullifier) -> Option<&ReceivedSaplingNote> {
        let (account, note_id) = self.nullifiers.sapling.get(nf)?;
        self.unspent.sapling.get(account)?.get(note_id)
    }

    pub fn get_ironwood_note_by_nf(
        &self,
        nf: &orchard::note::Nullifier,
    ) -> Option<&ReceivedIronwoodNote> {
        let (account, rho) = self.nullifiers.ironwood.get(nf)?;
        self.unspent.ironwood.get(account)?.get(rho)
    }
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a transaction to the balance, updating unspent notes and nullifier indexes.
    pub fn add_transaction(&mut self, tx: &TransactionRecord) {
        // Insert newly received Orchard notes
        for note in &tx.received_orchard {
            let rho = note.note.rho();
            self.unspent
                .orchard
                .entry(note.account_id)
                .or_default()
                .insert(rho, note.clone());
            self.nullifiers
                .orchard
                .insert(note.nullifier, (note.account_id, rho));
        }

        // Insert newly received Sapling notes
        for note in &tx.received_sapling {
            let position = note.position;
            self.unspent
                .sapling
                .entry(note.account_id)
                .or_default()
                .insert(position, note.clone());
            self.nullifiers
                .sapling
                .insert(note.nullifier, (note.account_id, position));
        }

        // Insert newly received Ironwood notes
        for note in &tx.received_ironwood {
            let rho = note.note.rho();
            self.unspent
                .ironwood
                .entry(note.account_id)
                .or_default()
                .insert(rho, note.clone());
            self.nullifiers
                .ironwood
                .insert(note.nullifier, (note.account_id, rho));
        }

        // Remove spent Orchard notes
        for spent in &tx.spent_orchard {
            if let Some((account_id, rho)) = self.nullifiers.orchard.remove(&spent.nullifier) {
                if let Some(account_notes) = self.unspent.orchard.get_mut(&account_id) {
                    account_notes.remove(&rho);
                }
            }
        }

        // Remove spent Sapling notes
        for spent in &tx.spent_sapling {
            if let Some((account_id, id)) = self.nullifiers.sapling.remove(&spent.nullifier) {
                if let Some(account_notes) = self.unspent.sapling.get_mut(&account_id) {
                    account_notes.remove(&id);
                }
            }
        }

        // Remove spent Ironwood notes
        for spent in &tx.spent_ironwood {
            if let Some((account_id, rho)) = self.nullifiers.ironwood.remove(&spent.nullifier) {
                if let Some(account_notes) = self.unspent.ironwood.get_mut(&account_id) {
                    account_notes.remove(&rho);
                }
            }
        }

        self.transactions.push(tx.clone());
    }

    /// Rewinds the balance cache back to the specified height (linear undo).
    pub fn truncate_to_height(&mut self, height: zcash_protocol::consensus::BlockHeight) {
        while let Some(tx) = self.transactions.last() {
            if tx.block_height <= height {
                break;
            }

            // Undo received notes (delete them)
            for note in &tx.received_orchard {
                let rho = note.note.rho();
                if let Some(account_notes) = self.unspent.orchard.get_mut(&note.account_id) {
                    account_notes.remove(&rho);
                }
                self.nullifiers.orchard.remove(&note.nullifier);
            }

            for note in &tx.received_sapling {
                let position = note.position;
                if let Some(account_notes) = self.unspent.sapling.get_mut(&note.account_id) {
                    account_notes.remove(&position);
                }
                self.nullifiers.sapling.remove(&note.nullifier);
            }

            for note in &tx.received_ironwood {
                let rho = note.note.rho();
                if let Some(account_notes) = self.unspent.ironwood.get_mut(&note.account_id) {
                    account_notes.remove(&rho);
                }
                self.nullifiers.ironwood.remove(&note.nullifier);
            }

            // Undo spent notes (put them back!)
            for spent in &tx.spent_orchard {
                let rho = spent.original_note.note.rho();
                self.unspent
                    .orchard
                    .entry(spent.account_id)
                    .or_default()
                    .insert(rho, spent.original_note.clone());
                self.nullifiers
                    .orchard
                    .insert(spent.nullifier, (spent.account_id, rho));
            }

            for spent in &tx.spent_sapling {
                let position = spent.original_note.position;
                self.unspent
                    .sapling
                    .entry(spent.account_id)
                    .or_default()
                    .insert(position, spent.original_note.clone());
                self.nullifiers
                    .sapling
                    .insert(spent.nullifier, (spent.account_id, position));
            }

            for spent in &tx.spent_ironwood {
                let rho = spent.original_note.note.rho();
                self.unspent
                    .ironwood
                    .entry(spent.account_id)
                    .or_default()
                    .insert(rho, spent.original_note.clone());
                self.nullifiers
                    .ironwood
                    .insert(spent.nullifier, (spent.account_id, rho));
            }

            self.transactions.pop();
        }
    }
}
