use std::collections::HashMap;
use zip32::AccountId;

use super::transaction::{ReceivedOrchardNote, ReceivedSaplingNote, TransactionRecord};

#[derive(Default)]
pub struct UnspentNotes {
    pub orchard: HashMap<AccountId, HashMap<[u8; 32], ReceivedOrchardNote>>,
    pub sapling: HashMap<AccountId, HashMap<[u8; 32], ReceivedSaplingNote>>,
}

#[derive(Default)]
pub struct NullifierIndex {
    /// Maps a nullifier to the AccountId and the note's unique `rho`
    pub orchard: HashMap<[u8; 32], (AccountId, [u8; 32])>,
    /// Maps a nullifier to the AccountId and the note's `rho` equivalent
    pub sapling: HashMap<[u8; 32], (AccountId, [u8; 32])>,
}

#[derive(Default)]
pub struct WalletBalance {
    pub unspent: UnspentNotes,
    pub nullifiers: NullifierIndex,
    pub transactions: Vec<TransactionRecord>,
}

impl WalletBalance {
    pub fn get_orchard_note_by_nf(&self, nf: &[u8; 32]) -> Option<&ReceivedOrchardNote> {
        let (account_id, rho) = self.nullifiers.orchard.get(nf)?;
        self.unspent.orchard.get(account_id)?.get(rho)
    }

    pub fn get_sapling_note_by_nf(&self, nf: &[u8; 32]) -> Option<&ReceivedSaplingNote> {
        let (account_id, id) = self.nullifiers.sapling.get(nf)?;
        self.unspent.sapling.get(account_id)?.get(id)
    }
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a transaction to the balance, updating unspent notes and nullifier indexes.
    pub fn add_transaction(&mut self, tx: &TransactionRecord) {
        // Insert newly received Orchard notes
        for note in &tx.received_orchard {
            let rho = note.note.rho().to_bytes();
            self.unspent
                .orchard
                .entry(note.account_id)
                .or_default()
                .insert(rho, note.clone());
        }

        // Insert newly received Sapling notes
        // Note: For sapling, we would typically use the note's rcm or similar unique identifier
        // instead of rho. We'll use a placeholder [0; 32] until we wire up Sapling keys.
        for note in &tx.received_sapling {
            let id = [0u8; 32];
            self.unspent
                .sapling
                .entry(note.account_id)
                .or_default()
                .insert(id, note.clone());
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
                let rho = note.note.rho().to_bytes();
                if let Some(account_notes) = self.unspent.orchard.get_mut(&note.account_id) {
                    account_notes.remove(&rho);
                }
            }
            
            for note in &tx.received_sapling {
                let id = [0u8; 32];
                if let Some(account_notes) = self.unspent.sapling.get_mut(&note.account_id) {
                    account_notes.remove(&id);
                }
            }
            
            // Undo spent notes (put them back!)
            for spent in &tx.spent_orchard {
                let rho = spent.original_note.note.rho().to_bytes();
                self.unspent.orchard
                    .entry(spent.account_id)
                    .or_default()
                    .insert(rho, spent.original_note.clone());
                self.nullifiers.orchard.insert(spent.nullifier, (spent.account_id, rho));
            }
            
            for spent in &tx.spent_sapling {
                let id = [0u8; 32];
                self.unspent.sapling
                    .entry(spent.account_id)
                    .or_default()
                    .insert(id, spent.original_note.clone());
                self.nullifiers.sapling.insert(spent.nullifier, (spent.account_id, id));
            }
            
            self.transactions.pop();
        }
    }
}
