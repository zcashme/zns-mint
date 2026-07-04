use crate::wallet::{SpendableNote, Wallet};
use std::collections::HashSet;
use zip32::AccountId;

/// Selects a subset of unspent notes for a given account whose total value is
/// at least `target`, ignoring any notes present in the `exclude` set.
///
/// Implements a Best-Fit / Waterfall selection strategy (Exact match, Smallest sufficient,
/// then Dust Sweep fallback). Returns the selected notes and the total value selected, or
/// `None` if the account balance is insufficient.
pub fn select_funds<'a>(
    wallet: &'a Wallet,
    account: AccountId,
    target: u64,
    exclude: &HashSet<[u8; 32]>,
) -> Option<(Vec<&'a SpendableNote>, u64)> {
    let mut notes: Vec<&SpendableNote> = wallet
        .notes_for(account)
        .filter(|n| !exclude.contains(&n.note.rho().to_bytes()))
        .collect();
    
    // Sort from smallest to largest value
    notes.sort_by_key(|n| n.note.value().inner());

    // 1. Exact match (holy grail: minimum inputs, zero change)
    if let Some(exact) = notes.iter().find(|n| n.note.value().inner() == target) {
        return Some((vec![*exact], target));
    }

    // 2. Smallest sufficient (minimum inputs, preserves large notes)
    if let Some(sufficient) = notes.iter().find(|n| n.note.value().inner() > target) {
        return Some((vec![*sufficient], sufficient.note.value().inner()));
    }

    // 3. Dust sweep fallback (sweeps small notes until target is reached)
    let mut selected = Vec::new();
    let mut total = 0;
    for note in notes {
        selected.push(note);
        total += note.note.value().inner();
        if total >= target {
            return Some((selected, total));
        }
    }

    None
}
