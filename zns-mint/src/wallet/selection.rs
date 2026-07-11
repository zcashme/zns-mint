use crate::wallet::transaction::{ReceivedOrchardNote, ReceivedSaplingNote};
use crate::wallet::Wallet;
use incrementalmerkletree::Position;
use std::collections::BTreeSet;
use zip32::AccountId;
use zcash_protocol::value::Zatoshis;

/// Selects a subset of unspent notes for a given account whose total value is
/// at least `target`, ignoring any notes present in the `exclude` set.
///
/// Implements a Best-Fit / Waterfall selection strategy (Exact match, Smallest sufficient,
/// then Dust Sweep fallback). Returns the selected notes and the total value selected, or
/// `None` if the account balance is insufficient.
pub fn select_funds<'a>(
    wallet: &'a Wallet,
    account: AccountId,
    target: Zatoshis,
    exclude: &BTreeSet<orchard::note::Rho>,
) -> Option<(Vec<&'a ReceivedOrchardNote>, Zatoshis)> {
    let target_u64 = target.into_u64();
    let mut notes: Vec<&ReceivedOrchardNote> = wallet
        .orchard_notes_for(account)
        .filter(|n| !exclude.contains(&n.note.rho()))
        .collect();
    
    // Sort from smallest to largest value
    notes.sort_by_key(|n| n.note.value().inner());

    // 1. Exact match (holy grail: minimum inputs, zero change)
    if let Some(exact) = notes.iter().find(|n| n.note.value().inner() == target_u64) {
        return Some((vec![*exact], target));
    }

    // 2. Smallest sufficient (minimum inputs, preserves large notes)
    if let Some(sufficient) = notes.iter().find(|n| n.note.value().inner() > target_u64) {
        return Some((vec![*sufficient], Zatoshis::from_u64(sufficient.note.value().inner()).unwrap()));
    }

    // 3. Dust sweep fallback (sweeps small notes until target is reached)
    let mut selected = Vec::new();
    let mut total = 0;
    for note in notes {
        selected.push(note);
        total += note.note.value().inner();
        if total >= target_u64 {
            return Some((selected, Zatoshis::from_u64(total).unwrap()));
        }
    }

    None
}

/// Selects a subset of unspent Sapling notes for a given account whose total value is
/// at least `target`, ignoring any notes present in the `exclude` set (identified by Position).
pub fn select_sapling_funds<'a>(
    wallet: &'a Wallet,
    account: AccountId,
    target: Zatoshis,
    exclude: &BTreeSet<Position>,
) -> Option<(Vec<&'a ReceivedSaplingNote>, Zatoshis)> {
    let target_u64 = target.into_u64();
    let mut notes: Vec<&ReceivedSaplingNote> = wallet
        .sapling_notes_for(account)
        .filter(|n| !exclude.contains(&n.position))
        .collect();
    
    // Sort from smallest to largest value
    notes.sort_by_key(|n| n.note.value().inner());

    // 1. Exact match
    if let Some(exact) = notes.iter().find(|n| n.note.value().inner() == target_u64) {
        return Some((vec![*exact], target));
    }

    // 2. Smallest sufficient
    if let Some(sufficient) = notes.iter().find(|n| n.note.value().inner() > target_u64) {
        return Some((vec![*sufficient], Zatoshis::from_u64(sufficient.note.value().inner()).unwrap()));
    }

    // 3. Dust sweep fallback
    let mut selected = Vec::new();
    let mut total = 0;
    for note in notes {
        selected.push(note);
        total += note.note.value().inner();
        if total >= target_u64 {
            return Some((selected, Zatoshis::from_u64(total).unwrap()));
        }
    }

    None
}
