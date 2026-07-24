//! Transaction submission tracking for the Live phase.
//!
//! Tracks pending submitted transactions, their reserved notes, and their
//! confirmation or expiry status. All state is in-memory and ephemeral —
//! restart loses this state, and reconciliation re-derives pending work from
//! canonical chain state.

use std::collections::{BTreeMap, BTreeSet};

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::mint::Action;
use crate::wallet::NoteLocator;

/// The kind of operation a submitted transaction performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubmissionKind {
    /// An atomic claim: Treasury payment spend + Registry Name Note creation.
    Claim,
    /// A Name Note update transition.
    Update,
    /// A Name Note release transition.
    Release,
    /// An OTP relay from Treasury to the current controller.
    OtpRelay,
    /// Treasury→Registry fee-note replenishment.
    Replenish,
    /// Treasury auto-sweep to cold storage.
    AutoSweep,
}

impl SubmissionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Update => "update",
            Self::Release => "release",
            Self::OtpRelay => "otp_relay",
            Self::Replenish => "replenish",
            Self::AutoSweep => "sweep",
        }
    }

    pub fn action(self) -> Option<Action> {
        match self {
            Self::Claim => Some(Action::Claim),
            Self::Update => Some(Action::Update),
            Self::Release => Some(Action::Release),
            Self::OtpRelay => None,
            Self::Replenish => None,
            Self::AutoSweep => None,
        }
    }
}

/// One pending or confirmed submitted transaction.
#[derive(Debug, Clone)]
pub struct Submission {
    pub kind: SubmissionKind,
    pub txid: TxId,
    /// The chain height at which the transaction was first submitted.
    pub submit_height: BlockHeight,
    /// The expiry height encoded in the transaction. After this height the
    /// transaction can no longer be mined and the reservations are released.
    pub expiry_height: BlockHeight,
    /// Notes spent in this transaction. Reserved until confirmation or expiry
    /// so that reconciliation does not re-derive the same work.
    pub reserved_notes: Vec<NoteLocator>,
    /// The block height at which the transaction was confirmed, if confirmed.
    pub confirmed_at: Option<BlockHeight>,
}

impl Submission {
    /// Whether this submission has expired at `current_height`.
    pub fn is_expired(&self, current_height: BlockHeight) -> bool {
        self.confirmed_at.is_none() && current_height > self.expiry_height
    }

    /// Whether this submission has been confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }
}

/// In-memory tracking of all pending and recently-confirmed submissions.
#[derive(Default)]
pub struct Submissions {
    pending: BTreeMap<TxId, Submission>,
}

impl Submissions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a new submission.
    pub fn add(&mut self, submission: Submission) {
        self.pending.insert(submission.txid, submission);
    }

    /// Marks a submission as confirmed at `height`. Returns the confirmed
    /// submission if it was pending.
    pub fn confirm(&mut self, txid: &TxId, height: BlockHeight) -> Option<Submission> {
        if let Some(sub) = self.pending.get_mut(txid) {
            if sub.confirmed_at.is_none() {
                sub.confirmed_at = Some(height);
            }
            return Some(sub.clone());
        }
        None
    }

    /// Returns and removes all submissions that have expired at
    /// `current_height`. Their reserved notes are released.
    pub fn expire(&mut self, current_height: BlockHeight) -> Vec<Submission> {
        let expired: Vec<TxId> = self
            .pending
            .iter()
            .filter(|(_, sub)| sub.is_expired(current_height))
            .map(|(txid, _)| *txid)
            .collect();

        expired
            .into_iter()
            .filter_map(|txid| self.pending.remove(&txid))
            .collect()
    }

    /// Removes and returns confirmed submissions. Called after metrics are
    /// updated to keep the pending set focused on unconfirmed work.
    pub fn drain_confirmed(&mut self) -> Vec<Submission> {
        let confirmed: Vec<TxId> = self
            .pending
            .iter()
            .filter(|(_, sub)| sub.is_confirmed())
            .map(|(txid, _)| *txid)
            .collect();

        confirmed
            .into_iter()
            .filter_map(|txid| self.pending.remove(&txid))
            .collect()
    }

    /// Whether a transaction with this txid is currently pending.
    pub fn contains(&self, txid: &TxId) -> bool {
        self.pending.contains_key(txid)
    }

    /// All currently pending submissions (confirmed and unconfirmed).
    pub fn iter(&self) -> impl Iterator<Item = &Submission> {
        self.pending.values()
    }

    /// All note locators reserved by pending submissions.
    pub fn reserved_locators(&self) -> BTreeSet<NoteLocator> {
        self.pending
            .values()
            .flat_map(|sub| sub.reserved_notes.iter().copied())
            .collect()
    }

    /// Clears all submission state. Called on reorg to invalidate all
    /// cursor-bound operational work.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// The number of pending submissions.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_txid(n: u8) -> TxId {
        TxId::from_bytes([n; 32])
    }

    fn dummy_submission(txid: u8, kind: SubmissionKind) -> Submission {
        Submission {
            kind,
            txid: dummy_txid(txid),
            submit_height: BlockHeight::from_u32(100),
            expiry_height: BlockHeight::from_u32(120),
            reserved_notes: Vec::new(),
            confirmed_at: None,
        }
    }

    #[test]
    fn add_and_confirm() {
        let mut subs = Submissions::new();
        let sub = dummy_submission(1, SubmissionKind::Claim);
        subs.add(sub.clone());

        assert!(subs.contains(&dummy_txid(1)));
        assert_eq!(subs.len(), 1);

        let confirmed = subs.confirm(&dummy_txid(1), BlockHeight::from_u32(105));
        assert!(confirmed.is_some());
        assert_eq!(
            confirmed.unwrap().confirmed_at,
            Some(BlockHeight::from_u32(105))
        );
    }

    #[test]
    fn expire_releases_expired() {
        let mut subs = Submissions::new();
        subs.add(dummy_submission(1, SubmissionKind::Claim));
        subs.add(dummy_submission(2, SubmissionKind::Update));

        let expired = subs.expire(BlockHeight::from_u32(121));
        assert_eq!(expired.len(), 2);
        assert!(subs.is_empty());
    }

    #[test]
    fn confirmed_not_kept_after_drain() {
        let mut subs = Submissions::new();
        subs.add(dummy_submission(1, SubmissionKind::Claim));
        subs.add(dummy_submission(2, SubmissionKind::Update));

        subs.confirm(&dummy_txid(1), BlockHeight::from_u32(105));

        let drained = subs.drain_confirmed();
        assert_eq!(drained.len(), 1);
        assert_eq!(subs.len(), 1);
        assert!(subs.contains(&dummy_txid(2)));
    }

    #[test]
    fn clear_removes_all() {
        let mut subs = Submissions::new();
        subs.add(dummy_submission(1, SubmissionKind::Claim));
        subs.add(dummy_submission(2, SubmissionKind::Update));
        subs.clear();
        assert!(subs.is_empty());
    }
}