//! Upstream `InputSource` implementation.
//!
//! Sapling and Ironwood are the only owned shielded input lanes. The ordinary
//! Orchard pool is maintained as a compatibility commitment tree only and is
//! never surfaced as wallet inputs. Selection, spendability, lock admission,
//! and confirmation classification live here so that `wallet::read` balance
//! reporting reuses exactly the same rules.

use std::num::NonZeroU32;

use shardtree::store::ShardStore;
use zcash_client_backend::data_api::{
    AccountMeta, CoinbaseFilter, InputSource, NoteFilter, PoolMeta, ReceivedNotes, TargetValue,
    wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
};
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::wallet::{
    Note, NoteId, OutputRef, ReceivedNote, WalletTransparentOutput,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;
use zip32::AccountId;

use super::{Wallet, read::WalletError};

impl Wallet {
    /// Whether the Sapling note identified by `note_id` is spent as of
    /// `target_height`.
    ///
    /// A spend recorded by an unmined transaction still blocks re-selection
    /// unless the spending transaction has expired before the target height
    /// (in which case it can never be mined).
    pub(super) fn sapling_note_is_spent(&self, note_id: &NoteId, target_height: TargetHeight) -> bool {
        self.sapling_note_spends
            .get(note_id)
            .is_some_and(|txid| self.spend_confirms_or_blocks(txid, target_height))
    }

    /// Whether the Ironwood note identified by `note_id` is spent as of
    /// `target_height`.
    pub(super) fn ironwood_note_is_spent(
        &self,
        note_id: &NoteId,
        target_height: TargetHeight,
    ) -> bool {
        self.ironwood_note_spends
            .get(note_id)
            .is_some_and(|txid| self.spend_confirms_or_blocks(txid, target_height))
    }

    /// Whether a recorded spending transaction either confirms the spend or
    /// still potentially stands at `target_height`.
    fn spend_confirms_or_blocks(&self, txid: &TxId, target_height: TargetHeight) -> bool {
        use zcash_client_backend::data_api::TransactionStatus;
        use zcash_protocol::consensus::H0;

        match self.transaction_statuses.get(txid) {
            // Every spend recorded by `put_blocks` is mined; a mined spend is
            // confirmed.
            Some(TransactionStatus::Mined(_)) => true,
            // A spend recorded by `store_transactions_to_be_sent` that has not
            // been mined blocks re-selection until the spending transaction
            // expires: an unmined transaction whose expiry height is below the
            // target can never confirm. Expiry height zero means no expiry.
            Some(TransactionStatus::NotInMainChain) => self
                .transactions
                .get(txid)
                .map(|tx| {
                    let expiry = tx.expiry_height();
                    expiry == H0 || expiry >= BlockHeight::from(target_height)
                })
                // No raw transaction retained: the conservative answer is
                // that the spend still stands.
                .unwrap_or(true),
            // A status of TxidNotRecognized, or a missing status, is treated
            // conservatively: the note stays unselectable.
            _ => true,
        }
    }

    /// The number of confirmations required before a note is spendable under
    /// `policy` ([ZIP 315]): notes the wallet sent to itself (change) and
    /// notes of transactions marked trusted via `set_tx_trust` require only
    /// the trusted depth.
    ///
    /// [ZIP 315]: https://zips.z.cash/zip-0315
    pub(super) fn required_confirmations(
        &self,
        txid: &TxId,
        is_change: bool,
        policy: ConfirmationsPolicy,
    ) -> NonZeroU32 {
        if is_change || self.trusted_transactions.contains(txid) {
            policy.trusted()
        } else {
            policy.untrusted()
        }
    }

    /// Whether the lock on `output` (if any) admits selection at
    /// `target_height` under `lock_filter`.
    pub(super) fn lock_admits(
        &self,
        output: &OutputRef,
        target_height: TargetHeight,
        lock_filter: LockFilter<'_>,
    ) -> bool {
        match self.locks.get(output) {
            None => true,
            Some((owner, expiry)) => {
                if *expiry < BlockHeight::from(target_height) {
                    // The lock has lapsed.
                    true
                } else {
                    match lock_filter {
                        LockFilter::Unfiltered => true,
                        LockFilter::Policy(policy) => {
                            policy.overridable_owners().contains(owner)
                        }
                    }
                }
            }
        }
    }

    /// The mined height of `txid`, if the wallet has applied a block mining
    /// it.
    pub(crate) fn mined_height(&self, txid: &TxId) -> Option<BlockHeight> {
        match self.transaction_statuses.get(txid) {
            Some(zcash_client_backend::data_api::TransactionStatus::Mined(height)) => Some(*height),
            _ => None,
        }
    }

    /// Whether a received note satisfies the trusted/untrusted confirmation
    /// policy at `target_height`.
    fn confirmations_satisfied(
        &self,
        txid: &TxId,
        is_change: bool,
        target_height: TargetHeight,
        policy: ConfirmationsPolicy,
    ) -> bool {
        match self.mined_height(txid) {
            Some(mined) => {
                let required = self.required_confirmations(txid, is_change, policy);
                target_height.saturating_sub(u32::from(required)) >= mined
            }
            None => false,
        }
    }

    /// Builds the [`ReceivedNote`] for a retained Sapling output, or `None`
    /// when the spending key scope was not retained.
    fn sapling_received_note(&self, note_id: NoteId) -> Option<ReceivedNote<NoteId, sapling::Note>> {
        let output = self.sapling_notes.get(&note_id)?;
        Some(ReceivedNote::from_parts(
            note_id,
            *note_id.txid(),
            note_id.output_index(),
            output.note().clone(),
            output.recipient_key_scope()?,
            output.note_commitment_tree_position(),
            self.mined_height(note_id.txid()),
            // The mint never shields transparent funds, so no shielded note of
            // this wallet was created from transparent inputs.
            None,
        ))
    }

    /// Builds the [`ReceivedNote`] for a retained Ironwood output, or `None`
    /// when the spending key scope was not retained.
    pub(crate) fn ironwood_received_note(
        &self,
        note_id: NoteId,
    ) -> Option<ReceivedNote<NoteId, orchard::note::Note>> {
        let output = self.ironwood_notes.get(&note_id)?;
        Some(ReceivedNote::from_parts(
            note_id,
            *note_id.txid(),
            note_id.output_index(),
            output.note().0.clone(),
            output.recipient_key_scope()?,
            output.note_commitment_tree_position(),
            self.mined_height(note_id.txid()),
            None,
        ))
    }

    /// Collects the eligible Sapling notes of `account`, oldest first by
    /// commitment tree position. `confirmations_policy` of `None` selects
    /// every unspent note irrespective of confirmations.
    fn eligible_sapling(
        &self,
        account: AccountId,
        target_height: TargetHeight,
        confirmations_policy: Option<ConfirmationsPolicy>,
        exclude: &[NoteId],
        lock_filter: LockFilter<'_>,
    ) -> Vec<ReceivedNote<NoteId, sapling::Note>> {
        let mut notes: Vec<_> = self
            .sapling_notes
            .iter()
            .filter(|(note_id, output)| {
                *output.account_id() == account
                    && !exclude.contains(note_id)
                    && output.recipient_key_scope().is_some()
                    && !self.sapling_note_is_spent(note_id, target_height)
                    && self.lock_admits(&OutputRef::from(**note_id), target_height, lock_filter)
                    && confirmations_policy.is_none_or(|policy| {
                        self.confirmations_satisfied(
                            note_id.txid(),
                            output.is_change(),
                            target_height,
                            policy,
                        )
                    })
            })
            .filter_map(|(note_id, _)| self.sapling_received_note(*note_id))
            .collect();
        notes.sort_by_key(ReceivedNote::note_commitment_tree_position);
        notes
    }

    /// Collects the eligible Ironwood notes of `account`, oldest first by
    /// commitment tree position.
    fn eligible_ironwood(
        &self,
        account: AccountId,
        target_height: TargetHeight,
        confirmations_policy: Option<ConfirmationsPolicy>,
        exclude: &[NoteId],
        lock_filter: LockFilter<'_>,
    ) -> Vec<ReceivedNote<NoteId, orchard::note::Note>> {
        let mut notes: Vec<_> = self
            .ironwood_notes
            .iter()
            .filter(|(note_id, output)| {
                *output.account_id() == account
                    && !exclude.contains(note_id)
                    && output.recipient_key_scope().is_some()
                    && !self.ironwood_note_is_spent(note_id, target_height)
                    && self.lock_admits(&OutputRef::from(**note_id), target_height, lock_filter)
                    && confirmations_policy.is_none_or(|policy| {
                        self.confirmations_satisfied(
                            note_id.txid(),
                            output.is_change(),
                            target_height,
                            policy,
                        )
                    })
            })
            .filter_map(|(note_id, _)| self.ironwood_received_note(*note_id))
            .collect();
        notes.sort_by_key(ReceivedNote::note_commitment_tree_position);
        notes
    }

    /// Evaluates `filter` against a note of `value`, returning `None` when
    /// the filter cannot be evaluated from this wallet's data.
    fn note_matches_filter(value: Zatoshis, filter: &NoteFilter) -> Option<bool> {
        match filter {
            NoteFilter::ExceedsMinValue(min) => Some(value > *min),
            // Send-history and balance-distribution filters require data this
            // wallet does not retain.
            NoteFilter::ExceedsPriorSendPercentile(_) | NoteFilter::ExceedsBalancePercentage(_) => {
                None
            }
            // Both conditions are evaluated; one that cannot be evaluated is
            // ignored, and if neither can the combined filter cannot either.
            NoteFilter::Combine(a, b) => {
                match (
                    Self::note_matches_filter(value, a),
                    Self::note_matches_filter(value, b),
                ) {
                    (None, None) => None,
                    (a, b) => Some(a.unwrap_or(true) && b.unwrap_or(true)),
                }
            }
            NoteFilter::Attempt { condition, fallback } => {
                Self::note_matches_filter(value, condition)
                    .or_else(|| Self::note_matches_filter(value, fallback))
            }
        }
    }

    /// Aggregates the eligible notes of one pool into [`PoolMeta`], returning
    /// `None` when the selector cannot be evaluated.
    #[allow(clippy::too_many_arguments)]
    fn pool_meta(
        &self,
        account: AccountId,
        pool: ShieldedPool,
        selector: &NoteFilter,
        target_height: TargetHeight,
        policy: ConfirmationsPolicy,
        exclude: &[NoteId],
        lock_filter: LockFilter<'_>,
    ) -> Option<PoolMeta> {
        let values: Vec<Zatoshis> = match pool {
            ShieldedPool::Sapling => self
                .eligible_sapling(account, target_height, Some(policy), exclude, lock_filter)
                .into_iter()
                .map(|note| {
                    note.note_value()
                        .expect("Sapling note values are within valid ZEC bounds by consensus")
                })
                .collect(),
            ShieldedPool::Ironwood => self
                .eligible_ironwood(account, target_height, Some(policy), exclude, lock_filter)
                .into_iter()
                .map(|note| {
                    note.note_value()
                        .expect("Ironwood note values are within valid ZEC bounds by consensus")
                })
                .collect(),
            ShieldedPool::Orchard => return None,
        };

        let mut count = 0usize;
        let mut total = Zatoshis::ZERO;
        for value in values {
            if Self::note_matches_filter(value, selector)? {
                count += 1;
                total = (total + value).expect(
                    "balance cannot overflow MAX_MONEY; mirrors upstream Balance::total",
                );
            }
        }
        Some(PoolMeta::new(count, total))
    }
}

impl InputSource for Wallet {
    type Error = WalletError;
    type AccountId = AccountId;
    type NoteRef = NoteId;

    fn get_spendable_note(
        &self,
        txid: &TxId,
        protocol: ShieldedPool,
        index: u32,
        target_height: TargetHeight,
        lock_filter: LockFilter<'_>,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        let Some(index) = u16::try_from(index).ok() else {
            return Ok(None);
        };
        let note_id = NoteId::new(*txid, protocol, index);
        match protocol {
            ShieldedPool::Sapling => {
                if self.sapling_note_is_spent(&note_id, target_height)
                    || !self.lock_admits(&OutputRef::from(note_id), target_height, lock_filter)
                    || self.mined_height(txid).is_none()
                {
                    return Ok(None);
                }
                Ok(self
                    .sapling_received_note(note_id)
                    .map(|note| note.map_note(Note::Sapling)))
            }
            ShieldedPool::Ironwood => {
                if self.ironwood_note_is_spent(&note_id, target_height)
                    || !self.lock_admits(&OutputRef::from(note_id), target_height, lock_filter)
                    || self.mined_height(txid).is_none()
                {
                    return Ok(None);
                }
                Ok(self.ironwood_received_note(note_id).map(|note| {
                    note.map_note(|note| Note::Orchard {
                        note,
                        pool: orchard::ValuePool::Ironwood,
                    })
                }))
            }
            // The mint owns no ordinary-Orchard notes.
            ShieldedPool::Orchard => Ok(None),
        }
    }

    fn anchor_computable(
        &self,
        protocol: ShieldedPool,
        height: BlockHeight,
    ) -> Result<bool, Self::Error> {
        let checkpoint = match protocol {
            ShieldedPool::Sapling => self.sapling_tree.store().get_checkpoint(&height),
            ShieldedPool::Ironwood => self.ironwood_tree.store().get_checkpoint(&height),
            // The compatibility tree is maintained, so ordinary-Orchard
            // anchors are computable to the same extent.
            ShieldedPool::Orchard => self.orchard_tree.store().get_checkpoint(&height),
        };
        Ok(checkpoint.ok().flatten().is_some())
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        if self.ufvks.get(&account).is_none() {
            return Err(WalletError::AccountUnknown(account));
        }

        let mut sapling = Vec::new();
        let mut ironwood = Vec::new();
        let mut accumulated = Zatoshis::ZERO;

        // Pools are drawn on in the caller's preference order; within a pool
        // notes are taken oldest-first until the accumulation exceeds the
        // target, mirroring the upstream in-memory selector (the crossing
        // note is included).
        for pool in sources {
            match pool {
                ShieldedPool::Sapling => {
                    for note in self.eligible_sapling(
                        account,
                        target_height,
                        Some(confirmations_policy),
                        exclude,
                        lock_filter,
                    ) {
                        let take = match target_value {
                            TargetValue::AtLeast(target) => accumulated <= target,
                            // AllFunds selects every eligible note.
                            TargetValue::AllFunds(_) => true,
                        };
                        let value = note
                            .note_value()
                            .expect("Sapling note values are within valid ZEC bounds by consensus");
                        accumulated = (accumulated + value).expect(
                            "selection cannot overflow MAX_MONEY; mirrors upstream Balance::total",
                        );
                        if !take {
                            break;
                        }
                        sapling.push(note);
                    }
                }
                ShieldedPool::Ironwood => {
                    for note in self.eligible_ironwood(
                        account,
                        target_height,
                        Some(confirmations_policy),
                        exclude,
                        lock_filter,
                    ) {
                        let take = match target_value {
                            TargetValue::AtLeast(target) => accumulated <= target,
                            TargetValue::AllFunds(_) => true,
                        };
                        let value = note.note_value().expect(
                            "Ironwood note values are within valid ZEC bounds by consensus",
                        );
                        accumulated = (accumulated + value).expect(
                            "selection cannot overflow MAX_MONEY; mirrors upstream Balance::total",
                        );
                        if !take {
                            break;
                        }
                        ironwood.push(note);
                    }
                }
                // The mint owns no ordinary-Orchard inputs.
                ShieldedPool::Orchard => {}
            }
        }

        Ok(ReceivedNotes::new(sapling, Vec::new(), ironwood))
    }

    fn select_unspent_notes(
        &self,
        account: Self::AccountId,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        if self.ufvks.get(&account).is_none() {
            return Err(WalletError::AccountUnknown(account));
        }

        let mut sapling = Vec::new();
        let mut ironwood = Vec::new();
        for pool in sources {
            match pool {
                ShieldedPool::Sapling => sapling.extend(self.eligible_sapling(
                    account,
                    target_height,
                    None,
                    exclude,
                    lock_filter,
                )),
                ShieldedPool::Ironwood => ironwood.extend(self.eligible_ironwood(
                    account,
                    target_height,
                    None,
                    exclude,
                    lock_filter,
                )),
                ShieldedPool::Orchard => {}
            }
        }
        Ok(ReceivedNotes::new(sapling, Vec::new(), ironwood))
    }

    fn get_account_metadata(
        &self,
        account: Self::AccountId,
        selector: &NoteFilter,
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<AccountMeta, Self::Error> {
        if self.ufvks.get(&account).is_none() {
            return Err(WalletError::AccountUnknown(account));
        }

        // Metadata describes spendability structure, so the minimal
        // symmetrical policy (one confirmation) is used, mirroring
        // `zcash_client_memory`.
        let policy = ConfirmationsPolicy::MIN;

        let sapling_meta = self.pool_meta(
            account,
            ShieldedPool::Sapling,
            selector,
            target_height,
            policy,
            exclude,
            lock_filter,
        );
        let ironwood_meta = self.pool_meta(
            account,
            ShieldedPool::Ironwood,
            selector,
            target_height,
            policy,
            exclude,
            lock_filter,
        );
        // Ordinary Orchard is not a tracked pool of this wallet.
        Ok(AccountMeta::new(sapling_meta, None, ironwood_meta))
    }

    fn get_unspent_transparent_output(
        &self,
        _outpoint: &transparent::bundle::OutPoint,
        _target_height: TargetHeight,
    ) -> Result<Option<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        // Transparent support is outbound-only: the mint never spends
        // transparent inputs.
        Ok(None)
    }

    fn get_spendable_transparent_outputs(
        &self,
        _address: &transparent::address::TransparentAddress,
        _target_height: TargetHeight,
        _confirmations_policy: ConfirmationsPolicy,
        _output_filter: CoinbaseFilter,
        _lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        // Transparent support is outbound-only: the mint never spends
        // transparent inputs.
        Ok(Vec::new())
    }

    fn select_spendable_transparent_outputs(
        &self,
        _account: Self::AccountId,
        _target_height: TargetHeight,
        _confirmations_policy: ConfirmationsPolicy,
        _output_filter: CoinbaseFilter,
        _address_allow_list: Option<&[transparent::address::TransparentAddress]>,
        _target_value: TargetValue,
        _max_inputs: usize,
        _fee_rule: &StandardFeeRule,
        _lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        // Transparent support is outbound-only: the mint never spends
        // transparent inputs.
        Ok(Vec::new())
    }
}
