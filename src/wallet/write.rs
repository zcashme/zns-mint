//! Upstream write-side wallet operations: [`OutputLockStore`] and
//! [`WalletWrite`] — plus the ZNS Name Note ingestion lane, which the
//! upstream write surface cannot express (see [`Wallet::store_name_note`]).

use std::collections::{BTreeSet, HashSet};
use std::convert::Infallible;
use std::time::SystemTime;

use incrementalmerkletree::{Hashable, Position};
use secrecy::SecretVec;
use shardtree::store::{Checkpoint, ShardStore, TreeState};
use shardtree::ShardTree;
use transparent::bundle::OutPoint;
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, DecryptedTransaction,
    ScannedBlock, ScannedBundles, SentTransaction, SentTransactionOutput, TransactionStatus,
    TransactionsInvolvingAddress, WalletWrite, chain::ChainState,
    error::RewindError, locking::{LockError, LockOwner, OutputLockStore},
    scanning::ScanPriority,
};
use zcash_client_backend::wallet::{
    NoteId, OutputRef, WalletIronwoodOutput, WalletTransparentOutput,
};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;
use zcash_protocol::{PoolType, ShieldedPool};
use zip32::{AccountId, DiversifierIndex};

use super::{
    Wallet,
    read::{WalletError, account_birthday, next_height},
};
use crate::mint::REGISTRY_ACCOUNT;

impl Wallet {
    /// Returns the account that owns a wallet output, if the reference names
    /// a currently retained Sapling, Ironwood, or transparent output.
    fn output_account(&self, output: &OutputRef) -> Option<AccountId> {
        match output.pool() {
            PoolType::Shielded(ShieldedPool::Sapling) => {
                let index = u16::try_from(output.output_index()).ok()?;
                self.sapling_notes
                    .get(&NoteId::new(*output.txid(), ShieldedPool::Sapling, index))
                    .map(|note| *note.account_id())
            }
            PoolType::Shielded(ShieldedPool::Ironwood) => {
                let index = u16::try_from(output.output_index()).ok()?;
                self.ironwood_notes
                    .get(&NoteId::new(*output.txid(), ShieldedPool::Ironwood, index))
                    .map(|note| *note.account_id())
            }
            PoolType::TRANSPARENT => self
                .transparent_outputs
                .get(&OutPoint::new(
                    (*output.txid()).into(),
                    output.output_index(),
                ))
                .and_then(|utxo| utxo.recipient_account().copied()),
            // Ordinary Orchard deliberately has no received-note table.
            PoolType::Shielded(ShieldedPool::Orchard) => None,
        }
    }

    /// True when a foreign lock remains active at the most recently supplied
    /// Zebra tip. Without a known tip, an existing foreign lock is retained
    /// conservatively.
    fn is_foreign_lock_active(&self, output: &OutputRef, owner: LockOwner) -> bool {
        match self.locks.get(output) {
            Some((existing_owner, expiry)) if *existing_owner != owner => {
                match self.zebra_tip {
                    Some(tip) => *expiry > tip,
                    None => true,
                }
            }
            _ => false,
        }
    }

    /// The largest height at or below `max_height` that every one of the
    /// three trees has retained as a checkpoint and that the wallet has
    /// applied (or, before any block is applied, the boot seed checkpoint
    /// common to all three trees).
    fn common_truncation_height(&self, max_height: BlockHeight) -> Option<BlockHeight> {
        let applied = self
            .blocks
            .range(..=max_height)
            .next_back()
            .map(|(height, _)| *height);
        if applied.is_some() {
            return applied;
        }
        // No applied block qualifies. The boot seed checkpoint remains
        // truncatable when all three trees agree on the same floor.
        let floors = [
            self.sapling_tree.store().min_checkpoint_id().ok().flatten(),
            self.orchard_tree.store().min_checkpoint_id().ok().flatten(),
            self.ironwood_tree.store().min_checkpoint_id().ok().flatten(),
        ];
        match floors {
            [Some(a), Some(b), Some(c)] if a == b && b == c && a <= max_height => Some(a),
            _ => None,
        }
    }
}

impl OutputLockStore for Wallet {
    type Error = WalletError;
    type AccountId = AccountId;

    fn lock_outputs(
        &mut self,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<usize, LockError<Self::Error>> {
        // Preflight is what makes acquisition all-or-nothing.
        for output in outputs {
            if self.output_account(output).is_none() || self.is_foreign_lock_active(output, owner) {
                return Err(LockError::LockFailure(*output));
            }
        }

        for output in outputs {
            self.locks.insert(*output, (owner, lock_expiry_height));
        }
        Ok(outputs.len())
    }

    fn unlock_output(&mut self, output: &OutputRef, owner: LockOwner) -> Result<bool, Self::Error> {
        match self.locks.get(output) {
            Some((existing_owner, _)) if *existing_owner == owner => {
                self.locks.remove(output);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn clear_locked_outputs(&mut self, account: Self::AccountId) -> Result<usize, Self::Error> {
        let outputs = self
            .locks
            .keys()
            .copied()
            .filter(|output| self.output_account(output) == Some(account))
            .collect::<Vec<_>>();
        let count = outputs.len();
        for output in outputs {
            self.locks.remove(&output);
        }
        Ok(count)
    }

    fn get_locked_outputs(&self, account: Self::AccountId) -> Result<Vec<OutputRef>, Self::Error> {
        Ok(self
            .locks
            .keys()
            .copied()
            .filter(|output| self.output_account(output) == Some(account))
            .collect())
    }
}

/// Ensures a checkpoint exists at `height` for a tree that has just appended
/// the commitments of the block ending at that height.
///
/// Every accepted height is checkpointed in all three pools — including pools
/// with no commitments in that block — so anchors remain computable at each
/// block boundary and reorg truncation is exact.
fn ensure_block_checkpoint<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<shardtree::store::memory::MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
    height: BlockHeight,
    final_tree_size: u32,
) -> Result<(), WalletError>
where
    shardtree::store::memory::MemoryShardStore<H, BlockHeight>:
        ShardStore<H = H, CheckpointId = BlockHeight, Error = Infallible>,
    H: Hashable + PartialEq + Clone,
{
    if tree.store().get_checkpoint(&height)?.is_none() {
        let tree_state = if final_tree_size == 0 {
            TreeState::Empty
        } else {
            TreeState::AtPosition(Position::from(u64::from(final_tree_size) - 1))
        };
        tree.store_mut()
            .add_checkpoint(height, Checkpoint::from_parts(tree_state, BTreeSet::new()))
            .map_err(shardtree::error::ShardTreeError::Storage)?;
    }
    Ok(())
}

/// Appends one scanned block's bundle commitments with the scanner-provided
/// retention markers, then checkpoints the accepted height.
fn append_block_commitments<H, Nf, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<
        shardtree::store::memory::MemoryShardStore<H, BlockHeight>,
        DEPTH,
        SHARD_HEIGHT,
    >,
    bundles: &ScannedBundles<H, Nf>,
    height: BlockHeight,
) -> Result<(), WalletError>
where
    shardtree::store::memory::MemoryShardStore<H, BlockHeight>:
        ShardStore<H = H, CheckpointId = BlockHeight, Error = Infallible>,
    H: Hashable + PartialEq + Clone,
{
    for (commitment, retention) in bundles.commitments() {
        tree.append(commitment.clone(), *retention)?;
    }
    ensure_block_checkpoint(tree, height, bundles.final_tree_size())
}

impl WalletWrite for Wallet {
    type UtxoRef = OutPoint;

    fn create_account(
        &mut self,
        _account_name: &str,
        _seed: &SecretVec<u8>,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(AccountId, UnifiedSpendingKey), WalletError> {
        // Accounts 0 and 1 are installed once at boot; the database never
        // creates spending keys, and no seed crosses this boundary.
        Err(WalletError::FixedAccountsOnly)
    }

    fn import_account_hd(
        &mut self,
        _account_name: &str,
        _seed: &SecretVec<u8>,
        _account_index: zip32::AccountId,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), WalletError> {
        Err(WalletError::FixedAccountsOnly)
    }

    fn import_account_ufvk(
        &mut self,
        _account_name: &str,
        _unified_key: &UnifiedFullViewingKey,
        _birthday: &AccountBirthday,
        _purpose: AccountPurpose,
        _key_source: Option<&str>,
    ) -> Result<Self::Account, WalletError> {
        // The viewing keys of accounts 0 and 1 are installed once at boot.
        Err(WalletError::FixedAccountsOnly)
    }

    fn delete_account(&mut self, _account: AccountId) -> Result<(), WalletError> {
        // The namespace cannot survive deletion of either account.
        Err(WalletError::FixedAccountsOnly)
    }

    fn get_next_available_address(
        &mut self,
        _account: AccountId,
        _request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, WalletError> {
        // This wallet generates no addresses; receivers are derived on demand
        // from the fixed UFVKs by the application.
        Err(WalletError::FixedAccountsOnly)
    }

    fn get_address_for_index(
        &mut self,
        _account: AccountId,
        _diversifier_index: DiversifierIndex,
        _request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, WalletError> {
        Err(WalletError::FixedAccountsOnly)
    }

    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), WalletError> {
        // The Zebra consensus tip is chain state, recorded exactly as
        // supplied; reorg handling is the caller's truncate/rescan loop.
        self.zebra_tip = Some(tip_height);
        Ok(())
    }

    fn prune_scan_queue_below(
        &mut self,
        _height: BlockHeight,
        _retain_with_priority: Option<ScanPriority>,
    ) -> Result<u64, WalletError> {
        // There is no scan queue: scanning is one linear range.
        Ok(0)
    }

    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<AccountId>>,
    ) -> Result<(), WalletError> {
        let Some(first) = blocks.first() else {
            return Ok(());
        };

        // Continuity: the batch must start exactly at the block after
        // `from_state`, heights must be sequential, and `from_state` must be
        // the wallet's applied tip. All checks run before any mutation.
        if next_height(from_state.block_height()) != first.height() {
            return Err(WalletError::ChainDiscontinuity(first.height()));
        }
        for pair in blocks.windows(2) {
            if next_height(pair[0].height()) != pair[1].height() {
                return Err(WalletError::ChainDiscontinuity(pair[1].height()));
            }
        }
        match self.blocks.last_key_value() {
            Some((&applied_tip, metadata)) if applied_tip == from_state.block_height() => {
                if metadata.block_hash() != from_state.block_hash() {
                    return Err(WalletError::ChainDiscontinuity(applied_tip));
                }
            }
            // Either a gap below our applied tip (stale or replayed state) or
            // a from-state above it: both would desynchronize note commitment
            // positions.
            Some((&applied_tip, _)) => return Err(WalletError::ChainDiscontinuity(applied_tip)),
            // First batch after boot seeding; the trees were seeded from the
            // checkpoint at `from_state.block_height()`.
            None => {}
        }

        // Commitment trees are mutated before the infallible tables: if a
        // tree operation fails, no wallet state has been applied and
        // `truncate_to_height` can repair the trees.
        for block in &blocks {
            let height = block.height();
            append_block_commitments(&mut self.sapling_tree, block.sapling(), height)?;
            append_block_commitments(&mut self.orchard_tree, block.orchard(), height)?;
            append_block_commitments(&mut self.ironwood_tree, block.ironwood(), height)?;
        }

        for block in blocks {
            let height = block.height();

            for wtx in block.transactions() {
                let txid = wtx.txid();
                self.transaction_statuses
                    .insert(txid, TransactionStatus::Mined(height));
                self.transaction_indices.insert(txid, wtx.block_index());

                for output in wtx.sapling_outputs() {
                    let note_id = NoteId::new(
                        txid,
                        ShieldedPool::Sapling,
                        // Sapling bundle output counts are bounded far below
                        // 2^16 by consensus; upstream in-memory wallets make
                        // the same assumption.
                        u16::try_from(output.index())
                            .expect("Sapling output index fits in u16"),
                    );
                    self.sapling_notes.insert(note_id, output.clone());
                    if let Some(nf) = output.nf() {
                        self.sapling_nullifiers.insert(*nf, note_id);
                    }
                }
                for output in wtx.ironwood_outputs() {
                    let note_id = NoteId::new(
                        txid,
                        ShieldedPool::Ironwood,
                        u16::try_from(output.index())
                            .expect("Ironwood action index fits in u16"),
                    );
                    self.ironwood_notes.insert(note_id, output.clone());
                    if let Some(nf) = output.nf() {
                        self.ironwood_nullifiers.insert(*nf, note_id);
                    }
                }
                for utxo in wtx.transparent_outputs() {
                    self.transparent_outputs
                        .insert(utxo.outpoint().clone(), utxo.clone());
                }
            }

            // Spends are resolved from the block's full nullifier map rather
            // than only the scanner's `WalletTx` spend lists: notes received
            // earlier in this same batch are not yet in the nullifier set the
            // scanner matched against, and a note can be created and spent
            // within one batch.
            for (_index, txid, nullifiers) in block.sapling().nullifier_map() {
                for nf in nullifiers {
                    if let Some(note_id) = self.sapling_nullifiers.get(nf) {
                        self.sapling_note_spends.insert(*note_id, *txid);
                    }
                }
            }
            for (_index, txid, nullifiers) in block.ironwood().nullifier_map() {
                for nf in nullifiers {
                    if let Some(note_id) = self.ironwood_nullifiers.get(nf) {
                        self.ironwood_note_spends.insert(*note_id, *txid);
                    }
                }
            }

            self.blocks.insert(height, block.to_block_metadata());
        }
        Ok(())
    }

    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput<AccountId>,
    ) -> Result<Self::UtxoRef, WalletError> {
        // Stored as a chain observation only: under the outbound-only
        // transparent policy it is never surfaced as a spendable input.
        let outpoint = output.outpoint().clone();
        self.transparent_outputs.insert(outpoint.clone(), output.clone());
        Ok(outpoint)
    }

    fn store_decrypted_tx(
        &mut self,
        received_tx: DecryptedTransaction<Transaction, AccountId>,
    ) -> Result<(), WalletError> {
        let tx = received_tx.tx();
        let txid = tx.txid();
        self.transactions.insert(txid, tx.clone());

        match received_tx.mined_height() {
            Some(height) => {
                self.transaction_statuses
                    .insert(txid, TransactionStatus::Mined(height));
            }
            None => {
                // A mempool observation must not downgrade a known mined
                // status.
                self.transaction_statuses
                    .entry(txid)
                    .or_insert(TransactionStatus::NotInMainChain);
            }
        }

        // Memos are stored for the owned pools. Received notes themselves are
        // established only by `put_blocks`: a decrypted output carries no
        // nullifier or commitment position with which to maintain them.
        for output in received_tx.sapling_outputs() {
            if let Ok(memo) = Memo::from_bytes(output.memo().as_slice()) {
                self.memos.insert(
                    NoteId::new(
                        txid,
                        ShieldedPool::Sapling,
                        u16::try_from(output.index())
                            .expect("Sapling output index fits in u16"),
                    ),
                    memo,
                );
            }
        }
        for output in received_tx.ironwood_outputs() {
            if let Ok(memo) = Memo::from_bytes(output.memo().as_slice()) {
                self.memos.insert(
                    NoteId::new(
                        txid,
                        ShieldedPool::Ironwood,
                        u16::try_from(output.index())
                            .expect("Ironwood action index fits in u16"),
                    ),
                    memo,
                );
            }
        }
        Ok(())
    }

    fn set_tx_trust(&mut self, txid: TxId, trusted: bool) -> Result<(), WalletError> {
        if trusted {
            self.trusted_transactions.insert(txid);
        } else {
            self.trusted_transactions.remove(&txid);
        }
        Ok(())
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<AccountId>],
    ) -> Result<(), WalletError> {
        for sent in transactions {
            let tx = sent.tx();
            let txid = tx.txid();
            self.transactions.insert(txid, tx.clone());
            // Not yet broadcast-mined; a previously learned mined status is
            // never downgraded.
            self.transaction_statuses
                .entry(txid)
                .or_insert(TransactionStatus::NotInMainChain);
            self.sent_outputs
                .insert(txid, sent.outputs().iter().map(|o| {
                    SentTransactionOutput::from_parts(
                        o.output_index(),
                        o.recipient().clone(),
                        o.value(),
                        o.memo().cloned(),
                    )
                }).collect());

            // Record spends of wallet outputs from the raw bundles, then
            // release the locks on every output now recorded as spent: the
            // spend records themselves protect against double selection.
            if let Some(bundle) = tx.sapling_bundle() {
                for spend in bundle.shielded_spends() {
                    if let Some(note_id) = self.sapling_nullifiers.get(spend.nullifier()) {
                        self.sapling_note_spends.insert(*note_id, txid);
                        self.locks.remove(&OutputRef::from(*note_id));
                    }
                }
            }
            if let Some(bundle) = tx.ironwood_bundle() {
                for action in bundle.actions() {
                    if let Some(note_id) = self.ironwood_nullifiers.get(action.nullifier()) {
                        self.ironwood_note_spends.insert(*note_id, txid);
                        self.locks.remove(&OutputRef::from(*note_id));
                    }
                }
            }
            for outpoint in sent.utxos_spent() {
                let outpoint = outpoint.clone();
                self.locks.remove(&OutputRef::new(
                    *outpoint.txid(),
                    PoolType::TRANSPARENT,
                    outpoint.n(),
                ));
                self.transparent_spends.insert((txid, outpoint.clone()));
                self.transparent_output_spends.insert(outpoint, txid);
            }
        }
        Ok(())
    }

    fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, WalletError> {
        let Some(target) = self.common_truncation_height(max_height) else {
            if self.blocks.is_empty() {
                // Nothing has been applied; there is nothing to truncate.
                return Ok(max_height);
            }
            return Err(WalletError::TruncationTargetUnavailable(max_height));
        };

        // Trees first: on failure the tables remain untouched.
        for result in [
            self.sapling_tree.truncate_to_checkpoint(&target),
            self.orchard_tree.truncate_to_checkpoint(&target),
            self.ironwood_tree.truncate_to_checkpoint(&target),
        ] {
            if !result.map_err(WalletError::CommitmentTree)? {
                return Err(WalletError::TruncationTargetUnavailable(target));
            }
        }

        // Un-mine transactions above the truncation point. Notes, memos, and
        // sent outputs are deliberately retained — memo data is not
        // recoverable from the chain, and un-mined notes are excluded from
        // spendability by the status-based eligibility rules.
        for status in self.transaction_statuses.values_mut() {
            if let TransactionStatus::Mined(height) = *status {
                if height > target {
                    *status = TransactionStatus::NotInMainChain;
                }
            }
        }
        self.blocks.retain(|height, _| *height <= target);
        Ok(target)
    }

    fn truncate_to_chain_state(&mut self, chain_state: ChainState) -> Result<(), WalletError> {
        let height = chain_state.block_height();
        match self.blocks.get(&height) {
            Some(metadata) if metadata.block_hash() == chain_state.block_hash() => {}
            // A recorded block at that height with a different hash means the
            // caller is rewinding onto a fork this wallet never applied.
            Some(_) => return Err(WalletError::ChainDiscontinuity(height)),
            // A height outside the applied range is either below the scan
            // floor or above the applied tip; both are safe no-op-ish
            // truncations because the applied blocks are contiguous.
            None => {}
        }
        self.truncate_to_height(height).map(|_| ())
    }

    fn rewind_to_chain_state(
        &mut self,
        chain_state: ChainState,
        reset_account_birthdays: HashSet<AccountId>,
    ) -> Result<(), RewindError<AccountId, WalletError>> {
        for account in &reset_account_birthdays {
            if !self.ufvks.contains_key(account) {
                return Err(RewindError::DataSource(WalletError::AccountUnknown(
                    *account,
                )));
            }
        }
        // Account birthdays are fixed application identity and are never
        // lowered; a rewind below the birthday floor can only proceed when no
        // reset was requested.
        if !reset_account_birthdays.is_empty()
            && next_height(chain_state.block_height()) < account_birthday()
        {
            let birthdays = self
                .ufvks
                .keys()
                .map(|account| (*account, account_birthday()))
                .collect();
            return Err(RewindError::RewindBeyondBirthdays(birthdays));
        }
        self.truncate_to_chain_state(chain_state)
            .map_err(RewindError::DataSource)
    }

    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        _account_id: AccountId,
        _n: usize,
    ) -> Result<Vec<(transparent::address::TransparentAddress, zcash_client_backend::wallet::TransparentAddressMetadata)>, WalletError>
    {
        // Neither fixed account owns, derives, or reserves a transparent
        // receiver.
        Err(WalletError::FixedAccountsOnly)
    }

    fn reserve_next_n_internal_addresses(
        &mut self,
        _account_id: AccountId,
        _n: usize,
    ) -> Result<Vec<(transparent::address::TransparentAddress, zcash_client_backend::wallet::TransparentAddressMetadata)>, WalletError>
    {
        Err(WalletError::FixedAccountsOnly)
    }

    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: TransactionStatus,
    ) -> Result<(), WalletError> {
        self.transaction_statuses.insert(txid, status);
        Ok(())
    }

    fn schedule_next_check(
        &mut self,
        _address: &transparent::address::TransparentAddress,
        _offset_seconds: u32,
    ) -> Result<Option<SystemTime>, WalletError> {
        // No transparent address is tracked, so there is nothing to schedule.
        Ok(None)
    }

    fn mark_transparent_addresses_exposed(
        &mut self,
        exposures: &[(transparent::address::TransparentAddress, BlockHeight)],
    ) -> Result<(), WalletError> {
        // The wallet tracks no transparent addresses; an empty request is a
        // no-op, any other is unrecognized.
        if exposures.is_empty() {
            Ok(())
        } else {
            Err(WalletError::FixedAccountsOnly)
        }
    }

    fn notify_address_checked(
        &mut self,
        _request: TransactionsInvolvingAddress,
        _as_of_height: BlockHeight,
    ) -> Result<(), WalletError> {
        // No address-check state is maintained.
        Ok(())
    }
}

impl Wallet {
    /// Stores one decrypted ZNS Name Note as the Registry account's ordinary
    /// received Ironwood note, at its consensus-derived tree position.
    ///
    /// The standard scanning lane cannot see Name Notes (its domain re-derives
    /// the commitment from rseed and rejects the ZNS-derived cmx), so the
    /// orchestrator's ZNS pass supplies them here. Storage mirrors
    /// `put_blocks`: note table + memo + mined status. `ordinal` is the
    /// action's index in the block's full Ironwood commitment stream.
    pub fn store_name_note(
        &mut self,
        scanned: &ScannedBlock<AccountId>,
        ordinal: usize,
        txid: TxId,
        action_index: usize,
        note: orchard::note::Note,
        ephemeral_key: zcash_note_encryption::EphemeralKeyBytes,
        memo: [u8; 512],
    ) -> Option<()> {
        let fvk = self.ufvks.get(&REGISTRY_ACCOUNT)?.orchard()?.clone();
        let bundles = scanned.ironwood();
        let start_size = bundles
            .final_tree_size()
            .checked_sub(u32::try_from(bundles.commitments().len()).ok()?)?;
        let position = Position::from(u64::from(start_size) + ordinal as u64);
        let note_id = NoteId::new(txid, ShieldedPool::Ironwood, u16::try_from(action_index).ok()?);
        self.ironwood_notes.insert(
            note_id,
            WalletIronwoodOutput::from_parts(
                action_index,
                ephemeral_key,
                (note.clone(), orchard::ValuePool::Ironwood),
                false,
                position,
                Some(note.nullifier(&fvk)),
                REGISTRY_ACCOUNT,
                Some(zip32::Scope::External),
            ),
        );
        self.ironwood_nullifiers
            .insert(note.nullifier(&fvk), note_id);
        self.memos.insert(
            note_id,
            Memo::Future(
                zcash_protocol::memo::MemoBytes::from_bytes(&memo)
                    .expect("512-byte memo always parses"),
            ),
        );
        self.transaction_statuses.insert(
            txid,
            zcash_client_backend::data_api::TransactionStatus::Mined(scanned.height()),
        );
        Some(())
    }
}
