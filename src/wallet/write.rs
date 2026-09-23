//! Upstream write-side wallet operations: [`OutputLockStore`] and
//! [`WalletWrite`] — plus the ZNS Name Note ingestion lane, which the
//! upstream write surface cannot express (see [`Wallet::store_name_note`]).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::Infallible;
use std::time::SystemTime;

use incrementalmerkletree::{Hashable, Marking, Position, Retention};
use secrecy::SecretVec;
use shardtree::store::memory::MemoryShardStore;
use shardtree::store::{Checkpoint, ShardStore, TreeState};
use shardtree::ShardTree;
use transparent::bundle::OutPoint;
use zcash_client_backend::data_api::{
    chain::ChainState,
    error::RewindError,
    locking::{LockError, LockOwner, OutputLockStore},
    scanning::ScanPriority,
    AccountBirthday, AccountPurpose, DecryptedTransaction, ScannedBlock, ScannedBundles,
    SentTransaction, SentTransactionOutput, TransactionStatus, TransactionsInvolvingAddress,
    WalletWrite,
};
use zcash_client_backend::wallet::{
    NoteId, OutputRef, Recipient, WalletIronwoodOutput, WalletTransparentOutput,
};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::Memo;
use zcash_protocol::{PoolType, ShieldedPool};
use zip32::{AccountId, DiversifierIndex};

use super::{
    read::{next_height, WalletError},
    TreeError, Wallet, MAX_CHECKPOINTS,
};
use crate::mint::REGISTRY_ACCOUNT;

impl<P: Parameters> Wallet<P> {
    /// Returns the account that owns a wallet output, if the reference
    /// names a currently retained Sapling or Ironwood note.
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
            // The wallet owns no transparent output, ever: the mint never
            // receives, stores, or spends transparent money.
            PoolType::TRANSPARENT => None,
            // Ordinary Orchard deliberately has no received-note table;
            // `put_blocks_marked` rejects decryptable Orchard outputs.
            PoolType::Shielded(ShieldedPool::Orchard) => None,
        }
    }

    /// True when a foreign lock outlives the wallet's position.
    fn is_foreign_lock_active(&self, output: &OutputRef, owner: LockOwner) -> bool {
        match self.locks.get(output) {
            Some((existing_owner, expiry)) if *existing_owner != owner => {
                *expiry > self.tip().block_height()
            }
            _ => false,
        }
    }

    /// Lowers birthday metadata for acknowledged accounts when `new_birthday`
    /// is strictly below the current value. Birthdays are never raised.
    fn lower_account_birthdays(
        &mut self,
        reset_account_birthdays: &HashSet<AccountId>,
        new_birthday: BlockHeight,
    ) {
        for account in reset_account_birthdays {
            if let Some(birthday) = self.account_birthdays.get_mut(account) {
                if new_birthday < *birthday {
                    *birthday = new_birthday;
                }
            }
        }
    }

    /// The oldest retained checkpoint — the deepest height the trees can
    /// still truncate to, identical across the three trees by the commit
    /// discipline. `None` before the first applied block.
    fn retained_floor(&self) -> Option<BlockHeight> {
        // The store error type is `Infallible`; `.ok()` cannot lose one.
        self.sapling_tree.store().min_checkpoint_id().ok().flatten()
    }

    /// The deepest applied block at or below `max_height` — the candidate
    /// `try_truncate_trees_to` verifies against the trees.
    fn common_truncation_height(&self, max_height: BlockHeight) -> Option<BlockHeight> {
        self.blocks
            .range(..=max_height)
            .next_back()
            .map(|(height, _)| *height)
    }

    /// Whether every tree can truncate to `height` as a retained checkpoint.
    ///
    /// Truncation is applied to cloned trees first; the wallet's trees are
    /// replaced only when all three succeed, so a failure leaves them unchanged.
    fn try_truncate_trees_to(&mut self, height: BlockHeight) -> Result<bool, WalletError> {
        let present = [
            self.sapling_tree
                .store()
                .get_checkpoint(&height)
                .ok()
                .flatten()
                .is_some(),
            self.orchard_tree
                .store()
                .get_checkpoint(&height)
                .ok()
                .flatten()
                .is_some(),
            self.ironwood_tree
                .store()
                .get_checkpoint(&height)
                .ok()
                .flatten()
                .is_some(),
        ];
        if present.iter().any(|have| !have) {
            return Ok(false);
        }

        let mut sapling = clone_shard_tree(&self.sapling_tree)?;
        let mut orchard = clone_shard_tree(&self.orchard_tree)?;
        let mut ironwood = clone_shard_tree(&self.ironwood_tree)?;
        if !sapling
            .truncate_to_checkpoint(&height)
            .map_err(WalletError::CommitmentTree)?
            || !orchard
                .truncate_to_checkpoint(&height)
                .map_err(WalletError::CommitmentTree)?
            || !ironwood
                .truncate_to_checkpoint(&height)
                .map_err(WalletError::CommitmentTree)?
        {
            return Ok(false);
        }
        self.sapling_tree = sapling;
        self.orchard_tree = orchard;
        self.ironwood_tree = ironwood;
        Ok(true)
    }

    /// Drops applied blocks above `height` and removes effects that belonged
    /// only to the abandoned branch.
    ///
    /// Received notes (and their nullifiers, memos, and indexes) created above
    /// `height` are deleted — otherwise they linger as phantom pending value.
    /// Spend links whose spending transaction was mined above `height` and
    /// was observed only through scanning (no retained raw transaction) are
    /// cleared so the note is selectable again; locally built spends keep
    /// their raw transaction and stay blocked until expiry.
    fn drop_applied_above(&mut self, height: BlockHeight) {
        let orphaned: HashSet<TxId> = self
            .transaction_statuses
            .iter()
            .filter_map(|(txid, status)| match status {
                TransactionStatus::Mined(mined) if *mined > height => Some(*txid),
                _ => None,
            })
            .collect();

        self.sapling_notes
            .retain(|note_id, _| !orphaned.contains(note_id.txid()));
        self.ironwood_notes
            .retain(|note_id, _| !orphaned.contains(note_id.txid()));
        self.sapling_nullifiers
            .retain(|_, note_id| !orphaned.contains(note_id.txid()));
        self.ironwood_nullifiers
            .retain(|_, note_id| !orphaned.contains(note_id.txid()));
        self.memos
            .retain(|note_id, _| !orphaned.contains(note_id.txid()));
        self.transaction_indices
            .retain(|txid, _| !orphaned.contains(txid));

        // Scanned-only spends have no raw transaction; after un-mining they
        // would block forever. Locally built spends remain until expiry.
        let scanned_only_spends: HashSet<TxId> = orphaned
            .iter()
            .filter(|txid| !self.transactions.contains_key(*txid))
            .copied()
            .collect();
        self.sapling_note_spends.retain(|note_id, spend_txid| {
            self.sapling_notes.contains_key(note_id) && !scanned_only_spends.contains(spend_txid)
        });
        self.ironwood_note_spends.retain(|note_id, spend_txid| {
            self.ironwood_notes.contains_key(note_id) && !scanned_only_spends.contains(spend_txid)
        });

        for status in self.transaction_statuses.values_mut() {
            if let TransactionStatus::Mined(mined) = *status {
                if mined > height {
                    *status = TransactionStatus::NotInMainChain;
                }
            }
        }

        self.sapling_tree_shard_end_heights
            .retain(|_, end| *end <= height);
        self.orchard_tree_shard_end_heights
            .retain(|_, end| *end <= height);
        self.ironwood_tree_shard_end_heights
            .retain(|_, end| *end <= height);

        self.blocks.retain(|h, _| *h <= height);
    }
}

impl<P: Parameters> OutputLockStore for Wallet<P> {
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
        let target = next_height(self.tip().block_height());
        Ok(self
            .locks
            .iter()
            .filter(|(output, (_, expiry))| {
                self.output_account(output) == Some(account) && *expiry >= target
            })
            .map(|(output, _)| *output)
            .collect())
    }
}

/// Deep-copies an in-memory note commitment tree via its store API.
///
/// `ShardTree` / `MemoryShardStore` are not `Clone`; this rebuilds an
/// equivalent tree so callers can mutate a candidate and commit only on
/// success.
pub(super) fn clone_shard_tree<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
) -> Result<ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>, TreeError>
where
    H: Hashable + Clone + PartialEq,
{
    let src = tree.store();
    let mut dst = MemoryShardStore::empty();

    for root in src
        .get_shard_roots()
        .map_err(shardtree::error::ShardTreeError::Storage)?
    {
        if let Some(shard) = src
            .get_shard(root)
            .map_err(shardtree::error::ShardTreeError::Storage)?
        {
            dst.put_shard(shard)
                .map_err(shardtree::error::ShardTreeError::Storage)?;
        }
    }

    dst.put_cap(
        src.get_cap()
            .map_err(shardtree::error::ShardTreeError::Storage)?,
    )
    .map_err(shardtree::error::ShardTreeError::Storage)?;

    let checkpoint_count = src
        .checkpoint_count()
        .map_err(shardtree::error::ShardTreeError::Storage)?;
    src.for_each_checkpoint(checkpoint_count, |id, checkpoint| {
        dst.add_checkpoint(*id, checkpoint.clone())
    })
    .map_err(shardtree::error::ShardTreeError::Storage)?;

    for id in src
        .retained_checkpoints()
        .map_err(shardtree::error::ShardTreeError::Storage)?
    {
        dst.add_retained_checkpoint(id)
            .map_err(shardtree::error::ShardTreeError::Storage)?;
    }

    Ok(ShardTree::new(dst, MAX_CHECKPOINTS))
}

/// Ensures a checkpoint exists at `height` for a tree that has just appended
/// the commitments of the block ending at that height.
///
/// Every accepted height is checkpointed in all three pools — including pools
/// with no commitments in that block — so anchors remain computable at each
/// block boundary and reorg truncation is exact.
///
/// The store door bypasses the ordering check that guards `ShardTree::append`,
/// so the height must exceed every existing checkpoint id. Heights arrive
/// monotonically through `put_blocks_marked`'s continuity checks; anything
/// else is a chain discontinuity — refused here rather than accepted as a
/// time-inverted checkpoint.
fn ensure_block_checkpoint<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<
        shardtree::store::memory::MemoryShardStore<H, BlockHeight>,
        DEPTH,
        SHARD_HEIGHT,
    >,
    height: BlockHeight,
    final_tree_size: u32,
) -> Result<(), WalletError>
where
    shardtree::store::memory::MemoryShardStore<H, BlockHeight>:
        ShardStore<H = H, CheckpointId = BlockHeight, Error = Infallible>,
    H: Hashable + PartialEq + Clone,
{
    if tree.store().get_checkpoint(&height)?.is_none() {
        if tree.store().max_checkpoint_id()?.as_ref() >= Some(&height) {
            return Err(WalletError::ChainDiscontinuity(height));
        }
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
/// retention markers, then checkpoints the accepted height. `marks` upgrades
/// those commitments to `Marked` — the retention the scanner assigns to notes
/// it decrypts mid-block. The height's single checkpoint-retention append
/// belongs to the block's last commitment; a marked Name Note that is not
/// last must not claim it.
fn append_block_commitments<H, Nf, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<
        shardtree::store::memory::MemoryShardStore<H, BlockHeight>,
        DEPTH,
        SHARD_HEIGHT,
    >,
    bundles: &ScannedBundles<H, Nf>,
    height: BlockHeight,
    marks: &[H],
) -> Result<(), WalletError>
where
    shardtree::store::memory::MemoryShardStore<H, BlockHeight>:
        ShardStore<H = H, CheckpointId = BlockHeight, Error = Infallible>,
    H: Hashable + PartialEq + Clone,
{
    for (commitment, retention) in bundles.commitments() {
        let retention = if marks.contains(commitment) {
            Retention::Marked
        } else {
            *retention
        };
        tree.append(commitment.clone(), retention)?;
    }
    ensure_block_checkpoint(tree, height, bundles.final_tree_size())
}

impl<P: Parameters + Clone> WalletWrite for Wallet<P> {
    type UtxoRef = OutPoint;

    fn create_account(
        &mut self,
        _account_name: &str,
        _seed: &SecretVec<u8>,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(AccountId, UnifiedSpendingKey), WalletError> {
        // Production: accounts 0 and 1 are installed once at boot; the
        // wallet never derives spending keys from a seed. Test builds
        // install the upstream conformance fixture account through the
        // cfg(test) seam in `wallet::testing` — a build without `cfg(test)`
        // compiles this branch out entirely, so no code exists to receive
        // a seed outside the test suite.
        #[cfg(test)]
        {
            super::testing::create_fixture_account(self, _seed, _birthday)
        }
        #[cfg(not(test))]
        {
            Err(WalletError::FixedAccountsOnly)
        }
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
        // The one writer for chain knowledge: scanning and chain-state
        // adoption call it. Reorg correction is the caller's loop.
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
        self.put_blocks_marked(from_state, blocks, &[])
    }

    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput<AccountId>,
    ) -> Result<Self::UtxoRef, WalletError> {
        // The mint never receives, stores, or spends transparent money;
        // the only transparent flow is the vault unshield, which spends
        // shielded notes. Nothing can deliver a UTXO here.
        Err(WalletError::FixedAccountsOnly)
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

        // Memos for mempool observations. Scanned-block memos arrive via
        // `store_scanned_memo`: upstream's ScannedBlock drops note
        // plaintexts, so the run loop extracts memos from the block.
        for output in received_tx.sapling_outputs() {
            if let Ok(memo) = Memo::from_bytes(output.memo().as_slice()) {
                self.memos.insert(
                    NoteId::new(
                        txid,
                        ShieldedPool::Sapling,
                        u16::try_from(output.index()).expect("Sapling output index fits in u16"),
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
                        u16::try_from(output.index()).expect("Ironwood action index fits in u16"),
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
            self.sent_outputs.insert(
                txid,
                sent.outputs()
                    .iter()
                    .map(|o| {
                        SentTransactionOutput::from_parts(
                            o.output_index(),
                            o.recipient().clone(),
                            o.value(),
                            o.memo().cloned(),
                        )
                    })
                    .collect(),
            );
            for output in sent.outputs() {
                let pool = match output.recipient() {
                    Recipient::External {
                        output_pool: PoolType::Shielded(pool),
                        ..
                    } => *pool,
                    Recipient::InternalShielded { note, .. } => note.pool(),
                    _ => continue,
                };
                let Ok(index) = u16::try_from(output.output_index()) else {
                    continue;
                };
                if let Some(bytes) = output.memo() {
                    if let Ok(memo) = Memo::from_bytes(bytes.as_array()) {
                        self.memos.insert(NoteId::new(txid, pool, index), memo);
                    }
                }
            }

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

        // Trees first on clones: on failure the live trees and tables stay
        // untouched. `try_truncate_trees_to` commits all three only after each
        // truncation succeeds.
        if !self.try_truncate_trees_to(target)? {
            return Err(WalletError::TruncationTargetUnavailable(target));
        }

        self.drop_applied_above(target);
        Ok(target)
    }

    fn truncate_to_chain_state(&mut self, chain_state: ChainState) -> Result<(), WalletError> {
        let height = chain_state.block_height();
        match self.blocks.get(&height) {
            Some(metadata) if metadata.block_hash() == chain_state.block_hash() => {}
            Some(_) => return Err(WalletError::ChainDiscontinuity(height)),
            None => {}
        }

        if self.blocks.is_empty() || self.tip().block_height() <= height {
            // Adoption is knowledge — through the one writer.
            self.update_chain_tip(height)?;
            return Ok(());
        }

        // Restore the rollback boundary in retained trees, preserving marked
        // leaves and their witness paths. Publish only after all pools succeed.
        let retention = Retention::Checkpoint {
            id: height,
            marking: Marking::None,
        };
        let mut sapling = clone_shard_tree(&self.sapling_tree)?;
        let mut orchard = clone_shard_tree(&self.orchard_tree)?;
        let mut ironwood = clone_shard_tree(&self.ironwood_tree)?;

        // Remove abandoned checkpoint records before insertion so a full
        // window cannot immediately prune the restored checkpoint. Tree
        // nodes remain available for the frontier merge.
        sapling
            .store_mut()
            .truncate_checkpoints_retaining(&height)?;
        orchard
            .store_mut()
            .truncate_checkpoints_retaining(&height)?;
        ironwood
            .store_mut()
            .truncate_checkpoints_retaining(&height)?;
        sapling.insert_frontier(chain_state.final_sapling_tree().clone(), retention)?;
        orchard.insert_frontier(chain_state.final_orchard_tree().clone(), retention)?;
        ironwood.insert_frontier(chain_state.final_ironwood_tree().clone(), retention)?;
        if !sapling.truncate_to_checkpoint(&height)?
            || !orchard.truncate_to_checkpoint(&height)?
            || !ironwood.truncate_to_checkpoint(&height)?
        {
            return Err(WalletError::TruncationTargetUnavailable(height));
        }

        self.sapling_tree = sapling;
        self.orchard_tree = orchard;
        self.ironwood_tree = ironwood;
        self.drop_applied_above(height);
        if self.blocks.is_empty() {
            self.seed = super::block_metadata(&chain_state);
        }
        // Adoption is knowledge — through the one writer.
        self.update_chain_tip(height)?;
        Ok(())
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

        // Height to which acknowledged accounts may have their birthday lowered.
        let new_birthday = next_height(chain_state.block_height());

        // Empty acknowledgement set: refuse only when every account would need
        // its birthday lowered to reach the rewind target.
        if reset_account_birthdays.is_empty()
            && !self.account_birthdays.is_empty()
            && self
                .account_birthdays
                .values()
                .all(|&birthday| birthday > new_birthday)
        {
            return Err(RewindError::RewindBeyondBirthdays(
                self.account_birthdays
                    .iter()
                    .map(|(account, birthday)| (*account, *birthday))
                    .collect::<HashMap<_, _>>(),
            ));
        }

        // Upstream rewinds by height alone; hash validation belongs to
        // `truncate_to_chain_state`.
        let rewind_target = chain_state.block_height();

        // Nothing applied above the target: birthdays only.
        if self.tip().block_height() <= rewind_target {
            self.lower_account_birthdays(&reset_account_birthdays, new_birthday);
            return Ok(());
        }

        // Retention bounds rewinding: the floor is the trees' oldest
        // retained checkpoint, never a tip.
        let Some(floor) = self.retained_floor() else {
            self.lower_account_birthdays(&reset_account_birthdays, new_birthday);
            return Ok(());
        };
        let data_height = rewind_target.max(floor);

        if !self
            .try_truncate_trees_to(data_height)
            .map_err(RewindError::DataSource)?
        {
            return Err(RewindError::DataSource(
                WalletError::TruncationTargetUnavailable(data_height),
            ));
        }
        self.drop_applied_above(data_height);

        self.lower_account_birthdays(&reset_account_birthdays, new_birthday);
        Ok(())
    }

    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        _account_id: AccountId,
        n: usize,
    ) -> Result<
        Vec<(
            transparent::address::TransparentAddress,
            zcash_client_backend::wallet::TransparentAddressMetadata,
        )>,
        WalletError,
    > {
        // `create_proposed_transactions` always calls this, including `n == 0`
        // (no transparent change). The mint does not derive transparent
        // receivers; a zero request is a no-op, not a policy error.
        if n == 0 {
            return Ok(Vec::new());
        }
        Err(WalletError::FixedAccountsOnly)
    }

    fn reserve_next_n_internal_addresses(
        &mut self,
        _account_id: AccountId,
        n: usize,
    ) -> Result<
        Vec<(
            transparent::address::TransparentAddress,
            zcash_client_backend::wallet::TransparentAddressMetadata,
        )>,
        WalletError,
    > {
        // Same as ephemeral: `n == 0` is a no-op; the mint does not derive
        // transparent receivers.
        if n == 0 {
            return Ok(Vec::new());
        }
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

impl<P: Parameters> Wallet<P> {
    /// [`WalletWrite::put_blocks`], with the accepted Name Note commitments
    /// marked: the scanner cannot decrypt ZNS-domain outputs, so they
    /// would otherwise enter the Ironwood tree Ephemeral — prunable, and
    /// then the note has no witness. Marking is plain `Retention::Marked`,
    /// exactly as the scanner retains mid-block decrypted notes; the
    /// per-height checkpoint is `ensure_block_checkpoint`'s to create.
    pub(crate) fn put_blocks_marked(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<AccountId>>,
        marks: &[orchard::tree::MerkleHashOrchard],
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
            // First batch: `from_state` must be the recorded boot origin.
            None => {
                if from_state.block_height() != self.seed.block_height()
                    || from_state.block_hash() != self.seed.block_hash()
                {
                    return Err(WalletError::ChainDiscontinuity(from_state.block_height()));
                }
            }
        }

        // Ordinary Orchard is a compatibility commitment tree only: never
        // persist received notes. Refuse a decryptable Orchard output rather
        // than apply the block and lose the value from wallet state.
        for block in &blocks {
            for wtx in block.transactions() {
                if !wtx.orchard_outputs().is_empty() {
                    return Err(WalletError::UnexpectedOrchardReceive);
                }
            }
        }

        // Append commitments on clones of the three trees. Only after the
        // full batch succeeds are the live trees replaced, so a mid-batch
        // tree failure leaves wallet state (including trees) unchanged.
        let mut sapling_tree = clone_shard_tree(&self.sapling_tree)?;
        let mut orchard_tree = clone_shard_tree(&self.orchard_tree)?;
        let mut ironwood_tree = clone_shard_tree(&self.ironwood_tree)?;
        for block in &blocks {
            let height = block.height();
            append_block_commitments(&mut sapling_tree, block.sapling(), height, &[])?;
            append_block_commitments(&mut orchard_tree, block.orchard(), height, &[])?;
            append_block_commitments(&mut ironwood_tree, block.ironwood(), height, marks)?;
        }
        self.sapling_tree = sapling_tree;
        self.orchard_tree = orchard_tree;
        self.ironwood_tree = ironwood_tree;

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
                        u16::try_from(output.index()).expect("Sapling output index fits in u16"),
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
                        u16::try_from(output.index()).expect("Ironwood action index fits in u16"),
                    );
                    self.ironwood_notes.insert(note_id, output.clone());
                    if let Some(nf) = output.nf() {
                        self.ironwood_nullifiers.insert(*nf, note_id);
                    }
                }
            }

            // Spends are recorded from the scanner's matched `WalletSpend`s.
            // The watch list the scanner matched against came from this
            // wallet, so every spend of an owned note is present, already
            // account-tagged. The nullifier map carries only foreign
            // nullifiers — upstream's gap-scan recovery mechanism, useless
            // to a wallet that scans contiguously from its birthday — and
            // owned spends never appear in it. (A note cannot be spent in
            // the block that creates it, and the mint applies one block per
            // `put_blocks_marked` call, so same-batch create-and-spend
            // cannot arise.)
            for wtx in block.transactions() {
                let txid = wtx.txid();
                for spend in wtx.sapling_spends() {
                    if let Some(note_id) = self.sapling_nullifiers.get(spend.nf()) {
                        self.sapling_note_spends.insert(*note_id, txid);
                    }
                }
                for spend in wtx.ironwood_spends() {
                    if let Some(note_id) = self.ironwood_nullifiers.get(spend.nf()) {
                        self.ironwood_note_spends.insert(*note_id, txid);
                    }
                }
            }

            self.blocks.insert(height, block.to_block_metadata());
        }

        // Scanning verified this far: knowledge follows, through the writer.
        if let Some((&applied, _)) = self.blocks.last_key_value() {
            self.update_chain_tip(applied)?;
        }
        Ok(())
    }

    /// Stores one decrypted ZNS Name Note as the Registry account's ordinary
    /// received Ironwood note, at its consensus-derived tree position.
    ///
    /// The standard scanning lane cannot see Name Notes (its domain re-derives
    /// the commitment from rseed and rejects the ZNS-derived cmx), so the
    /// orchestrator's ZNS pass supplies them here, after `put_blocks_marked`
    /// has committed the block. The caller derives `position` from that same
    /// scanned block before moving it into `put_blocks_marked`.
    ///
    /// `nullifier` was derived by the ZNS decryption pass from the same
    /// authenticated `(rcm, psi)` pair that reproduced the action's cmx. The
    /// ordinary rseed-derived nullifier never matches a Name Note spend.
    ///
    /// Returns [`WalletError::InvalidNameNote`] when the arguments contradict
    /// applied state: the height must be an applied block, the txid must
    /// already be mined at that height, the Ironwood tree must witness
    /// `position` there, and the note id / nullifier must not collide with a
    /// different retained note.
    #[allow(clippy::too_many_arguments)]
    pub fn store_name_note(
        &mut self,
        height: BlockHeight,
        position: Position,
        txid: TxId,
        action_index: usize,
        note: orchard::note::Note,
        nullifier: orchard::note::Nullifier,
        ephemeral_key: zcash_note_encryption::EphemeralKeyBytes,
        memo: [u8; 512],
    ) -> Result<(), WalletError> {
        if !self.blocks.contains_key(&height) {
            return Err(WalletError::InvalidNameNote(
                "height is not an applied block",
            ));
        }
        match self.transaction_statuses.get(&txid) {
            Some(TransactionStatus::Mined(mined)) if *mined == height => {}
            Some(TransactionStatus::Mined(_)) => {
                return Err(WalletError::InvalidNameNote(
                    "txid is mined at a different height",
                ));
            }
            Some(_) => {
                return Err(WalletError::InvalidNameNote(
                    "txid is not mined in the main chain",
                ));
            }
            None => {
                return Err(WalletError::InvalidNameNote(
                    "txid was not applied with put_blocks",
                ));
            }
        }
        let output_index = u16::try_from(action_index)
            .map_err(|_| WalletError::InvalidNameNote("Ironwood action index does not fit u16"))?;
        let note_id = NoteId::new(txid, ShieldedPool::Ironwood, output_index);

        // Nullifier collision: a different NoteId with the same nullifier
        // means the nullifier was derived from a different note — refused.
        if let Some(owner) = self.ironwood_nullifiers.get(&nullifier) {
            if *owner != note_id {
                return Err(WalletError::InvalidNameNote(
                    "nullifier already identifies a different Ironwood note",
                ));
            }
        }
        // Binding check (committed fields): the note's commitment must match
        // the tree leaf at position; the root from the path + note must equal
        // the Ironwood anchor at this height.
        let path = self
            .ironwood_witness(position, height)
            .map_err(WalletError::CommitmentTree)?
            .ok_or(WalletError::InvalidNameNote(
                "no Ironwood witness at position for this height",
            ))?;
        let note_cmx: orchard::note::NoteCommitment = note.commitment();
        let leaf = orchard::tree::MerkleHashOrchard::from_cmx(&(note_cmx.into()));
        let computed_root = path.root(leaf);
        let anchor = self
            .ironwood_anchor(height)
            .map_err(WalletError::CommitmentTree)?
            .ok_or(WalletError::InvalidNameNote(
                "no Ironwood anchor at height for binding check",
            ))?;
        if computed_root.to_bytes() != anchor.to_bytes() {
            return Err(WalletError::InvalidNameNote(
                "note commitment does not match tree root at height",
            ));
        }

        // Byte-identical retry (uncommitted fields): if the NoteId exists,
        // every stored field must match byte-for-byte; any divergence is a
        // refusal, not a silent overwrite.
        if let Some(existing) = self.ironwood_notes.get(&note_id) {
            if existing.note_commitment_tree_position() != position
                || existing.nf().copied() != Some(nullifier)
                || existing.note().0 != note
                || existing.ephemeral_key().as_ref() != ephemeral_key.as_ref()
                || existing.note().1 != orchard::ValuePool::Ironwood
                || existing.account_id() != &REGISTRY_ACCOUNT
                || existing.recipient_key_scope() != Some(zip32::Scope::External)
            {
                return Err(WalletError::InvalidNameNote(
                    "NoteId exists with divergent fields",
                ));
            }
            // Compare memo byte-for-byte via PartialEq on Memo.
            let existing_memo = self.memos.get(&note_id);
            let new_memo = Memo::Future(
                zcash_protocol::memo::MemoBytes::from_bytes(&memo).map_err(|_| {
                    WalletError::InvalidNameNote("memo bytes are not valid MemoBytes")
                })?,
            );
            if existing_memo != Some(&new_memo) {
                return Err(WalletError::InvalidNameNote(
                    "NoteId exists with divergent memo",
                ));
            }
            // Idempotent no-op: byte-identical retry succeeds without mutation.
            return Ok(());
        }

        let memo = Memo::Future(
            zcash_protocol::memo::MemoBytes::from_bytes(&memo)
                .map_err(|_| WalletError::InvalidNameNote("memo bytes are not valid MemoBytes"))?,
        );

        self.ironwood_notes.insert(
            note_id,
            WalletIronwoodOutput::from_parts(
                action_index,
                ephemeral_key,
                (note, orchard::ValuePool::Ironwood),
                false,
                position,
                Some(nullifier),
                REGISTRY_ACCOUNT,
                Some(zip32::Scope::External),
            ),
        );
        self.ironwood_nullifiers.insert(nullifier, note_id);
        self.memos.insert(note_id, memo);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Wallet, WalletError, MAX_CHECKPOINTS};
    use incrementalmerkletree::frontier::Frontier;
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_client_backend::data_api::locking::{LockOwner, OutputLockStore};
    use zcash_client_backend::data_api::testing::pool::dsl::TestDsl;
    use zcash_client_backend::data_api::testing::pool::{InputTrust, ShieldedPoolTester};
    use zcash_client_backend::data_api::testing::AddressType;
    use zcash_client_backend::data_api::testing::{pool, sapling::SaplingPoolTester};
    use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
    use zcash_client_backend::data_api::Account;
    use zcash_client_backend::data_api::{WalletRead, WalletWrite};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, NetworkType, Parameters};
    use zcash_protocol::value::Zatoshis;
    use zip32::AccountId;

    use crate::wallet::testing::{Cache, Factory};

    #[test]
    fn scan_cached_blocks_finds_received_notes() {
        pool::scan_cached_blocks_finds_received_notes::<SaplingPoolTester, _>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes() {
        pool::scan_cached_blocks_finds_change_notes::<SaplingPoolTester, _>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn valid_chain_states() {
        pool::valid_chain_states::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn scan_full_block_detects_outputs() {
        pool::scan_full_block_detects_outputs::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn truncate_to_chain_state() {
        pool::truncate_to_chain_state::<SaplingPoolTester, _>(Factory, Cache::default());
    }

    #[test]
    fn truncate_to_chain_state_below_birthday() {
        pool::truncate_to_chain_state_below_birthday::<SaplingPoolTester, _>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn truncate_to_chain_state_above_scanned() {
        pool::truncate_to_chain_state_above_scanned::<SaplingPoolTester, _>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn rewind_to_chain_state_shallow() {
        pool::rewind_to_chain_state_shallow::<SaplingPoolTester, _>(Factory, Cache::default());
    }

    #[test]
    fn change_note_spends_succeed() {
        pool::change_note_spends_succeed::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn receive_two_notes_with_same_value() {
        pool::receive_two_notes_with_same_value::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn spend_fails_on_unverified_notes() {
        pool::spend_fails_on_unverified_notes::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn metadata_queries_exclude_unwanted_notes() {
        pool::metadata_queries_exclude_unwanted_notes::<SaplingPoolTester, _, _>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn zip_315_confirmations_external_untrusted() {
        pool::zip_315_confirmations_test_steps::<SaplingPoolTester>(
            Factory,
            Cache::default(),
            InputTrust::ExternalUntrusted,
        );
    }

    #[test]
    fn zip_315_confirmations_external_trusted() {
        pool::zip_315_confirmations_test_steps::<SaplingPoolTester>(
            Factory,
            Cache::default(),
            InputTrust::ExternalTrusted,
        );
    }

    #[test]
    fn rewind_to_chain_state_deep() {
        pool::rewind_to_chain_state_deep::<SaplingPoolTester, _>(Factory, Cache::default());
    }

    #[test]
    fn explicit_note_locking() {
        pool::locking::explicit_note_locking::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn note_locking_height_boundary() {
        pool::locking::note_locking_height_boundary::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn clear_locked_outputs() {
        pool::locking::clear_locked_outputs::<SaplingPoolTester>(Factory, Cache::default());
    }

    #[test]
    fn lock_conflict_and_batch_atomicity() {
        pool::locking::lock_conflict_and_batch_atomicity::<SaplingPoolTester>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn lock_expiry_restores_spendability() {
        pool::locking::lock_expiry_restores_spendability::<SaplingPoolTester>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn unlock_proposal_inputs_releases_locks() {
        pool::locking::unlock_proposal_inputs_releases_locks::<SaplingPoolTester>(
            Factory,
            Cache::default(),
        );
    }

    #[test]
    fn proposal_level_note_locking() {
        pool::locking::proposal_level_note_locking::<SaplingPoolTester>(Factory, Cache::default());
    }

    /// Local diagnostic, deliberately separate from the upstream corpus: the
    /// upstream scenarios never call `update_chain_tip`, so the divergence
    /// below is unobservable through them. This test performs the
    /// application-style sequence the mint's run loop performs (scan, then
    /// tip notification) and checks that the two readers of the lock map agree.
    ///
    /// Upstream contract, pinned by `note_locking_height_boundary` and
    /// `lock_expiry_restores_spendability`: a lock whose expiry height has
    /// passed is absent from `get_locked_outputs`. Our implementation reads
    /// the raw map and lists it, while balance and selection correctly treat
    /// the note as spendable — the same lock is simultaneously lapsed and
    /// listed. This test pins the upstream contract and stays red until the
    /// divergence is fixed; its result is not comparable to an unchanged
    /// upstream scenario.
    #[test]
    fn get_locked_outputs_drops_expired_locks() {
        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();

        // Fund through the raw path: no balance-checking helper, because the
        // helper requires a summary before any tip can exist.
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(50000);
        let (h, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // The application-level tip notification the upstream corpus omits.
        st.wallet_mut().update_chain_tip(h).unwrap();

        let account_id = st.test_account().unwrap().id();
        let output_ref = st.sole_note_ref();

        // A lock expiring at the current tip: `target_height` is tip + 1, so
        // the lock is lapsed from the moment it is taken.
        let owner = LockOwner::new([1; 32]);
        assert_eq!(
            st.wallet_mut()
                .lock_outputs(&[output_ref], owner, h)
                .unwrap(),
            1
        );

        // Balance evaluates the lock as lapsed: the note is fully spendable
        // and nothing is locked.
        let summary = st
            .wallet()
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .unwrap();
        let balance = summary.account_balances().get(&account_id).unwrap();
        assert_eq!(balance.sapling_balance().spendable_value(), value);
        assert_eq!(balance.sapling_balance().locked_value(), Zatoshis::ZERO);

        // The listing disagrees: the raw map read still contains the lapsed
        // lock. Upstream asserts this must be empty.
        assert!(
            st.wallet()
                .get_locked_outputs(account_id)
                .unwrap()
                .is_empty(),
            "get_locked_outputs must not list a lock whose expiry height has passed"
        );
    }

    /// Truncation must drop notes created on the abandoned branch and clear
    /// scanned-only spends of surviving notes; otherwise balances show phantom
    /// pending value and reorged spends freeze notes forever.
    #[test]
    fn truncate_clears_orphaned_receives_and_scanned_spends() {
        use zcash_client_backend::data_api::TransactionStatus;
        use zcash_client_backend::wallet::NoteId;
        use zcash_primitives::transaction::TxId;

        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(50_000);

        let (h1, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        let (h2, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h2, 1);
        st.wallet_mut().update_chain_tip(h2).unwrap();

        let wallet = st.wallet_mut();
        assert_eq!(wallet.sapling_notes.len(), 2);
        let note_h1 = wallet
            .sapling_notes
            .keys()
            .copied()
            .find(|id: &NoteId| {
                matches!(
                    wallet.transaction_statuses.get(id.txid()),
                    Some(TransactionStatus::Mined(h)) if *h == h1
                )
            })
            .expect("note from first scanned block");
        let note_h2 = wallet
            .sapling_notes
            .keys()
            .copied()
            .find(|id: &NoteId| {
                matches!(
                    wallet.transaction_statuses.get(id.txid()),
                    Some(TransactionStatus::Mined(h)) if *h == h2
                )
            })
            .expect("note from second scanned block");

        // Scanned-only spend of the surviving note, mined on the abandoned tip.
        let orphan_spend = TxId::from_bytes([0xab; 32]);
        wallet.sapling_note_spends.insert(note_h1, orphan_spend);
        wallet
            .transaction_statuses
            .insert(orphan_spend, TransactionStatus::Mined(h2));
        assert!(!wallet.transactions.contains_key(&orphan_spend));

        WalletWrite::truncate_to_height(wallet, h1).expect("h1 remains a checkpoint");

        assert!(
            wallet.sapling_notes.contains_key(&note_h1),
            "note created at or below the truncation height must survive"
        );
        assert!(
            !wallet.sapling_notes.contains_key(&note_h2),
            "note created only on the abandoned branch must be removed"
        );
        assert!(
            !wallet.sapling_note_spends.contains_key(&note_h1),
            "scanned-only spend mined above the truncation height must clear"
        );

        let account_id = st.test_account().unwrap().id();
        let summary = st
            .wallet()
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .unwrap();
        let balance = summary.account_balances().get(&account_id).unwrap();
        assert_eq!(balance.sapling_balance().spendable_value(), value);
        assert_eq!(
            balance.sapling_balance().value_pending_spendability(),
            Zatoshis::ZERO,
            "orphaned receive must not linger as pending"
        );
    }

    fn empty_origin() -> ChainState {
        ChainState::new(
            BlockHeight::from_u32(0),
            BlockHash([0; 32]),
            Frontier::empty(),
            Frontier::empty(),
            Frontier::empty(),
        )
    }

    #[test]
    fn reserve_zero_transparent_addresses_is_a_noop() {
        let origin = empty_origin();
        let mut wallet =
            Wallet::new([], &origin, &[], &[], MainNetwork).expect("empty UFVK set is valid");
        let account = AccountId::const_from_u32(0);
        assert!(wallet
            .reserve_next_n_ephemeral_addresses(account, 0)
            .expect("n == 0 is not FixedAccountsOnly")
            .is_empty());
        assert!(wallet
            .reserve_next_n_internal_addresses(account, 0)
            .expect("n == 0 is not FixedAccountsOnly")
            .is_empty());
    }

    #[test]
    fn reserve_nonzero_transparent_addresses_is_fixed_accounts_only() {
        let origin = empty_origin();
        let mut wallet =
            Wallet::new([], &origin, &[], &[], MainNetwork).expect("empty UFVK set is valid");
        let account = AccountId::const_from_u32(0);
        assert!(matches!(
            wallet.reserve_next_n_ephemeral_addresses(account, 1),
            Err(WalletError::FixedAccountsOnly)
        ));
        assert!(matches!(
            wallet.reserve_next_n_internal_addresses(account, 1),
            Err(WalletError::FixedAccountsOnly)
        ));
    }

    #[test]
    fn wallet_knows_its_network() {
        let origin = empty_origin();
        let wallet =
            Wallet::new([], &origin, &[], &[], MainNetwork).expect("empty UFVK set is valid");
        assert_eq!(wallet.network().network_type(), NetworkType::Main);
    }

    // Both pruned and retained checkpoints must preserve older witnesses.
    #[test]
    fn deep_and_window_truncation_preserve_witnesses() {
        use incrementalmerkletree::{
            frontier::Frontier, Hashable, Level, Marking, Position, Retention,
        };
        use orchard::tree::MerkleHashOrchard;
        use zcash_client_backend::data_api::BlockMetadata;

        // 146 blocks × 2 Ironwood commitments; the block-2 note is marked,
        // using the retention decrypted notes and Name Notes carry.
        // Each block's last commitment takes the scanner's Checkpoint
        // retention, so 146 checkpoints age anything older than ~100 out
        // of the window.
        let build = |wallet: &mut Wallet<MainNetwork>, base: u32| {
            // Keep a real note row below the cut, as production scanning does.
            let sk = orchard::keys::SpendingKey::from_bytes([7u8; 32])
                .into_option()
                .expect("any 32 bytes are a spending key");
            let recipient = orchard::keys::FullViewingKey::from(&sk)
                .to_ivk(orchard::keys::Scope::External)
                .address_at(0u32);
            let rho = orchard::note::Rho::from_bytes(&[7u8; 32])
                .into_option()
                .expect("bytes are a canonical field element");
            let rseed = orchard::note::RandomSeed::from_bytes([7u8; 32], &rho)
                .into_option()
                .expect("rseed derives a valid esk");
            let note = orchard::note::Note::from_parts(
                recipient,
                orchard::value::NoteValue::ZERO,
                rho,
                rseed,
                orchard::note::NoteVersion::V2,
            )
            .into_option()
            .expect("note parts are valid");
            let txid = zcash_primitives::transaction::TxId::from_bytes([9u8; 32]);
            let note_id = zcash_client_backend::wallet::NoteId::new(
                txid,
                zcash_protocol::ShieldedPool::Ironwood,
                0,
            );
            wallet.transaction_statuses.insert(
                txid,
                zcash_client_backend::data_api::TransactionStatus::Mined(BlockHeight::from_u32(2)),
            );
            wallet.ironwood_notes.insert(
                note_id,
                zcash_client_backend::wallet::WalletIronwoodOutput::from_parts(
                    0,
                    zcash_note_encryption::EphemeralKeyBytes([0u8; 32]),
                    (note, orchard::ValuePool::Ironwood),
                    false,
                    Position::from(u64::from(base) + 2),
                    None,
                    zip32::AccountId::const_from_u32(0),
                    Some(zip32::Scope::External),
                ),
            );

            let mut cm = MerkleHashOrchard::empty_leaf();
            let mut next = || {
                cm = MerkleHashOrchard::combine(Level::from(0), &cm, &cm);
                cm
            };
            let mut targets = Vec::new();
            let mut frontier = if base == 0 {
                Frontier::<MerkleHashOrchard, 32>::empty()
            } else {
                let position = u64::from(base) - 1;
                Frontier::from_parts(
                    Position::from(position),
                    MerkleHashOrchard::empty_leaf(),
                    vec![MerkleHashOrchard::empty_leaf(); position.count_ones() as usize],
                )
                .unwrap()
            };
            wallet
                .ironwood_tree
                .insert_frontier(frontier.clone(), Retention::Ephemeral)
                .unwrap();
            for h in 1..=146u32 {
                let height = BlockHeight::from_u32(h);
                for i in 0..2u8 {
                    let retention = if h == 2 && i == 0 {
                        Retention::Marked
                    } else if i == 1 {
                        Retention::Checkpoint {
                            id: height,
                            marking: Marking::None,
                        }
                    } else {
                        Retention::Ephemeral
                    };
                    let commitment = next();
                    assert!(frontier.append(commitment));
                    wallet
                        .ironwood_tree
                        .append(commitment, retention)
                        .expect("per-block retention sequence is upstream-legal");
                }
                wallet.blocks.insert(
                    height,
                    BlockMetadata::from_parts(
                        height,
                        BlockHash([7u8; 32]),
                        Some(0),
                        Some(0),
                        Some(base + 2 * h),
                    ),
                );
                // Mirror production: every applied height is checkpointed
                // in all three pools, including pools with no commitments
                // (TreeState::Empty) — via the real ensure function.
                super::ensure_block_checkpoint(&mut wallet.sapling_tree, height, 0)
                    .expect("empty-pool checkpoint backfill succeeds");
                super::ensure_block_checkpoint(&mut wallet.orchard_tree, height, 0)
                    .expect("empty-pool checkpoint backfill succeeds");
                if h == 45 || h == 100 {
                    targets.push(ChainState::new(
                        height,
                        BlockHash([7u8; 32]),
                        Frontier::empty(),
                        Frontier::empty(),
                        frontier.clone(),
                    ));
                }
            }
            wallet.update_chain_tip(BlockHeight::from_u32(146)).unwrap();
            targets
        };

        for scenario in 0..5 {
            use shardtree::store::{Checkpoint, ShardStore};
            let target_index = if scenario == 2 { 0 } else { scenario % 2 };
            let origin = empty_origin();
            let mut wallet = Wallet::new([], &origin, &[], &[], MainNetwork).expect("valid wallet");
            // Start just before a shard boundary to exercise cap and shard truncation.
            let base = if scenario == 4 { (1 << 16) - 4 } else { 0 };
            let targets = build(&mut wallet, base);
            let target = targets[target_index].clone();
            let height = target.block_height();
            let expected_root = target.final_ironwood_tree().root();
            if scenario == 2 {
                // A checkpoint record alone cannot restore a pruned boundary.
                wallet
                    .ironwood_tree
                    .store_mut()
                    .add_checkpoint(height, Checkpoint::at_position(Position::from(89)))
                    .unwrap();
                assert!(matches!(
                    super::clone_shard_tree(&wallet.ironwood_tree)
                        .unwrap()
                        .truncate_to_checkpoint(&height),
                    Err(shardtree::error::ShardTreeError::Query(
                        shardtree::error::QueryError::CheckpointPruned
                    ))
                ));
            }
            if scenario == 3 {
                // Conflict in the last pool must not publish changes to earlier pools.
                let (position, _, ommers) = target
                    .final_ironwood_tree()
                    .clone()
                    .take()
                    .unwrap()
                    .into_parts();
                let invalid = ChainState::new(
                    height,
                    target.block_hash(),
                    Frontier::empty(),
                    Frontier::empty(),
                    Frontier::from_parts(position, MerkleHashOrchard::empty_leaf(), ommers)
                        .unwrap(),
                );
                let tip = BlockHeight::from_u32(146);
                let root = wallet.ironwood_tree.root_at_checkpoint_id(&tip).unwrap();
                assert!(wallet.truncate_to_chain_state(invalid).is_err());
                assert_eq!(wallet.chain_height().unwrap(), Some(tip));
                assert_eq!(wallet.tip().block_height(), tip);
                assert_eq!(wallet.ironwood_notes.len(), 1);
                assert_eq!(
                    wallet.sapling_tree.store().max_checkpoint_id().unwrap(),
                    Some(tip)
                );
                assert_eq!(
                    wallet.orchard_tree.store().max_checkpoint_id().unwrap(),
                    Some(tip)
                );
                assert_eq!(
                    wallet.ironwood_tree.root_at_checkpoint_id(&tip).unwrap(),
                    root
                );
                assert!(wallet
                    .ironwood_witness(Position::from(u64::from(base) + 2), tip)
                    .unwrap()
                    .is_some());
                continue;
            }
            let mut resumed_frontier = target.final_ironwood_tree().clone();
            wallet
                .truncate_to_chain_state(target)
                .expect("truncate to supplied state");
            assert_eq!(wallet.chain_height().unwrap(), Some(height));
            assert_eq!(wallet.tip().block_height(), height);
            assert_eq!(
                wallet.ironwood_tree.root_at_checkpoint_id(&height).unwrap(),
                Some(expected_root)
            );
            let witness = wallet
                .ironwood_witness(Position::from(u64::from(base) + 2), height)
                .expect("witness is structurally sound")
                .expect("marked note remains witnessed");
            let mut marked_leaf = MerkleHashOrchard::empty_leaf();
            for _ in 0..3 {
                marked_leaf =
                    MerkleHashOrchard::combine(Level::from(0), &marked_leaf, &marked_leaf);
            }
            assert_eq!(witness.root(marked_leaf), expected_root);
            assert_eq!(wallet.ironwood_notes.len(), 1);
            // Extend the replacement branch beyond another full pruning window.
            for offset in 1..=110u32 {
                let next_height = height + offset;
                let commitment =
                    MerkleHashOrchard::combine(Level::from(0), &marked_leaf, &marked_leaf);
                assert!(resumed_frontier.append(commitment));
                wallet
                    .ironwood_tree
                    .append(
                        commitment,
                        Retention::Checkpoint {
                            id: next_height,
                            marking: Marking::None,
                        },
                    )
                    .unwrap();
                if offset == 1 || offset == 110 {
                    let witness = wallet
                        .ironwood_witness(Position::from(u64::from(base) + 2), next_height)
                        .unwrap()
                        .expect("witness survives resumed appends and pruning");
                    assert_eq!(witness.root(marked_leaf), resumed_frontier.root());
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Position ownership: the wallet's own chain position
    // ------------------------------------------------------------------

    /// A chain state to seed a bare wallet from, mirroring `Factory`.
    fn origin() -> ChainState {
        ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32]))
    }

    /// Applied-block metadata at `height`, for direct `blocks` insertion.
    fn at(height: u32) -> zcash_client_backend::data_api::BlockMetadata {
        zcash_client_backend::data_api::BlockMetadata::from_parts(
            BlockHeight::from_u32(height),
            BlockHash([height as u8; 32]),
            Some(0),
            Some(0),
            Some(0),
        )
    }

    /// The wallet's position is the boot origin before any block is applied.
    #[test]
    fn tip_is_the_boot_seed_before_any_block_is_applied() {
        let origin = origin();
        let wallet =
            Wallet::new([], &origin, &[], &[], MainNetwork).expect("empty UFVK set is valid");
        assert_eq!(
            (wallet.tip().block_height(), wallet.tip().block_hash()),
            (origin.block_height(), origin.block_hash())
        );
    }

    /// With blocks applied, the position is the highest one, not the seed.
    #[test]
    fn tip_is_the_highest_applied_block() {
        let origin = origin();
        let mut wallet =
            Wallet::new([], &origin, &[], &[], MainNetwork).expect("empty UFVK set is valid");
        wallet.blocks.insert(BlockHeight::from_u32(5), at(5));
        wallet.blocks.insert(BlockHeight::from_u32(7), at(7));
        assert_eq!(
            (wallet.tip().block_height(), wallet.tip().block_hash()),
            (BlockHeight::from_u32(7), at(7).block_hash())
        );
    }

    /// After a full truncation the position falls back to the seed.
    #[test]
    fn tip_falls_back_to_the_seed_after_full_truncation() {
        let origin = origin();
        let mut wallet =
            Wallet::new([], &origin, &[], &[], MainNetwork).expect("empty UFVK set is valid");
        wallet.blocks.insert(BlockHeight::from_u32(5), at(5));
        wallet.blocks.clear();
        assert_eq!(wallet.tip().block_height(), origin.block_height());
    }

    /// Scanning advances knowledge through the writer; truncation never
    /// lowers it.
    #[test]
    fn chain_knowledge_moves_only_through_the_writer() {
        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(50_000);
        let (h1, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        // Scanning verified this far — knowledge advanced through the writer.
        assert_eq!(st.wallet().zebra_tip, Some(h1));
        let (h2, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h2, 1);
        assert_eq!(st.wallet().zebra_tip, Some(h2));
        // Truncation does not lower knowledge: no clamp behind the writer.
        st.wallet_mut().truncate_to_height(h1).unwrap();
        assert_eq!(st.wallet().zebra_tip, Some(h2));
    }

    /// A request above the applied tip commits the tip and returns it.
    #[test]
    fn truncate_to_above_the_tip_returns_the_tip() {
        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(50_000);
        let (h1, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        let above = BlockHeight::from_u32(u32::from(h1) + 10);
        let metadata = st
            .wallet_mut()
            .truncate_to(above)
            .expect("tip is committed");
        assert_eq!(metadata.block_height(), h1);
        assert_eq!(st.wallet().tip().block_height(), h1);
    }

    /// A far-ahead node tip must not defeat rewind: the floor is
    /// retention, never the tip.
    #[test]
    fn rewind_truncates_despite_a_far_ahead_node_tip() {
        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(50_000);
        let (h1, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        let (h2, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h2, 1);
        let (h3, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h3, 1);

        // An external driver supplies a tip far beyond every applied
        // height — every catch-up's normal state, and the condition under
        // which the tip-derived floor used to swallow rewinds whole.
        let ahead = BlockHeight::from_u32(u32::from(h3) + 10_000);
        st.wallet_mut().update_chain_tip(ahead).unwrap();

        // The claimed ancestor: the wallet's own block at h1, with its hash.
        let h1_hash = st
            .wallet()
            .block_metadata_at(h1)
            .expect("h1 is applied")
            .block_hash();
        st.wallet_mut()
            .rewind_to_chain_state(
                ChainState::empty(h1, h1_hash),
                std::collections::HashSet::new(),
            )
            .expect("lag must not defeat the rewind");

        // Truncated to the claimed ancestor, despite the known chain
        // extending far above every applied height — and the knowledge
        // itself is untouched by the rewind, per the upstream contract.
        assert_eq!(st.wallet().tip().block_height(), h1);
        assert_eq!(st.wallet().sapling_notes.len(), 1);
        assert_eq!(st.wallet().zebra_tip, Some(ahead));
    }

    /// Both lock readers answer from the position — no node tip needed.
    #[test]
    fn lock_readers_agree_without_any_node_tip() {
        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(50_000);
        let (h1, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        // No `update_chain_tip`: the node observation stays None.
        let account_id = st.test_account().unwrap().id();
        let output_ref = st.sole_note_ref();
        let owner = LockOwner::new([1; 32]);

        // A lock expiring at the wallet's own position is lapsed from
        // birth: the listing agrees with balance and selection, which
        // already judged by the applied position.
        let position = st.wallet().tip().block_height();
        assert_eq!(
            st.wallet_mut()
                .lock_outputs(&[output_ref], owner, position)
                .unwrap(),
            1
        );
        assert!(st
            .wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .is_empty());

        // A lock expiring above the position stays listed.
        let above = BlockHeight::from_u32(u32::from(position) + 10);
        assert_eq!(
            st.wallet_mut()
                .lock_outputs(&[output_ref], owner, above)
                .unwrap(),
            1
        );
        assert_eq!(st.wallet().get_locked_outputs(account_id).unwrap().len(), 1);
    }

    /// Below the retention window the checkpoint is gone: refuse rather
    /// than keep orphaned state — restart is the recovery.
    #[test]
    fn truncate_below_the_retention_window_refuses() {
        let mut st = TestDsl::with_sapling_birthday_account(Factory, Cache::default())
            .build::<SaplingPoolTester>();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(50_000);
        let (h1, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        // Outlive the retention window: the checkpoint at h1 is pruned.
        for _ in 0..(MAX_CHECKPOINTS as u32) {
            let (h, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, value);
            st.scan_cached_blocks(h, 1);
        }
        match st.wallet_mut().truncate_to_height(h1) {
            Err(WalletError::TruncationTargetUnavailable(height)) => assert_eq!(height, h1),
            other => panic!("expected TruncationTargetUnavailable at {h1}, got {other:?}"),
        }
    }
}
