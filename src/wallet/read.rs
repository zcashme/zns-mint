//! Upstream `WalletRead` implementation, its private fixed-account value,
//! and the Ironwood note reads that upstream's generic traits cannot express
//! — notably the ZNS lookup by a record's `rho`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::num::NonZeroU32;

use secrecy::SecretVec;
use shardtree::store::ShardStore;
use zcash_client_backend::data_api::{
    Account as UpstreamAccount, AccountBalance, AccountPurpose, AccountSource, AddressInfo,
    Balance, BlockMetadata, NullifierQuery, Progress, Ratio, ReceivedTransactionOutput,
    SeedRelevance, TransactionDataRequest, TransactionStatus, TransparentBalances, WalletRead,
    WalletSummary, Zip32Derivation, defaults, error::FindAccountForAddressError,
    scanning::{ScanPriority, ScanRange},
    wallet::{ConfirmationsPolicy, TargetHeight},
};
use zcash_client_backend::wallet::{NoteId, ReceivedNote, TransparentAddressMetadata};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{self, BlockHeight};
use zcash_protocol::memo::Memo;
use zcash_protocol::value::{BalanceError, Zatoshis};
use zcash_protocol::{PoolType, ShieldedPool};
use zip32::AccountId;

use crate::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};

use super::Wallet;

/// Errors produced by the mint's fixed-account in-memory WalletDb.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletError {
    /// A lifecycle operation that cannot exist in this wallet: account
    /// creation, import, or deletion, address generation or reservation.
    FixedAccountsOnly,
    /// A query or mutation named an account other than 0 (Treasury) or
    /// 1 (Registry).
    AccountUnknown(AccountId),
    /// `put_blocks` was called with non-sequential heights or a `from_state`
    /// that does not connect to the wallet's applied tip, or a truncation was
    /// requested against a chain state that contradicts the applied blocks.
    /// The payload is the height at which continuity broke.
    ChainDiscontinuity(BlockHeight),
    /// Truncation was requested to a height below every checkpoint retained by
    /// all three note commitment trees.
    TruncationTargetUnavailable(BlockHeight),
    /// A note commitment tree operation failed.
    CommitmentTree(shardtree::error::ShardTreeError<Infallible>),
    /// A value aggregation would overflow `MAX_MONEY`.
    Balance(BalanceError),
}

impl From<shardtree::error::ShardTreeError<Infallible>> for WalletError {
    fn from(e: shardtree::error::ShardTreeError<Infallible>) -> Self {
        WalletError::CommitmentTree(e)
    }
}

impl From<BalanceError> for WalletError {
    fn from(e: BalanceError) -> Self {
        WalletError::Balance(e)
    }
}

impl From<Infallible> for WalletError {
    fn from(e: Infallible) -> Self {
        match e {}
    }
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::FixedAccountsOnly => write!(
                f,
                "operation is not supported by the fixed Treasury/Registry wallet"
            ),
            WalletError::AccountUnknown(account) => {
                write!(f, "unknown account {account:?}")
            }
            WalletError::ChainDiscontinuity(height) => {
                write!(f, "chain discontinuity detected at or before height {height}")
            }
            WalletError::TruncationTargetUnavailable(height) => {
                write!(f, "no retained checkpoint at or below height {height}")
            }
            WalletError::CommitmentTree(e) => write!(f, "note commitment tree error: {e}"),
            WalletError::Balance(e) => write!(f, "balance error: {e}"),
        }
    }
}

impl std::error::Error for WalletError {}

/// The fixed earliest height at which either mint account may have been
/// exposed. This is application identity, not mutable wallet state.
const MINT_BIRTHDAY_HEIGHT: u32 = 3_400_000;

/// The birthday shared by both fixed mint accounts.
pub(super) fn account_birthday() -> BlockHeight {
    BlockHeight::from_u32(MINT_BIRTHDAY_HEIGHT)
}

/// The first height at or above the birthday from which a catch-up scan would
/// start when no block has been applied yet.
pub(super) fn scan_floor() -> BlockHeight {
    account_birthday()
}

/// `height + 1`, saturating instead of panicking at the top of the `u32`
/// height space.
pub(super) fn next_height(height: BlockHeight) -> BlockHeight {
    BlockHeight::from_u32(u32::from(height).saturating_add(1))
}

/// The concrete `WalletRead::Account` value for a fixed mint account.
///
/// Upstream provides the `Account` trait but no production record type. This
/// value is constructed only for an existing UFVK map entry and is never held
/// by `Wallet`; the database itself remains the fixed account-0/account-1 map.
pub struct FixedAccount {
    id: AccountId,
    ufvk: UnifiedFullViewingKey,
    source: AccountSource,
}

impl FixedAccount {
    pub(super) fn from_ufvk(id: AccountId, ufvk: UnifiedFullViewingKey) -> Option<Self> {
        matches!(id, TREASURY_ACCOUNT | REGISTRY_ACCOUNT).then_some(Self {
            id,
            ufvk,
            // Boot imports the viewing capability into this disposable
            // projection. The application retains the corresponding signing
            // capability outside Wallet.
            source: AccountSource::Imported {
                purpose: AccountPurpose::Spending { derivation: None },
                key_source: None,
            },
        })
    }

    fn name(&self) -> &'static str {
        if self.id == TREASURY_ACCOUNT {
            "Treasury"
        } else {
            debug_assert_eq!(self.id, REGISTRY_ACCOUNT);
            "Registry"
        }
    }
}

impl UpstreamAccount for FixedAccount {
    type AccountId = AccountId;

    fn id(&self) -> Self::AccountId {
        self.id
    }

    fn name(&self) -> Option<&str> {
        Some(self.name())
    }

    fn birthday_height(&self) -> BlockHeight {
        account_birthday()
    }

    fn source(&self) -> &AccountSource {
        &self.source
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        Some(&self.ufvk)
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.ufvk.to_unified_incoming_viewing_key()
    }
}

/// The largest retained checkpoint height at or below `bound`, walking down
/// from `start`.
///
/// Every applied block and the boot seed checkpoint are retained in all three
/// trees, so the walk is bounded by the store's retained checkpoint range.
pub(super) fn max_checkpoint_at_or_below<H, S>(
    store: &S,
    start: BlockHeight,
    bound: BlockHeight,
) -> Option<BlockHeight>
where
    S: ShardStore<H = H, CheckpointId = BlockHeight, Error = Infallible>,
{
    let floor = store.min_checkpoint_id().ok().flatten()?;
    let mut height = start.min(bound);
    while height >= floor {
        if store.get_checkpoint(&height).ok().flatten().is_some() {
            return Some(height);
        }
        if height == floor {
            break;
        }
        height = BlockHeight::from_u32(u32::from(height) - 1);
    }
    None
}

impl Wallet {
    /// The highest block height this wallet has applied, if any.
    pub(super) fn max_applied_height(&self) -> Option<BlockHeight> {
        self.blocks.last_key_value().map(|(height, _)| *height)
    }

    /// Folds one unspent note into its account's per-pool balance.
    ///
    /// Confirmation and trust classification is delegated to `wallet::input`
    /// so that balance reporting and input selection can never disagree.
    pub(super) fn add_note_to_balance(
        &self,
        balances: &mut HashMap<AccountId, AccountBalance>,
        account: AccountId,
        note_id: &zcash_client_backend::wallet::NoteId,
        is_change: bool,
        value: Zatoshis,
        pool: ShieldedPool,
        target_height: TargetHeight,
        policy: ConfirmationsPolicy,
    ) -> Result<(), WalletError> {
        use zcash_client_backend::wallet::OutputRef;

        let balance = balances
            .get_mut(&account)
            .expect("both fixed accounts are seeded with a zero balance");

        let Some(TransactionStatus::Mined(mined_height)) =
            self.transaction_statuses.get(note_id.txid())
        else {
            return Ok(());
        };
        let required = self.required_confirmations(note_id.txid(), is_change, policy);
        let confirmed = target_height.saturating_sub(u32::from(required)) >= *mined_height;
        let locked = self
            .locks
            .get(&OutputRef::from(*note_id))
            .is_some_and(|(_, expiry)| *expiry >= BlockHeight::from(target_height));

        let mut with_pool = |f: &mut dyn FnMut(&mut Balance) -> Result<(), WalletError>| match pool {
            ShieldedPool::Sapling => balance.with_sapling_balance_mut(|b| f(b)),
            ShieldedPool::Orchard => balance.with_orchard_balance_mut(|b| f(b)),
            ShieldedPool::Ironwood => balance.with_ironwood_balance_mut(|b| f(b)),
        };

        if !confirmed {
            with_pool(&mut |pool_balance| {
                if is_change {
                    pool_balance.add_pending_change_value(value)?;
                } else {
                    pool_balance.add_pending_spendable_value(value)?;
                }
                Ok(())
            })
        } else if locked {
            with_pool(&mut |pool_balance| Ok(pool_balance.add_locked_value(value)?))
        } else {
            with_pool(&mut |pool_balance| Ok(pool_balance.add_spendable_value(value)?))
        }
    }
}

impl WalletRead for Wallet {
    type Error = WalletError;
    type AccountId = AccountId;
    type Account = FixedAccount;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        Ok(self.ufvks.keys().copied().collect())
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Ok(self
            .ufvks
            .get(&account_id)
            .and_then(|ufvk| FixedAccount::from_ufvk(account_id, ufvk.clone())))
    }

    fn get_derived_account(
        &self,
        _derivation: &Zip32Derivation,
    ) -> Result<Option<Self::Account>, Self::Error> {
        // The wallet deliberately holds no ZIP-32 derivation metadata: the
        // seed never leaves the attested boundary, so no account can be
        // identified by seed fingerprint here.
        Ok(None)
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        _seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        match self.ufvks.get(&account_id) {
            // The wallet never sees the seed, so it cannot validate one; this
            // is the documented "no known ZIP-32 derivation" error path.
            Some(_) => Err(WalletError::FixedAccountsOnly),
            // A missing account is documented to return false.
            None => Ok(false),
        }
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        _seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        // Both accounts are imported viewing keys by construction.
        Ok(SeedRelevance::NoDerivedAccounts)
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        // `UnifiedFullViewingKey` has no equality, but
        // `UnifiedIncomingViewingKey` does (zcash_keys `keys.rs:1316`), so
        // compare through the incoming viewing keys.
        let queried = ufvk.to_unified_incoming_viewing_key();
        Ok(self.ufvks.iter().find_map(|(id, ufvk)| {
            (ufvk.to_unified_incoming_viewing_key() == queried)
                .then(|| FixedAccount::from_ufvk(*id, ufvk.clone()))
                .flatten()
        }))
    }

    fn list_addresses(&self, account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        // The wallet tracks no address index: addresses are derived on demand
        // from the fixed UFVKs and are never exposed through this database.
        let _ = account;
        Ok(Vec::new())
    }

    fn find_account_for_address<P: consensus::Parameters>(
        &self,
        params: &P,
        address: &Address,
    ) -> Result<Option<Self::AccountId>, FindAccountForAddressError<Self::Error>> {
        defaults::find_account_for_address(self, params, address)
    }

    fn get_last_generated_address_matching(
        &self,
        account: Self::AccountId,
        _address_filter: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        // No address is ever generated or persisted by this wallet.
        let _ = account;
        Ok(None)
    }

    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        match self.ufvks.get(&account) {
            Some(_) => Ok(account_birthday()),
            None => Err(WalletError::AccountUnknown(account)),
        }
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok((!self.ufvks.is_empty()).then(account_birthday))
    }

    fn get_wallet_recover_until(&self) -> Result<Option<BlockHeight>, Self::Error> {
        // The fixed accounts were created at the deployment scan floor, not
        // restored from backup, so there is no recovery horizon.
        Ok(None)
    }

    fn get_wallet_summary(
        &self,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        let Some(chain_tip_height) = self.zebra_tip else {
            return Ok(None);
        };
        let target_height = TargetHeight::from(next_height(chain_tip_height));

        let fully_scanned_height = self
            .max_applied_height()
            .unwrap_or_else(|| BlockHeight::from_u32(MINT_BIRTHDAY_HEIGHT - 1));

        let mut account_balances = self
            .ufvks
            .keys()
            .map(|id| (*id, AccountBalance::ZERO))
            .collect::<HashMap<AccountId, AccountBalance>>();

        for (note_id, output) in &self.sapling_notes {
            if self.sapling_note_is_spent(note_id, target_height) {
                continue;
            }
            let value = Zatoshis::try_from(output.note().value().inner())
                .expect("Sapling note values are within valid ZEC bounds by consensus");
            self.add_note_to_balance(
                &mut account_balances,
                *output.account_id(),
                note_id,
                output.is_change(),
                value,
                ShieldedPool::Sapling,
                target_height,
                confirmations_policy,
            )?;
        }
        for (note_id, output) in &self.ironwood_notes {
            if self.ironwood_note_is_spent(note_id, target_height) {
                continue;
            }
            let value = Zatoshis::from_u64(output.note().0.value().inner())
                .expect("Ironwood note values are within valid ZEC bounds by consensus");
            self.add_note_to_balance(
                &mut account_balances,
                *output.account_id(),
                note_id,
                output.is_change(),
                value,
                ShieldedPool::Ironwood,
                target_height,
                confirmations_policy,
            )?;
        }

        // Progress over the block span between the fixed birthday and the
        // Zebra tip; a display metric, not an authoritative note count.
        let scanned_span = u64::from(
            (u32::from(fully_scanned_height) + 1).saturating_sub(MINT_BIRTHDAY_HEIGHT),
        );
        let total_span =
            u64::from(u32::from(chain_tip_height).saturating_sub(MINT_BIRTHDAY_HEIGHT) + 1);
        let progress = Progress::new(
            Ratio::new(scanned_span.min(total_span), total_span),
            None,
        );

        let summary = WalletSummary::new(
            account_balances,
            chain_tip_height,
            fully_scanned_height,
            progress,
            self.sapling_tree_shard_end_heights.len() as u64,
            self.orchard_tree_shard_end_heights.len() as u64,
            self.ironwood_tree_shard_end_heights.len() as u64,
        );
        Ok(Some(summary))
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self.zebra_tip)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        Ok(self.blocks.get(&block_height).map(|m| m.block_hash()))
    }

    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(self.blocks.get(&height).cloned())
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        // Blocks are only ever applied sequentially, so the highest applied
        // block is by definition fully scanned.
        Ok(self
            .blocks
            .last_key_value()
            .map(|(_, metadata)| metadata.clone()))
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        Ok(self
            .blocks
            .last_key_value()
            .map(|(height, metadata)| (*height, metadata.block_hash())))
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        // This wallet never scans out of order.
        self.block_fully_scanned()
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        let Some(tip) = self.zebra_tip else {
            return Ok(Vec::new());
        };
        let start = self
            .max_applied_height()
            .map_or_else(scan_floor, next_height);
        let end = next_height(tip);
        if start >= end {
            Ok(Vec::new())
        } else {
            // One linear catch-up range: the mint rescans everything between
            // its applied tip and the Zebra tip, in order.
            Ok(vec![ScanRange::from_parts(
                start..end,
                ScanPriority::ChainTip,
            )])
        }
    }

    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> {
        let Some(tip) = self.zebra_tip else {
            return Ok(None);
        };
        let target = next_height(tip);
        // The anchor must have at least `min_confirmations` blocks on top of
        // it, relative to the next block.
        let bound = BlockHeight::from_u32(
            u32::from(target).saturating_sub(u32::from(min_confirmations)),
        );
        let start = self.max_applied_height().unwrap_or(bound);
        // The mint only ever spends Sapling and Ironwood, so the ordinary
        // Orchard compatibility tree does not constrain the anchor.
        let sapling = max_checkpoint_at_or_below(self.sapling_tree.store(), start, bound);
        let ironwood = max_checkpoint_at_or_below(self.ironwood_tree.store(), start, bound);
        let anchor = match (sapling, ironwood) {
            (Some(s), Some(i)) => Some(s.min(i)),
            (a, b) => a.or(b),
        };
        Ok(anchor.map(|height| (TargetHeight::from(target), height)))
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(match self.transaction_statuses.get(&txid) {
            Some(TransactionStatus::Mined(height)) => Some(*height),
            _ => None,
        })
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        Ok(self
            .ufvks
            .iter()
            .map(|(id, ufvk)| (*id, ufvk.clone()))
            .collect())
    }

    fn get_memo(
        &self,
        note_id: zcash_client_backend::wallet::NoteId,
    ) -> Result<Option<Memo>, Self::Error> {
        Ok(self.memos.get(&note_id).cloned())
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        Ok(self.transactions.get(&txid).cloned())
    }

    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        Ok(self
            .sapling_nullifiers
            .iter()
            .filter_map(|(nf, note_id)| {
                let note = self.sapling_notes.get(note_id)?;
                match query {
                    NullifierQuery::All => Some((*note.account_id(), *nf)),
                    // Spends known only from unmined transactions are not yet
                    // confirmed, so their nullifiers remain live for scanning.
                    NullifierQuery::Unspent => {
                        let confirmed = self
                            .sapling_note_spends
                            .get(note_id)
                            .and_then(|txid| self.transaction_statuses.get(txid))
                            .is_some_and(|s| matches!(s, TransactionStatus::Mined(_)));
                        (!confirmed).then_some((*note.account_id(), *nf))
                    }
                }
            })
            .collect())
    }

    fn get_orchard_nullifiers(
        &self,
        _query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        // The ordinary Orchard tree is maintained for compatibility only; the
        // mint owns no ordinary-Orchard notes and tracks no nullifiers.
        Ok(Vec::new())
    }

    fn get_ironwood_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        Ok(self
            .ironwood_nullifiers
            .iter()
            .filter_map(|(nf, note_id)| {
                let note = self.ironwood_notes.get(note_id)?;
                match query {
                    NullifierQuery::All => Some((*note.account_id(), *nf)),
                    NullifierQuery::Unspent => {
                        let confirmed = self
                            .ironwood_note_spends
                            .get(note_id)
                            .and_then(|txid| self.transaction_statuses.get(txid))
                            .is_some_and(|s| matches!(s, TransactionStatus::Mined(_)));
                        (!confirmed).then_some((*note.account_id(), *nf))
                    }
                }
            })
            .collect())
    }

    fn get_transparent_receivers(
        &self,
        _account: Self::AccountId,
        _include_change: bool,
        _include_standalone: bool,
    ) -> Result<HashMap<transparent::address::TransparentAddress, TransparentAddressMetadata>, Self::Error>
    {
        // Transparent support is outbound-only: neither fixed account owns,
        // derives, or reserves a transparent receiver through this wallet.
        Ok(HashMap::new())
    }

    fn get_ephemeral_transparent_receivers(
        &self,
        _account: Self::AccountId,
        _exposure_depth: u32,
        _exclude_used: bool,
    ) -> Result<HashMap<transparent::address::TransparentAddress, TransparentAddressMetadata>, Self::Error>
    {
        Ok(HashMap::new())
    }

    fn get_transparent_balances(
        &self,
        _account: Self::AccountId,
        _target_height: TargetHeight,
        _confirmations_policy: ConfirmationsPolicy,
    ) -> Result<TransparentBalances, Self::Error> {
        Ok(HashMap::new())
    }

    fn get_transparent_address_metadata(
        &self,
        _account: Self::AccountId,
        _address: &transparent::address::TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        Ok(None)
    }

    fn utxo_query_height(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        match self.ufvks.get(&account) {
            // No transparent receiver is ever derived, so there is nothing to
            // observe below the fixed scan floor.
            Some(_) => Ok(scan_floor()),
            None => Err(WalletError::AccountUnknown(account)),
        }
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        // This wallet keeps no enhancement queue; transaction data arrives
        // through `put_blocks` and `store_decrypted_tx`.
        Ok(Vec::new())
    }

    fn get_received_outputs(
        &self,
        txid: TxId,
        _target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> {
        let mut outputs = Vec::new();
        for (note_id, output) in &self.sapling_notes {
            if note_id.txid() != &txid {
                continue;
            }
            let confirmations =
                self.required_confirmations(&txid, output.is_change(), confirmations_policy);
            let value = Zatoshis::try_from(output.note().value().inner())
                .expect("Sapling note values are within valid ZEC bounds by consensus");
            outputs.push(ReceivedTransactionOutput::from_parts(
                PoolType::Shielded(ShieldedPool::Sapling),
                usize::from(note_id.output_index()),
                value,
                u32::from(confirmations),
            ));
        }
        for (note_id, output) in &self.ironwood_notes {
            if note_id.txid() != &txid {
                continue;
            }
            let confirmations =
                self.required_confirmations(&txid, output.is_change(), confirmations_policy);
            let value = Zatoshis::from_u64(output.note().0.value().inner())
                .expect("Ironwood note values are within valid ZEC bounds by consensus");
            outputs.push(ReceivedTransactionOutput::from_parts(
                PoolType::Shielded(ShieldedPool::Ironwood),
                usize::from(note_id.output_index()),
                value,
                u32::from(confirmations),
            ));
        }
        Ok(outputs)
    }
}

// ---------------------------------------------------------------------------
// Ironwood note reads beyond the upstream trait surface
// ---------------------------------------------------------------------------

impl Wallet {
    /// Returns every Ironwood note owned by `account` with no spend that is
    /// pending or mined as of `tip`: a spend recorded by a transaction whose
    /// expiry height has passed releases its note.
    pub fn unspent_ironwood_notes(
        &self,
        account: AccountId,
        tip: TargetHeight,
    ) -> Vec<ReceivedNote<NoteId, orchard::note::Note>> {
        self.ironwood_notes
            .iter()
            .filter(move |(_, output)| *output.account_id() == account)
            .filter(|(note_id, _)| !self.ironwood_note_is_spent(note_id, tip))
            .filter_map(|(note_id, _)| self.ironwood_received_note(*note_id))
            .collect()
    }

    /// Returns one Ironwood note with no pending-or-mined spend as of `tip`.
    pub(crate) fn unspent_ironwood_note(
        &self,
        account: AccountId,
        note_id: NoteId,
        tip: TargetHeight,
    ) -> Option<ReceivedNote<NoteId, orchard::note::Note>> {
        let output = self.ironwood_notes.get(&note_id)?;
        (*output.account_id() == account && !self.ironwood_note_is_spent(&note_id, tip))
            .then(|| self.ironwood_received_note(note_id))
            .flatten()
    }

    /// Finds an unspent owned Ironwood note by the `rho` persisted in a ZNS
    /// record, returning its native LRZ wallet representation.
    pub(crate) fn unspent_ironwood_note_by_rho(
        &self,
        account: AccountId,
        rho: orchard::note::Rho,
        tip: TargetHeight,
    ) -> Option<ReceivedNote<NoteId, orchard::note::Note>> {
        let note_id = self
            .ironwood_notes
            .iter()
            .find(|(_, output)| {
                *output.account_id() == account && output.note().0.rho() == rho
            })
            .map(|(note_id, _)| *note_id)?;
        self.unspent_ironwood_note(account, note_id, tip)
    }

    /// Returns the nullifiers of all Ironwood notes owned by `account` with
    /// no pending-or-mined spend as of `tip`, including value-0 notes: the
    /// Registry's Name Notes are value-0, and their nullifiers are what
    /// identifies a Registry spend in
    /// [`Registry::apply_block`](crate::mint::registry::Registry::apply_block)'s
    /// mint-authority check.
    ///
    /// Distinct from the [`WalletRead::get_ironwood_nullifiers`] impl above:
    /// that one classifies a spend as spent once its transaction is mined,
    /// while this read also blocks on locally recorded but unmined spends.
    pub(crate) fn unspent_ironwood_nullifiers(
        &self,
        account: AccountId,
        tip: TargetHeight,
    ) -> Vec<orchard::note::Nullifier> {
        self.ironwood_notes
            .iter()
            .filter(|(note_id, output)| {
                *output.account_id() == account
                    && !self.ironwood_note_is_spent(note_id, tip)
            })
            .filter_map(|(_, output)| output.nf().copied())
            .collect()
    }
}
