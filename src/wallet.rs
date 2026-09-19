//! In-memory wallet database for the ZNS mint.

mod input;
mod read;
mod trees;
mod write;

pub use read::WalletError;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use incrementalmerkletree::{Address, Marking, Retention};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use transparent::bundle::OutPoint;
use zcash_client_backend::scanning::ScanningKeys;
use zcash_client_backend::{
    data_api::chain::ChainState,
    data_api::locking::LockOwner,
    data_api::{
        anchor_retention::AnchorRetentionInterval, BlockMetadata, SentTransaction,
        SentTransactionOutput, TransactionStatus, WalletWrite,
    },
    wallet::{
        NoteId, OutputRef, ReceivedNote, WalletIronwoodOutput, WalletSaplingOutput,
        WalletTransparentOutput,
    },
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    consensus::{BlockHeight, Parameters, TxIndex},
    memo::Memo,
    value::Zatoshis,
};
use zip32::AccountId;

use crate::mint::TREASURY_ACCOUNT;

/// Depth of the Sapling note commitment tree,
const SAPLING_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;

/// Depth of the Orchard and Ironwood note commitment tree;
const ORCHARD_NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;

/// Shard height of the Sapling note commitment tree;
const SAPLING_SHARD_HEIGHT: u8 = 16;

/// Shard height of the Orchard and Ironwood note commitment trees;
const ORCHARD_SHARD_HEIGHT: u8 = 16;

/// Maximum checkpoints retained per note commitment tree.
const MAX_CHECKPOINTS: usize = 100;

/// Shard-tree error over the infallible in-memory store: only tree-structural
/// failures (`Query`, `Insert`) are reachable, never storage failures.
pub(crate) type TreeError = ShardTreeError<Infallible>;

/// The in-memory wallet for the two fixed mint accounts.
///
/// Owned shielded pools are Sapling (Treasury cold path —
/// `sweep_sapling_to_vault`) and Ironwood (Registry Name Notes and Treasury
/// operating pool). The ordinary Orchard commitment tree is kept only so
/// scanned blocks can append and checkpoint Orchard commitments in order;
/// this wallet never persists ordinary-Orchard received notes, nullifiers, or
/// spends. Under NU6.3 those inbound payments cannot arise; if a scanned
/// block still surfaces one, `put_blocks` refuses it rather than dropping
/// value.
pub struct Wallet<P: Parameters> {
    /// The consensus parameters of the network this wallet's accounts were
    /// derived for. The single authority for network context inside the
    /// wallet; callers of the free data-api functions keep passing their
    /// own `params` and must pass the same network.
    network: P,
    /// Interval-aligned checkpoints at or above NU6.3 are kept as durable
    /// anchors, outside the ordinary `MAX_CHECKPOINTS` pruning window.
    anchor_retention_interval: AnchorRetentionInterval,
    /// Per-account scan floors. Wallet-wide progress uses the earliest.
    account_birthdays: BTreeMap<AccountId, BlockHeight>,
    /// Exactly account 0 (Treasury) and account 1 (Registry).
    ufvks: BTreeMap<AccountId, UnifiedFullViewingKey>,

    /// Derived from those same UFVKs at birth: the scanner scans exactly
    /// what the wallet stores, by construction.
    scanning_keys: ScanningKeys<AccountId, (AccountId, zip32::Scope)>,

    /// The Zebra consensus tip last supplied through `WalletWrite::update_chain_tip`.
    zebra_tip: Option<BlockHeight>,

    /// Canonical Zebra blocks this in-memory projection has applied.
    blocks: BTreeMap<BlockHeight, BlockMetadata>,

    /// The boot origin cursor: the block before the birthday.
    seed: BlockMetadata,

    transactions: BTreeMap<TxId, Transaction>,
    transaction_statuses: BTreeMap<TxId, TransactionStatus>,
    transaction_indices: BTreeMap<TxId, TxIndex>,

    trusted_transactions: BTreeSet<TxId>,

    sapling_notes: BTreeMap<NoteId, WalletSaplingOutput<AccountId>>,
    ironwood_notes: BTreeMap<NoteId, WalletIronwoodOutput<AccountId>>,

    memos: BTreeMap<NoteId, Memo>,

    sapling_note_spends: BTreeMap<NoteId, TxId>,
    ironwood_note_spends: BTreeMap<NoteId, TxId>,

    sapling_nullifiers: BTreeMap<sapling::Nullifier, NoteId>,
    ironwood_nullifiers: BTreeMap<orchard::note::Nullifier, NoteId>,

    sent_outputs: BTreeMap<TxId, Vec<SentTransactionOutput<AccountId>>>,

    transparent_outputs: BTreeMap<OutPoint, WalletTransparentOutput<AccountId>>,
    transparent_output_spends: BTreeMap<OutPoint, TxId>,
    transparent_spends: BTreeSet<(TxId, OutPoint)>,

    /// Advisory locks use upstream `OutputRef` and `LockOwner` values directly.
    locks: BTreeMap<OutputRef, (LockOwner, BlockHeight)>,

    sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        SAPLING_NOTE_COMMITMENT_TREE_DEPTH,
        SAPLING_SHARD_HEIGHT,
    >,
    sapling_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        ORCHARD_NOTE_COMMITMENT_TREE_DEPTH,
        ORCHARD_SHARD_HEIGHT,
    >,
    orchard_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    ironwood_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        ORCHARD_NOTE_COMMITMENT_TREE_DEPTH,
        ORCHARD_SHARD_HEIGHT,
    >,
    ironwood_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
}

impl<P: Parameters> Wallet<P> {
    /// Builds the wallet against the origin checkpoint, for `network`.
    pub fn new(
        ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>,
        chain_state: &ChainState,
        network: P,
    ) -> Result<Self, TreeError> {
        let ufvks: BTreeMap<AccountId, UnifiedFullViewingKey> = ufvks.into_iter().collect();
        let scanning_keys = ScanningKeys::from_account_ufvks(ufvks.clone());
        let birthday =
            BlockHeight::from_u32(u32::from(chain_state.block_height()).saturating_add(1));
        let account_birthdays = ufvks.keys().map(|&id| (id, birthday)).collect();
        let mut wallet = Self {
            network,
            ufvks,
            scanning_keys,
            zebra_tip: None,
            account_birthdays,
            anchor_retention_interval: AnchorRetentionInterval::ZIP_318,
            blocks: BTreeMap::new(),
            seed: block_metadata(chain_state),
            transactions: BTreeMap::new(),
            transaction_statuses: BTreeMap::new(),
            transaction_indices: BTreeMap::new(),
            trusted_transactions: BTreeSet::new(),
            sapling_notes: BTreeMap::new(),
            ironwood_notes: BTreeMap::new(),
            memos: BTreeMap::new(),
            sapling_note_spends: BTreeMap::new(),
            ironwood_note_spends: BTreeMap::new(),
            sapling_nullifiers: BTreeMap::new(),
            ironwood_nullifiers: BTreeMap::new(),
            sent_outputs: BTreeMap::new(),
            transparent_outputs: BTreeMap::new(),
            transparent_output_spends: BTreeMap::new(),
            transparent_spends: BTreeSet::new(),
            locks: BTreeMap::new(),
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS),
            sapling_tree_shard_end_heights: BTreeMap::new(),
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS),
            orchard_tree_shard_end_heights: BTreeMap::new(),
            ironwood_tree: ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS),
            ironwood_tree_shard_end_heights: BTreeMap::new(),
        };
        let retention = Retention::Checkpoint {
            id: chain_state.block_height(),
            marking: Marking::Reference,
        };
        // Checkpoint id is birthday − 1: each frontier is the tree state at
        // the start of `MINT_BIRTHDAY`. Empty frontiers are inserted too —
        // the per-pool origin checkpoint is the reorg floor.
        wallet
            .sapling_tree
            .insert_frontier(chain_state.final_sapling_tree().clone(), retention)?;
        wallet
            .orchard_tree
            .insert_frontier(chain_state.final_orchard_tree().clone(), retention)?;
        wallet
            .ironwood_tree
            .insert_frontier(chain_state.final_ironwood_tree().clone(), retention)?;
        Ok(wallet)
    }

    /// The consensus parameters this wallet was constructed for.
    pub fn network(&self) -> &P {
        &self.network
    }

    /// The wallet's own scanning faculty, born from the same UFVKs.
    pub fn scanning_keys(&self) -> &ScanningKeys<AccountId, (AccountId, zip32::Scope)> {
        &self.scanning_keys
    }

    /// Returns the viewing key of one fixed mint account.
    pub fn ufvk_for(&self, account: AccountId) -> Option<&UnifiedFullViewingKey> {
        self.ufvks.get(&account)
    }

    /// Scan floor for one account, if the account is present.
    pub(crate) fn birthday_of(&self, account: AccountId) -> Option<BlockHeight> {
        self.account_birthdays.get(&account).copied()
    }

    /// Earliest account birthday; wallet-wide scan and progress floor.
    pub(crate) fn wallet_birthday(&self) -> Option<BlockHeight> {
        self.account_birthdays.values().copied().min()
    }

    /// Witnesses one received Ironwood note at `tip`.
    pub fn witness(
        &mut self,
        note: &ReceivedNote<NoteId, orchard::note::Note>,
        tip: BlockHeight,
    ) -> Option<orchard::tree::MerklePath> {
        let path = self
            .ironwood_witness(note.note_commitment_tree_position(), tip)
            .expect("FATAL: Ironwood tree access failed")
            .expect("FATAL: owned note has no witness at the applied tip");
        Some(orchard::tree::MerklePath::from(path))
    }

    /// The Ironwood anchor at `tip`: the root every spend of this block's
    /// transaction must prove against.
    pub fn anchor_at(&mut self, tip: BlockHeight) -> orchard::tree::Anchor {
        self.ironwood_anchor(tip)
            .expect("FATAL: Ironwood tree access failed")
            .expect("FATAL: wallet has no Ironwood anchor at its applied tip")
    }

    /// Records a mint-built transaction as sent-but-unconfirmed intent:
    /// marks its input spends (which also releases any locks) so the same
    /// notes cannot be selected again until the transaction either mines
    /// or expires.
    pub fn record_sent(
        &mut self,
        transaction: &Transaction,
        target_height: BlockHeight,
        fee: Zatoshis,
    ) {
        use zcash_client_backend::data_api::wallet::TargetHeight;
        use zcash_client_backend::data_api::WalletWrite as _;
        let sent = SentTransaction::new(
            transaction,
            time::OffsetDateTime::now_utc(),
            TargetHeight::from(target_height),
            TREASURY_ACCOUNT,
            &[],
            fee,
            &[],
        );
        self.store_transactions_to_be_sent(&[sent])
            .expect("FATAL: wallet rejected a locally built transaction");
    }

    /// The block hash at `height`: an applied block, or the boot origin.
    pub fn block_hash_at(&self, height: BlockHeight) -> Option<BlockHash> {
        self.blocks
            .get(&height)
            .map(|m| m.block_hash())
            .or_else(|| (height == self.seed.block_height()).then(|| self.seed.block_hash()))
    }

    /// Continuity metadata at `height`: an applied block, or the boot origin.
    pub fn block_metadata_at(&self, height: BlockHeight) -> Option<BlockMetadata> {
        self.blocks
            .get(&height)
            .cloned()
            .or_else(|| (height == self.seed.block_height()).then_some(self.seed))
    }

    /// Truncates the wallet to `max_height` and returns the
    /// [`BlockMetadata`] at that height — the new chain tip after reorg.
    pub fn truncate_to(&mut self, max_height: BlockHeight) -> Result<BlockMetadata, WalletError> {
        WalletWrite::truncate_to_height(self, max_height)?;
        self.block_metadata_at(max_height)
            .ok_or(WalletError::TruncationTargetUnavailable(max_height))
    }
}

/// Scan-cursor metadata implied by a [`ChainState`]: height, hash, tree sizes.
pub fn block_metadata(state: &ChainState) -> BlockMetadata {
    let sapling_size =
        u32::try_from(state.final_sapling_tree().tree_size()).expect("tree size fits u32");
    let orchard_size =
        u32::try_from(state.final_orchard_tree().tree_size()).expect("tree size fits u32");
    let ironwood_size =
        u32::try_from(state.final_ironwood_tree().tree_size()).expect("tree size fits u32");
    BlockMetadata::from_parts(
        state.block_height(),
        state.block_hash(),
        Some(sapling_size),
        Some(orchard_size),
        Some(ironwood_size),
    )
}

/// Adapter for upstream's unchanged Sapling scenarios. Only account setup is
/// special: all scanning, balances, input selection, locking and transaction
/// persistence use the real Wallet implementations. In particular, this does
/// not override the mint birthday or make unsupported operations succeed.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use incrementalmerkletree::{Hashable, Position};
    use secrecy::{ExposeSecret, SecretVec};
    use shardtree::store::ShardStore;
    use std::collections::BTreeSet;
    use zcash_client_backend::{
        data_api::{
            anchor_retention::AnchorRetentionInterval,
            chain::{error, BlockSource},
            testing::{CacheInsertionResult, DataStoreFactory, TestCache, TransactionSummary},
            AccountBirthday, OutputOfSentTx, WalletTest,
        },
        proto::compact_formats::CompactBlock,
        wallet::{Note, Recipient},
    };
    use zcash_keys::address::Address;
    use zcash_keys::keys::{transparent::gap_limits::GapLimits, UnifiedSpendingKey};
    use zcash_protocol::value::{BalanceError, ZatBalance};
    use zcash_protocol::{local_consensus::LocalNetwork, PoolType, ShieldedPool};

    pub(crate) struct Factory;

    impl DataStoreFactory for Factory {
        type Error = WalletError;
        type AccountId = AccountId;
        type Account = super::read::FixedAccount;
        type DsError = WalletError;
        type DataStore = Wallet<LocalNetwork>;

        fn new_data_store(
            &self,
            network: LocalNetwork,
            anchor_retention_interval: Option<AnchorRetentionInterval>,
            gap_limits: Option<GapLimits>,
        ) -> Result<Wallet<LocalNetwork>, WalletError> {
            assert!(gap_limits.is_none(), "address gap limits are not supported");
            let mut wallet = Wallet::new(
                [],
                &ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
                network,
            )?;
            if let Some(interval) = anchor_retention_interval {
                wallet.anchor_retention_interval = interval;
            }
            Ok(wallet)
        }
    }

    /// Installs the one account upstream's conformance scenarios need,
    /// translating the harness's seed-based `WalletWrite::create_account`
    /// call into the mint's fixed-account shape. Test builds only: the
    /// production trait method compiles this seam out entirely.
    ///
    /// The harness's test seed is a fixed public vector of zero bytes
    /// (`TestBuilder::build`); no secret ever crosses this boundary.
    pub(super) fn create_fixture_account<P: Parameters + Clone>(
        wallet: &mut Wallet<P>,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
    ) -> Result<(AccountId, UnifiedSpendingKey), WalletError> {
        // These scenarios need only one account. Fail loudly if a new test
        // requires account lifecycle behavior that the mint does not have.
        assert!(
            wallet.ufvks.is_empty(),
            "fixture supports one initial account only"
        );
        assert!(wallet.blocks.is_empty());
        let id = TREASURY_ACCOUNT;
        let usk = UnifiedSpendingKey::from_seed(&wallet.network, seed.expose_secret(), id)
            .expect("valid upstream test seed");
        let prior = birthday.prior_chain_state();
        let interval = wallet.anchor_retention_interval;
        // `TestBuilder::build` may already have written the birthday
        // frontier and shard roots through the public tree API; replacing
        // the wallet would discard them.
        let frontier_loaded = wallet
            .sapling_tree
            .store()
            .get_checkpoint(&prior.block_height())
            .ok()
            .flatten()
            .is_some();
        if frontier_loaded {
            wallet.seed = block_metadata(prior);
            let birthday = BlockHeight::from_u32(u32::from(prior.block_height()).saturating_add(1));
            wallet.ufvks.insert(id, usk.to_unified_full_viewing_key());
            wallet.account_birthdays.insert(id, birthday);
            wallet.scanning_keys = ScanningKeys::from_account_ufvks(wallet.ufvks.clone());
        } else {
            *wallet = Wallet::new(
                [(id, usk.to_unified_full_viewing_key())],
                prior,
                wallet.network.clone(),
            )?;
            wallet.anchor_retention_interval = interval;
        }
        Ok((id, usk))
    }

    #[derive(Default)]
    pub(crate) struct Cache(BTreeMap<BlockHeight, CompactBlock>);

    pub(crate) struct Inserted(Vec<TxId>);

    impl CacheInsertionResult for Inserted {
        fn txids(&self) -> &[TxId] {
            &self.0
        }
    }

    impl BlockSource for Cache {
        type Error = Infallible;

        fn with_blocks<F, E>(
            &self,
            from_height: Option<BlockHeight>,
            limit: Option<usize>,
            mut with_block: F,
        ) -> Result<(), error::Error<E, Infallible>>
        where
            F: FnMut(CompactBlock) -> Result<(), error::Error<E, Infallible>>,
        {
            for (_, block) in self
                .0
                .range(from_height.unwrap_or(BlockHeight::from_u32(0))..)
                .take(limit.unwrap_or(usize::MAX))
            {
                with_block(block.clone())?;
            }
            Ok(())
        }
    }

    impl TestCache for Cache {
        type BsError = Infallible;
        type BlockSource = Self;
        type InsertResult = Inserted;

        fn block_source(&self) -> &Self {
            self
        }

        fn insert(&mut self, block: &CompactBlock) -> Inserted {
            self.0.insert(block.height(), block.clone());
            Inserted(block.vtx.iter().map(|tx| tx.txid()).collect())
        }

        fn truncate_to_height(&mut self, height: BlockHeight) {
            self.0.retain(|h, _| *h <= height);
        }
    }

    fn checkpoint_history<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
        tree: &ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
    ) -> Result<Vec<(BlockHeight, Option<Position>)>, WalletError>
    where
        H: Hashable + Clone + PartialEq,
    {
        let count = tree.store().checkpoint_count()?;
        let mut out = Vec::with_capacity(count);
        tree.store().for_each_checkpoint(count, |cid, checkpoint| {
            out.push((*cid, checkpoint.position()));
            Ok(())
        })?;
        Ok(out)
    }

    fn add_zat(acc: Zatoshis, value: Zatoshis) -> Result<Zatoshis, WalletError> {
        (acc + value)
            .ok_or(BalanceError::Overflow)
            .map_err(Into::into)
    }

    fn sapling_value(output: &WalletSaplingOutput<AccountId>) -> Result<Zatoshis, WalletError> {
        Zatoshis::try_from(output.note().value().inner()).map_err(Into::into)
    }

    fn ironwood_value(output: &WalletIronwoodOutput<AccountId>) -> Result<Zatoshis, WalletError> {
        Zatoshis::from_u64(output.note().0.value().inner()).map_err(Into::into)
    }

    impl Wallet<LocalNetwork> {
        fn transaction_summary(
            &self,
            account: AccountId,
            txid: TxId,
        ) -> Result<TransactionSummary<AccountId>, WalletError> {
            let mut spent = Zatoshis::ZERO;
            let mut received = Zatoshis::ZERO;
            let mut spent_note_count = 0;
            let mut received_note_count = 0;
            let mut sent_note_count = 0;
            let mut has_change = false;
            let mut sent_output_value = Zatoshis::ZERO;
            let mut has_sent_outputs = false;

            for (note_id, output) in &self.sapling_notes {
                if *output.account_id() != account {
                    continue;
                }
                if *note_id.txid() == txid {
                    received = add_zat(received, sapling_value(output)?)?;
                    received_note_count += 1;
                    if output.is_change()
                        || output.recipient_key_scope() == Some(zip32::Scope::Internal)
                    {
                        has_change = true;
                    }
                }
                if self.sapling_note_spends.get(note_id) == Some(&txid) {
                    spent = add_zat(spent, sapling_value(output)?)?;
                    spent_note_count += 1;
                }
            }
            for (note_id, output) in &self.ironwood_notes {
                if *output.account_id() != account {
                    continue;
                }
                if *note_id.txid() == txid {
                    received = add_zat(received, ironwood_value(output)?)?;
                    received_note_count += 1;
                    if output.is_change()
                        || output.recipient_key_scope() == Some(zip32::Scope::Internal)
                    {
                        has_change = true;
                    }
                }
                if self.ironwood_note_spends.get(note_id) == Some(&txid) {
                    spent = add_zat(spent, ironwood_value(output)?)?;
                    spent_note_count += 1;
                }
            }

            if let Some(outputs) = self.sent_outputs.get(&txid) {
                has_sent_outputs = true;
                for output in outputs {
                    sent_output_value = add_zat(sent_output_value, output.value())?;
                    match output.recipient() {
                        Recipient::External { .. } => sent_note_count += 1,
                        Recipient::InternalShielded {
                            receiving_account,
                            external_address,
                            note,
                        } if *receiving_account == account => {
                            let Ok(index) = u16::try_from(output.output_index()) else {
                                continue;
                            };
                            let note_id = NoteId::new(txid, note.pool(), index);
                            let already = self.sapling_notes.contains_key(&note_id)
                                || self.ironwood_notes.contains_key(&note_id);
                            if !already {
                                received = add_zat(received, output.value())?;
                                received_note_count += 1;
                            }
                            if external_address.is_none() {
                                has_change = true;
                            }
                        }
                        _ => {}
                    }
                }
            }

            let mined_height = match self.transaction_statuses.get(&txid) {
                Some(TransactionStatus::Mined(height)) => Some(*height),
                _ => None,
            };
            let expiry_height = self.transactions.get(&txid).map(|tx| tx.expiry_height());
            let expired_unmined = mined_height.is_none()
                && expiry_height
                    .filter(|height| u32::from(*height) > 0)
                    .is_some_and(|expiry| self.zebra_tip.is_some_and(|tip| expiry <= tip));
            let fee_paid = has_sent_outputs
                .then(|| spent - sent_output_value)
                .flatten();
            let delta = i64::try_from(received.into_u64()).expect("zatoshis fit i64")
                - i64::try_from(spent.into_u64()).expect("zatoshis fit i64");
            let memo_count = self
                .memos
                .iter()
                .filter(|(note_id, memo)| *note_id.txid() == txid && !matches!(memo, Memo::Empty))
                .count();

            Ok(TransactionSummary::from_parts(
                account,
                txid,
                expiry_height,
                mined_height,
                ZatBalance::from_i64(delta)?,
                spent,
                received,
                fee_paid,
                spent_note_count,
                has_change,
                sent_note_count,
                received_note_count,
                memo_count,
                expired_unmined,
                false,
                None,
            ))
        }
    }

    impl WalletTest for Wallet<LocalNetwork> {
        fn get_tx_history(&self) -> Result<Vec<TransactionSummary<AccountId>>, WalletError> {
            let mut pairs = BTreeSet::new();
            for (note_id, output) in &self.sapling_notes {
                pairs.insert((*output.account_id(), *note_id.txid()));
                if let Some(spend_txid) = self.sapling_note_spends.get(note_id) {
                    pairs.insert((*output.account_id(), *spend_txid));
                }
            }
            for (note_id, output) in &self.ironwood_notes {
                pairs.insert((*output.account_id(), *note_id.txid()));
                if let Some(spend_txid) = self.ironwood_note_spends.get(note_id) {
                    pairs.insert((*output.account_id(), *spend_txid));
                }
            }
            for (txid, outputs) in &self.sent_outputs {
                for output in outputs {
                    if let Recipient::InternalShielded {
                        receiving_account, ..
                    } = output.recipient()
                    {
                        pairs.insert((*receiving_account, *txid));
                    }
                }
            }

            let mut history = Vec::with_capacity(pairs.len());
            for (account, txid) in pairs {
                history.push(self.transaction_summary(account, txid)?);
            }
            // Newest mined height first, unmined last — sqlite's
            // `ORDER BY mined_height DESC, tx_index DESC` with NULLs last.
            history.sort_by(|a, b| match (a.mined_height(), b.mined_height()) {
                (Some(ha), Some(hb)) => hb.cmp(&ha).then_with(|| {
                    let ia = self
                        .transaction_indices
                        .get(&a.txid())
                        .copied()
                        .map(u16::from)
                        .unwrap_or(0);
                    let ib = self
                        .transaction_indices
                        .get(&b.txid())
                        .copied()
                        .map(u16::from)
                        .unwrap_or(0);
                    ib.cmp(&ia)
                }),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.txid().cmp(&b.txid()),
            });
            Ok(history)
        }

        fn get_sent_note_ids(
            &self,
            txid: &TxId,
            protocol: ShieldedPool,
        ) -> Result<Vec<NoteId>, WalletError> {
            let Some(outputs) = self.sent_outputs.get(txid) else {
                return Ok(Vec::new());
            };
            Ok(outputs
                .iter()
                .filter_map(|output| {
                    let pool = match output.recipient() {
                        Recipient::External {
                            output_pool: PoolType::Shielded(pool),
                            ..
                        } => *pool,
                        Recipient::InternalShielded { note, .. } => note.pool(),
                        _ => return None,
                    };
                    (pool == protocol).then(|| {
                        NoteId::new(
                            *txid,
                            protocol,
                            u16::try_from(output.output_index()).expect("output index fits u16"),
                        )
                    })
                })
                .collect())
        }

        fn get_sent_outputs(&self, txid: &TxId) -> Result<Vec<OutputOfSentTx>, WalletError> {
            let Some(outputs) = self.sent_outputs.get(txid) else {
                return Ok(Vec::new());
            };
            Ok(outputs
                .iter()
                .map(|output| {
                    let external = match output.recipient() {
                        Recipient::External {
                            recipient_address, ..
                        } => Address::try_from_zcash_address(
                            &self.network,
                            recipient_address.clone(),
                        )
                        .ok(),
                        Recipient::InternalShielded {
                            external_address, ..
                        } => external_address.as_ref().and_then(|addr| {
                            Address::try_from_zcash_address(&self.network, addr.clone()).ok()
                        }),
                        _ => None,
                    };
                    OutputOfSentTx::from_parts(output.value(), external, None)
                })
                .collect())
        }

        fn get_checkpoint_history(
            &self,
            protocol: &ShieldedPool,
        ) -> Result<Vec<(BlockHeight, Option<Position>)>, WalletError> {
            match protocol {
                ShieldedPool::Sapling => checkpoint_history(&self.sapling_tree),
                ShieldedPool::Orchard => checkpoint_history(&self.orchard_tree),
                ShieldedPool::Ironwood => checkpoint_history(&self.ironwood_tree),
            }
        }

        fn get_notes(
            &self,
            protocol: ShieldedPool,
        ) -> Result<Vec<ReceivedNote<NoteId, Note>>, WalletError> {
            match protocol {
                ShieldedPool::Sapling => Ok(self
                    .sapling_notes
                    .keys()
                    .map(|id| {
                        self.sapling_received_note(*id)
                            .expect("stored note has spending scope")
                            .map_note(Note::Sapling)
                    })
                    .collect()),
                _ => unimplemented!("this batch covers Sapling only"),
            }
        }
    }
}
