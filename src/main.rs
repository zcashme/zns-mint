use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::scanning::ScanningKeys;
use zcash_primitives::block::Block;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};

use zns_mint::boot::Boot;
use zns_mint::live::{self, LiveState};
use zns_mint::metrics;
use zns_mint::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zns_mint::registry::state::Registry;
use zns_mint::registry::{classify_registry_ironwood_note, RegistryNoteClass};
use zns_mint::sync::scan_block;
use zns_mint::wallet::trees::RETAINED_CHECKPOINTS;
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{CanonicalBlockSource, CanonicalTip, ChainClient, JsonRpc, TransportError};

/// Polling interval when waiting for the next best-chain block.
const BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Read-only chain capability consumed by passive canonical reconstruction.
///
/// The production implementation is Zebra-backed. Keeping the runtime generic
/// over this private boundary permits deterministic branch and crash schedules
/// in tests without exposing submission or key capabilities.
trait CanonicalBlockReader {
    async fn exact_tip(&self) -> Result<CanonicalTip, TransportError>;
    async fn get_block(&self, height: BlockHeight) -> Result<Block, TransportError>;
}

impl CanonicalBlockReader for CanonicalBlockSource {
    async fn exact_tip(&self) -> Result<CanonicalTip, TransportError> {
        CanonicalBlockSource::exact_tip(self).await
    }

    async fn get_block(&self, height: BlockHeight) -> Result<Block, TransportError> {
        CanonicalBlockSource::get_block(self, height).await
    }
}

/// The result of one catch-up cycle.
struct CatchUpResult {
    /// Txids of all transactions in blocks applied during this cycle.
    applied_txids: Vec<TxId>,
    /// Whether a reorg occurred during this cycle. When true, the main loop
    /// invalidates all cursor-bound operational state.
    reorged: bool,
}

/// Top-level canonical replay error.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("block scan failed: {0}")]
    Scan(#[from] zns_mint::sync::ScanError),
    #[error("Registry transition rejected: {0}")]
    Registry(#[from] zns_mint::registry::state::RegistryApplyError),
    #[error("wallet block application failed: {0}")]
    Wallet(#[from] zns_mint::wallet::WalletApplyError),
    #[error("reorg extends below the retained deterministic metadata history")]
    ReorgBeyondHistory,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");

    tokio::spawn(metrics::serve());

    let boot = Boot::run().await;
    metrics::set_boot_success(true);

    let boot_height = boot.height();
    let mut cursor = *boot.cursor().metadata();
    let (mut chain, mut wallet, mut registry, treasury, treasury_keys, registry_keys) =
        boot.into_parts();
    let block_source = CanonicalBlockSource::new();
    let rpc = JsonRpc::new();
    let mut live_state = LiveState::new();
    let mut chain_history = BTreeMap::from([(cursor.block_height(), cursor)]);
    publish_canonical_gauges(&wallet, cursor.block_height());

    tracing::info!(
        height = u32::from(boot_height),
        "zns-mint: boot complete; entering passive block fold loop"
    );

    // The gRPC stream is only a wake-up source. Canonical block retrieval and
    // continuity checks use JSON-RPC.
    let mut tip_stream = open_tip_stream(&mut chain)
        .await
        .expect("FATAL: could not open Zebra chain-tip stream");

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("zns-mint: received ctrl-c, shutting down");
                break;
            }
            tip_event = tip_stream.message() => {
                match tip_event {
                    Ok(Some(tip)) => {
                        let (height, hash) = zns_mint::zcash::tip_height_hash(&tip);
                        tracing::debug!(height = u32::from(height), %hash, "chain tip event");
                    }
                    Ok(None) => {
                        tracing::warn!("Zebra tip stream closed; waiting before reconnect");
                        tokio::time::sleep(BLOCK_POLL_INTERVAL).await;
                        tip_stream = open_tip_stream(&mut chain)
                            .await
                            .expect("FATAL: could not reopen Zebra chain-tip stream");
                    }
                    Err(error) => {
                        metrics::inc_rpc_error("chain_tip_change");
                        tracing::warn!(error = %error, "tip stream error; reconnecting");
                        tokio::time::sleep(BLOCK_POLL_INTERVAL).await;
                        tip_stream = open_tip_stream(&mut chain)
                            .await
                            .expect("FATAL: could not reopen Zebra chain-tip stream");
                    }
                }
            }
            _ = tokio::time::sleep(BLOCK_POLL_INTERVAL) => {}
        }

        let catch_up_result = catch_up(
            &block_source,
            &mut wallet,
            &mut registry,
            &mut cursor,
            &mut chain_history,
        )
        .await;

        match catch_up_result {
            Ok(result) => {
                // On reorg, invalidate all cursor-bound operational state.
                if result.reorged {
                    tracing::info!("live: reorg detected; invalidating operational state");
                    live_state.invalidate();
                }

                // Check confirmations for submitted transactions.
                if !result.applied_txids.is_empty() {
                    live::check_confirmations(
                        &mut live_state,
                        &result.applied_txids,
                        cursor.block_height(),
                    );
                }

                // Reconcile and execute Live work.
                let work = live::reconcile(
                    &mut live_state,
                    &wallet,
                    &registry,
                    &treasury,
                    cursor.block_height(),
                );

                if !work.is_empty() {
                    tracing::info!(
                        work_count = work.len(),
                        height = u32::from(cursor.block_height()),
                        "live: reconciled pending work"
                    );

                    let new_submissions = live::execute(
                        &mut live_state,
                        &mut wallet,
                        &registry,
                        &treasury_keys,
                        &registry_keys,
                        &rpc,
                        cursor.block_height(),
                        work,
                    )
                    .await;

                    for sub in &new_submissions {
                        metrics::inc_tx_submitted(sub.kind.as_str());
                    }
                }
            }
            Err(RuntimeError::Transport(error)) if error.is_retryable() => {
                tracing::warn!(error = %error, "canonical catch-up transport failed; retrying");
            }
            Err(error) => {
                panic!("FATAL: canonical catch-up failed: {error}");
            }
        }
    }
}

async fn open_tip_stream(
    chain: &mut ChainClient,
) -> Result<tonic::codec::Streaming<zebra_indexer_proto::BlockHashAndHeight>, tonic::Status> {
    use zebra_indexer_proto::Empty;
    let response = chain.client().chain_tip_change(Empty {}).await?;
    Ok(response.into_inner())
}

/// Rebuilds passively to one exact Zebra target and verifies it before success.
///
/// This path performs no request, OTP, policy, signing, proving, or submission
/// operation. Decrypted observations remain in canonical wallet history for a
/// later Live phase to interpret after an exact rebuild boundary is established.
async fn catch_up<S: CanonicalBlockReader>(
    block_source: &S,
    wallet: &mut Wallet,
    registry: &mut Registry,
    cursor: &mut BlockMetadata,
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
) -> Result<CatchUpResult, RuntimeError> {
    let ufvks: HashMap<zip32::AccountId, zcash_keys::keys::UnifiedFullViewingKey> = wallet
        .ufvk_map()
        .iter()
        .map(|(account_id, ufvk)| (*account_id, ufvk.clone()))
        .collect();
    let scanning_keys = ScanningKeys::from_account_ufvks(ufvks.clone());

    let mut applied_txids = Vec::new();
    let mut reorged = false;

    'targets: loop {
        let target = block_source.exact_tip().await?;
        let Some(captured_target_block) =
            get_block_while_target_is_current(block_source, target.height(), target).await?
        else {
            continue 'targets;
        };
        if captured_target_block.header().hash() != target.hash() {
            if block_source.exact_tip().await? != target {
                continue 'targets;
            }
            return Err(TransportError::BadNodeData(
                "captured target hash disagrees with getblockchaininfo",
            )
            .into());
        }

        let comparison_height = std::cmp::min(cursor.block_height(), target.height());
        let Some(local_at_comparison) = chain_history.get(&comparison_height).copied() else {
            if block_source.exact_tip().await? != target {
                continue 'targets;
            }
            return Err(RuntimeError::ReorgBeyondHistory);
        };
        let selected_hash = if comparison_height == target.height() {
            target.hash()
        } else {
            let Some(block) =
                get_block_while_target_is_current(block_source, comparison_height, target).await?
            else {
                continue 'targets;
            };
            block.header().hash()
        };

        if cursor.block_height() > target.height()
            || local_at_comparison.block_hash() != selected_hash
        {
            let Some(common_ancestor) = find_common_ancestor_while_target_is_current(
                block_source,
                chain_history,
                comparison_height,
                target,
            )
            .await?
            else {
                continue 'targets;
            };
            rewind_canonical_state(
                wallet,
                registry,
                cursor,
                chain_history,
                &common_ancestor,
            )?;
            reorged = true;
            continue 'targets;
        }

        while cursor.block_height() < target.height() {
            let next_height = cursor.block_height() + 1;
            let Some(block) =
                get_block_while_target_is_current(block_source, next_height, target).await?
            else {
                continue 'targets;
            };

            if next_height == target.height() && block.header().hash() != target.hash() {
                if block_source.exact_tip().await? != target {
                    continue 'targets;
                }
                return Err(TransportError::BadNodeData(
                    "target block hash disagrees with getblockchaininfo",
                )
                .into());
            }

            if block.header().prev_block != cursor.block_hash() {
                tracing::warn!(
                    height = u32::from(next_height),
                    expected = %cursor.block_hash(),
                    actual = %block.header().prev_block,
                    "reorg detected: block prev_hash does not match cursor"
                );

                let Some(common_ancestor) = find_common_ancestor_while_target_is_current(
                    block_source,
                    chain_history,
                    cursor.block_height(),
                    target,
                )
                .await?
                else {
                    continue 'targets;
                };
                if common_ancestor.block_height() == cursor.block_height() {
                    if block_source.exact_tip().await? != target {
                        continue 'targets;
                    }
                    return Err(TransportError::BadNodeData(
                        "canonical successor does not extend the accepted cursor",
                    )
                    .into());
                }
                rewind_canonical_state(
                    wallet,
                    registry,
                    cursor,
                    chain_history,
                    &common_ancestor,
                )?;
                reorged = true;
                continue 'targets;
            }

            let txids = apply_canonical_block(
                block,
                wallet,
                registry,
                cursor,
                chain_history,
                &ufvks,
                &scanning_keys,
            )?;
            applied_txids.extend(txids);
        }

        if cursor.block_height() != target.height() || cursor.block_hash() != target.hash() {
            continue 'targets;
        }

        let Some(target_block) =
            get_block_while_target_is_current(block_source, target.height(), target).await?
        else {
            continue 'targets;
        };
        if target_block.header().hash() != target.hash() {
            if block_source.exact_tip().await? != target {
                continue 'targets;
            }
            return Err(TransportError::BadNodeData(
                "verified target hash disagrees with getblockchaininfo",
            )
            .into());
        }
        if block_source.exact_tip().await? != target {
            continue 'targets;
        }

        publish_canonical_gauges(wallet, cursor.block_height());
        return Ok(CatchUpResult {
            applied_txids,
            reorged,
        });
    }
}

/// Reads one height and accepts the result only if `target` remains exact.
async fn get_block_while_target_is_current(
    block_source: &impl CanonicalBlockReader,
    height: BlockHeight,
    target: CanonicalTip,
) -> Result<Option<Block>, RuntimeError> {
    let result = block_source.get_block(height).await.and_then(|block| {
        if block.claimed_height() == height {
            Ok(block)
        } else {
            Err(TransportError::BadNodeData(
                "canonical block source returned the wrong height",
            ))
        }
    });
    if block_source.exact_tip().await? != target {
        return Ok(None);
    }

    result.map(Some).map_err(RuntimeError::from)
}

/// Accepts an ancestor-search result only if `target` remains exact.
async fn find_common_ancestor_while_target_is_current(
    block_source: &impl CanonicalBlockReader,
    chain_history: &BTreeMap<BlockHeight, BlockMetadata>,
    start_height: BlockHeight,
    target: CanonicalTip,
) -> Result<Option<BlockMetadata>, RuntimeError> {
    let mut height = start_height;
    loop {
        let Some(local) = chain_history.get(&height) else {
            if block_source.exact_tip().await? != target {
                return Ok(None);
            }
            return Err(RuntimeError::ReorgBeyondHistory);
        };
        let canonical_hash = if height == target.height() {
            target.hash()
        } else {
            let Some(block) =
                get_block_while_target_is_current(block_source, height, target).await?
            else {
                return Ok(None);
            };
            block.header().hash()
        };
        if canonical_hash == local.block_hash() {
            if block_source.exact_tip().await? != target {
                return Ok(None);
            }
            return Ok(Some(*local));
        }
        if height == BlockHeight::from_u32(0) {
            if block_source.exact_tip().await? != target {
                return Ok(None);
            }
            return Err(RuntimeError::ReorgBeyondHistory);
        }
        let previous_height = height - 1;
        if !chain_history.contains_key(&previous_height) {
            if block_source.exact_tip().await? != target {
                return Ok(None);
            }
            return Err(RuntimeError::ReorgBeyondHistory);
        }
        height = previous_height;
    }
}

/// Rewinds every canonical subsystem to one exact accepted ancestor.
fn rewind_canonical_state(
    wallet: &mut Wallet,
    registry: &mut Registry,
    cursor: &mut BlockMetadata,
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
    common_ancestor: &BlockMetadata,
) -> Result<(), RuntimeError> {
    let ancestor_height = common_ancestor.block_height();

    wallet.rewind_to_height(ancestor_height)?;
    registry.truncate_to_height(ancestor_height);
    chain_history.retain(|height, _| *height <= ancestor_height);
    *cursor = *common_ancestor;

    tracing::info!(
        height = u32::from(ancestor_height),
        "rewound canonical state to common ancestor"
    );

    Ok(())
}

/// Publishes snapshots derived exclusively from installed canonical state.
fn publish_canonical_gauges(wallet: &Wallet, height: BlockHeight) {
    metrics::set_chain_height(u32::from(height));
    metrics::set_treasury_balance(wallet.balance(TREASURY_ACCOUNT).into_u64());
    metrics::set_registry_fee_notes(
        wallet
            .ironwood_notes_for(REGISTRY_ACCOUNT)
            .filter(|note| classify_registry_ironwood_note(note) == RegistryNoteClass::Fee)
            .count() as u64,
    );
}

/// Retains exactly the metadata horizon supported by all three tree caches.
fn record_accepted_metadata(
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
    metadata: BlockMetadata,
) {
    chain_history.insert(metadata.block_height(), metadata);
    while chain_history.len() > RETAINED_CHECKPOINTS {
        chain_history.pop_first();
    }
}

/// Scans and commits one continuous canonical block.
///
/// Cursor and accepted history advance only after Registry simulation and
/// Wallet application both succeed. Success returns no event payload; later
/// operational work reconciles from the installed canonical state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanonicalCommitStage {
    Scan,
    RegistrySimulation,
    Wallet,
    Registry,
    History,
    Cursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitBoundary {
    Before(CanonicalCommitStage),
    After(CanonicalCommitStage),
}

fn apply_canonical_block(
    block: Block,
    wallet: &mut Wallet,
    registry: &mut Registry,
    cursor: &mut BlockMetadata,
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
    ufvks: &HashMap<zip32::AccountId, zcash_keys::keys::UnifiedFullViewingKey>,
    scanning_keys: &ScanningKeys<zip32::AccountId, (zip32::AccountId, zip32::Scope)>,
) -> Result<Vec<TxId>, RuntimeError> {
    apply_canonical_block_with_fault(
        block,
        wallet,
        registry,
        cursor,
        chain_history,
        ufvks,
        scanning_keys,
        |_| {},
    )
}

/// Canonical fold with a crash boundary around every ordered commit stage.
///
/// Production supplies a no-op hook. Tests panic at each boundary, discard the
/// interrupted in-memory state exactly as a process crash would, and rebuild
/// from the origin checkpoint.
#[allow(clippy::too_many_arguments)]
fn apply_canonical_block_with_fault(
    block: Block,
    wallet: &mut Wallet,
    registry: &mut Registry,
    cursor: &mut BlockMetadata,
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
    ufvks: &HashMap<zip32::AccountId, zcash_keys::keys::UnifiedFullViewingKey>,
    scanning_keys: &ScanningKeys<zip32::AccountId, (zip32::AccountId, zip32::Scope)>,
    mut fault: impl FnMut(CommitBoundary),
) -> Result<Vec<TxId>, RuntimeError> {
    fault(CommitBoundary::Before(CanonicalCommitStage::Scan));
    let output = scan_block(&MAIN_NETWORK, Some(cursor), block, ufvks, scanning_keys)?;
    fault(CommitBoundary::After(CanonicalCommitStage::Scan));

    fault(CommitBoundary::Before(
        CanonicalCommitStage::RegistrySimulation,
    ));
    let next_registry = registry.apply_block(wallet, &output)?;
    fault(CommitBoundary::After(
        CanonicalCommitStage::RegistrySimulation,
    ));

    fault(CommitBoundary::Before(CanonicalCommitStage::Wallet));
    wallet.apply_block(&output, cursor.block_height())?;
    fault(CommitBoundary::After(CanonicalCommitStage::Wallet));

    fault(CommitBoundary::Before(CanonicalCommitStage::Registry));
    *registry = next_registry;
    fault(CommitBoundary::After(CanonicalCommitStage::Registry));

    let metadata = *output.metadata();
    fault(CommitBoundary::Before(CanonicalCommitStage::History));
    record_accepted_metadata(chain_history, metadata);
    fault(CommitBoundary::After(CanonicalCommitStage::History));

    fault(CommitBoundary::Before(CanonicalCommitStage::Cursor));
    *cursor = metadata;
    fault(CommitBoundary::After(CanonicalCommitStage::Cursor));

    // Collect txids for confirmation checking by the Live phase.
    let txids: Vec<TxId> = output.transactions().iter().map(|tx| tx.txid()).collect();

    Ok(txids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::frontier::CommitmentTree;
    use secrecy::Secret;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use transparent::builder::{Coinbase, TransparentBuilder};
    use zcash_client_backend::scanning::ScanningKeys;
    use zcash_primitives::block::{BlockHash, BlockHeaderData};
    use zcash_primitives::transaction::{Authorized, TransactionData};
    use zcash_protocol::consensus::BranchId;
    use zns_mint::key::{derive_registry, derive_treasury};
    use zns_mint::zcash::{BlockchainInfo, CheckpointData};

    struct TestOrigin {
        height: BlockHeight,
        hash: BlockHash,
        block: Vec<u8>,
    }

    #[derive(Clone)]
    struct TestChain {
        blocks: BTreeMap<BlockHeight, Vec<u8>>,
        tip: CanonicalTip,
    }

    impl TestChain {
        fn from_origin(origin: &TestOrigin, salts: &[u32]) -> Self {
            let mut blocks = BTreeMap::from([(origin.height, origin.block.clone())]);
            let mut height = origin.height;
            let mut previous_hash = origin.hash;

            for salt in salts {
                height = height + 1;
                let (block, hash) = test_block(height, previous_hash, *salt);
                blocks.insert(height, block);
                previous_hash = hash;
            }

            Self {
                blocks,
                tip: canonical_tip(height, previous_hash),
            }
        }

        fn prefix(&self, height: BlockHeight) -> Self {
            let blocks = self
                .blocks
                .range(..=height)
                .map(|(height, block)| (*height, block.clone()))
                .collect();
            let block = Block::read(
                &self.blocks.get(&height).expect("prefix block exists")[..],
                &MAIN_NETWORK,
            )
            .expect("test block parses");
            Self {
                blocks,
                tip: canonical_tip(height, block.header().hash()),
            }
        }
    }

    struct ScriptedBlockSource {
        chains: Vec<TestChain>,
        tip_script: RefCell<VecDeque<usize>>,
        active_chain: Cell<usize>,
    }

    impl ScriptedBlockSource {
        fn stable(chain: TestChain) -> Self {
            Self {
                chains: vec![chain],
                tip_script: RefCell::new(VecDeque::new()),
                active_chain: Cell::new(0),
            }
        }

        fn moving(chains: Vec<TestChain>, tip_script: impl IntoIterator<Item = usize>) -> Self {
            Self {
                chains,
                tip_script: RefCell::new(tip_script.into_iter().collect()),
                active_chain: Cell::new(0),
            }
        }
    }

    impl CanonicalBlockReader for ScriptedBlockSource {
        async fn exact_tip(&self) -> Result<CanonicalTip, TransportError> {
            if let Some(next) = self.tip_script.borrow_mut().pop_front() {
                self.active_chain.set(next);
            }
            Ok(self.chains[self.active_chain.get()].tip)
        }

        async fn get_block(&self, height: BlockHeight) -> Result<Block, TransportError> {
            let bytes = self.chains[self.active_chain.get()]
                .blocks
                .get(&height)
                .ok_or(TransportError::BadNodeData("scripted block missing"))?;
            Block::read(&bytes[..], &MAIN_NETWORK)
                .map_err(|_| TransportError::BadNodeData("scripted block parse"))
        }
    }

    struct TestCanonicalState {
        wallet: Wallet,
        registry: Registry,
        cursor: BlockMetadata,
        history: BTreeMap<BlockHeight, BlockMetadata>,
    }

    impl TestCanonicalState {
        fn new(origin: &TestOrigin) -> Self {
            let seed = Secret::new([7u8; 32]);
            let treasury = derive_treasury(&seed);
            let registry_keys = derive_registry(&seed);
            let metadata = BlockMetadata::from_parts(
                origin.height,
                origin.hash,
                Some(0),
                Some(0),
                Some(0),
            );
            let checkpoint = CheckpointData {
                metadata,
                sapling_tree: CommitmentTree::empty(),
                orchard_tree: CommitmentTree::empty(),
                ironwood_tree: Some(CommitmentTree::empty()),
            };
            let mut wallet = Wallet::new([
                (TREASURY_ACCOUNT, treasury.fvk()),
                (REGISTRY_ACCOUNT, registry_keys.fvk()),
            ]);
            wallet.seed_trees(&checkpoint, origin.height);

            Self {
                wallet,
                registry: Registry::new(),
                cursor: metadata,
                history: BTreeMap::from([(origin.height, metadata)]),
            }
        }

        async fn catch_up(&mut self, source: &impl CanonicalBlockReader) {
            super::catch_up(
                source,
                &mut self.wallet,
                &mut self.registry,
                &mut self.cursor,
                &mut self.history,
            )
            .await
            .expect("scripted canonical reconstruction succeeds");
        }
    }

    fn canonical_tip(height: BlockHeight, hash: BlockHash) -> CanonicalTip {
        BlockchainInfo {
            blocks: u32::from(height),
            bestblockhash: hash.to_string(),
        }
        .canonical_tip()
        .expect("displayed block hash round-trips")
    }

    fn test_origin() -> TestOrigin {
        let height = BlockHeight::from_u32(3_500_000);
        let (block, hash) = test_block(height, BlockHash([0; 32]), 0);
        TestOrigin {
            height,
            hash,
            block,
        }
    }

    fn test_block(
        height: BlockHeight,
        previous_hash: BlockHash,
        salt: u32,
    ) -> (Vec<u8>, BlockHash) {
        let transparent = TransparentBuilder::empty()
            .build_coinbase(height, None)
            .expect("test coinbase")
            .map_authorization::<transparent::bundle::Authorized, _>(Coinbase);
        let transaction = TransactionData::<Authorized>::from_parts_v6(
            BranchId::for_height(&MAIN_NETWORK, height),
            0,
            height,
            Some(transparent),
            None,
            None,
            None,
        )
        .freeze()
        .expect("test transaction freezes");
        let header = BlockHeaderData {
            version: 4,
            prev_block: previous_hash,
            merkle_root: [salt as u8; 32],
            final_sapling_root: [0; 32],
            time: salt,
            bits: 0,
            nonce: [salt.wrapping_add(1) as u8; 32],
            solution: Vec::new(),
        }
        .freeze()
        .expect("test header freezes");
        let hash = header.hash();
        let mut encoded = Vec::new();
        header.write(&mut encoded).expect("header serializes");
        encoded.push(1);
        transaction
            .write(&mut encoded)
            .expect("transaction serializes");
        let parsed = Block::read(&encoded[..], &MAIN_NETWORK).expect("test block parses");
        assert_eq!(parsed.claimed_height(), height);
        assert_eq!(parsed.header().prev_block, previous_hash);
        (encoded, hash)
    }

    fn metadata_identity(
        metadata: &BlockMetadata,
    ) -> (
        BlockHeight,
        BlockHash,
        Option<u32>,
        Option<u32>,
        Option<u32>,
    ) {
        (
            metadata.block_height(),
            metadata.block_hash(),
            metadata.sapling_tree_size(),
            metadata.orchard_tree_size(),
            metadata.ironwood_tree_size(),
        )
    }

    fn assert_canonical_equivalent(
        left: &mut TestCanonicalState,
        right: &mut TestCanonicalState,
    ) {
        assert_eq!(
            metadata_identity(&left.cursor),
            metadata_identity(&right.cursor)
        );
        assert_eq!(
            left.history
                .values()
                .map(metadata_identity)
                .collect::<Vec<_>>(),
            right
                .history
                .values()
                .map(metadata_identity)
                .collect::<Vec<_>>()
        );
        for account in [TREASURY_ACCOUNT, REGISTRY_ACCOUNT] {
            assert_eq!(left.wallet.balance(account), right.wallet.balance(account));
            assert_eq!(
                left.wallet.orchard_notes_for(account).count(),
                right.wallet.orchard_notes_for(account).count()
            );
            assert_eq!(
                left.wallet.sapling_notes_for(account).count(),
                right.wallet.sapling_notes_for(account).count()
            );
            assert_eq!(
                left.wallet.ironwood_notes_for(account).count(),
                right.wallet.ironwood_notes_for(account).count()
            );
        }
        assert_eq!(
            left.registry.name_chain().count(),
            right.registry.name_chain().count()
        );
        let height = left.cursor.block_height();
        assert_eq!(
            left.wallet.orchard_anchor(height).unwrap(),
            right.wallet.orchard_anchor(height).unwrap()
        );
        assert_eq!(
            left.wallet.ironwood_anchor(height).unwrap(),
            right.wallet.ironwood_anchor(height).unwrap()
        );
    }

    #[test]
    fn accepted_metadata_matches_tree_checkpoint_horizon() {
        let mut history = BTreeMap::new();
        for height in 0..RETAINED_CHECKPOINTS {
            let height = u32::try_from(height).unwrap();
            record_accepted_metadata(
                &mut history,
                BlockMetadata::from_parts(
                    BlockHeight::from_u32(height),
                    BlockHash([height as u8; 32]),
                    Some(0),
                    Some(0),
                    Some(0),
                ),
            );
        }

        assert_eq!(history.len(), RETAINED_CHECKPOINTS);
        assert_eq!(
            history.first_key_value().map(|(height, _)| *height),
            Some(BlockHeight::from_u32(0))
        );
        assert_eq!(
            history.last_key_value().map(|(height, _)| *height),
            Some(BlockHeight::from_u32(
                u32::try_from(RETAINED_CHECKPOINTS - 1).unwrap()
            ))
        );

        record_accepted_metadata(
            &mut history,
            BlockMetadata::from_parts(
                BlockHeight::from_u32(u32::try_from(RETAINED_CHECKPOINTS).unwrap()),
                BlockHash([0xff; 32]),
                Some(0),
                Some(0),
                Some(0),
            ),
        );
        assert_eq!(history.len(), RETAINED_CHECKPOINTS);
        assert_eq!(
            history.first_key_value().map(|(height, _)| *height),
            Some(BlockHeight::from_u32(1))
        );
    }

    #[tokio::test]
    async fn exact_target_and_supported_reorg_schedules_converge() {
        let origin = test_origin();
        let first = TestChain::from_origin(&origin, &[1, 2, 3, 4]);
        let same_height_replacement = TestChain::from_origin(&origin, &[11, 12, 13, 14]);
        let shorter_replacement = TestChain::from_origin(&origin, &[21, 22]);
        let multi_block_replacement = TestChain::from_origin(&origin, &[31, 32, 33, 34, 35]);

        for replacement in [
            same_height_replacement,
            shorter_replacement,
            multi_block_replacement,
        ] {
            let mut scheduled = TestCanonicalState::new(&origin);
            scheduled
                .catch_up(&ScriptedBlockSource::stable(first.clone()))
                .await;
            scheduled
                .catch_up(&ScriptedBlockSource::stable(replacement.clone()))
                .await;

            let mut rebuilt = TestCanonicalState::new(&origin);
            rebuilt
                .catch_up(&ScriptedBlockSource::stable(replacement))
                .await;
            assert_canonical_equivalent(&mut scheduled, &mut rebuilt);
        }
    }

    #[tokio::test]
    async fn moving_target_discards_successful_stale_reads() {
        let origin = test_origin();
        let stale = TestChain::from_origin(&origin, &[1, 2, 3]);
        let selected = TestChain::from_origin(&origin, &[11, 12]);
        let moving =
            ScriptedBlockSource::moving(vec![stale, selected.clone()], [0, 1]);

        let mut raced = TestCanonicalState::new(&origin);
        raced.catch_up(&moving).await;

        let mut rebuilt = TestCanonicalState::new(&origin);
        rebuilt
            .catch_up(&ScriptedBlockSource::stable(selected))
            .await;
        assert_canonical_equivalent(&mut raced, &mut rebuilt);
    }

    #[tokio::test]
    async fn moving_target_after_partial_fold_converges() {
        let origin = test_origin();
        let stale = TestChain::from_origin(&origin, &[1, 2, 3]);
        let selected = TestChain::from_origin(&origin, &[11, 12]);
        let moving = ScriptedBlockSource::moving(
            vec![stale, selected.clone()],
            [0, 0, 0, 0, 1],
        );

        let mut raced = TestCanonicalState::new(&origin);
        raced.catch_up(&moving).await;

        let mut rebuilt = TestCanonicalState::new(&origin);
        rebuilt
            .catch_up(&ScriptedBlockSource::stable(selected))
            .await;
        assert_canonical_equivalent(&mut raced, &mut rebuilt);
    }

    #[tokio::test]
    async fn moving_target_during_each_ancestor_read_converges() {
        let origin = test_origin();
        let installed = TestChain::from_origin(&origin, &[1, 2, 3, 4]);
        let stale = TestChain::from_origin(&origin, &[11, 12, 13, 14]);
        let selected = TestChain::from_origin(&origin, &[21, 22, 23]);

        for tip_script in [vec![0, 0, 1], vec![0, 0, 0, 1]] {
            let mut raced = TestCanonicalState::new(&origin);
            raced
                .catch_up(&ScriptedBlockSource::stable(installed.clone()))
                .await;
            raced
                .catch_up(&ScriptedBlockSource::moving(
                    vec![stale.clone(), selected.clone()],
                    tip_script,
                ))
                .await;

            let mut rebuilt = TestCanonicalState::new(&origin);
            rebuilt
                .catch_up(&ScriptedBlockSource::stable(selected.clone()))
                .await;
            assert_canonical_equivalent(&mut raced, &mut rebuilt);
        }
    }

    #[tokio::test]
    async fn moving_target_discards_apparent_beyond_history_failure() {
        let selected_origin = test_origin();
        let alternate_height = selected_origin.height;
        let (alternate_block, alternate_hash) =
            test_block(alternate_height, BlockHash([0; 32]), 99);
        let alternate_origin = TestOrigin {
            height: alternate_height,
            hash: alternate_hash,
            block: alternate_block,
        };
        let stale = TestChain::from_origin(&alternate_origin, &[]);
        let selected = TestChain::from_origin(&selected_origin, &[]);
        let moving =
            ScriptedBlockSource::moving(vec![stale, selected.clone()], [0, 0, 1]);

        let mut raced = TestCanonicalState::new(&selected_origin);
        raced.catch_up(&moving).await;

        let mut rebuilt = TestCanonicalState::new(&selected_origin);
        rebuilt
            .catch_up(&ScriptedBlockSource::stable(selected))
            .await;
        assert_canonical_equivalent(&mut raced, &mut rebuilt);
    }

    #[tokio::test]
    async fn canonical_reader_rejects_wrong_claimed_height() {
        let origin = test_origin();
        let mut chain = TestChain::from_origin(&origin, &[1]);
        let requested = origin.height + 1;
        chain.blocks.insert(requested, origin.block.clone());
        let target = chain.tip;

        assert!(matches!(
            get_block_while_target_is_current(
                &ScriptedBlockSource::stable(chain),
                requested,
                target,
            )
            .await,
            Err(RuntimeError::Transport(TransportError::BadNodeData(_)))
        ));
    }

    #[tokio::test]
    async fn common_ancestor_rejects_history_gaps() {
        let origin = test_origin();
        let canonical = TestChain::from_origin(&origin, &[1, 2]);
        let start_height = origin.height + 2;
        let mut history = BTreeMap::from([
            (
                origin.height,
                BlockMetadata::from_parts(
                    origin.height,
                    origin.hash,
                    Some(0),
                    Some(0),
                    Some(0),
                ),
            ),
            (
                start_height,
                BlockMetadata::from_parts(
                    start_height,
                    BlockHash([0xff; 32]),
                    Some(0),
                    Some(0),
                    Some(0),
                ),
            ),
        ]);
        assert!(matches!(
            find_common_ancestor_while_target_is_current(
                &ScriptedBlockSource::stable(canonical.clone()),
                &history,
                start_height,
                canonical.tip,
            )
            .await,
            Err(RuntimeError::ReorgBeyondHistory)
        ));

        history.insert(
            origin.height + 1,
            BlockMetadata::from_parts(
                origin.height + 1,
                BlockHash([0xfe; 32]),
                Some(0),
                Some(0),
                Some(0),
            ),
        );
        assert_eq!(
            find_common_ancestor_while_target_is_current(
                &ScriptedBlockSource::stable(canonical.clone()),
                &history,
                start_height,
                canonical.tip,
            )
            .await
            .expect("contiguous history reaches origin")
            .expect("stable target returns an ancestor")
            .block_height(),
            origin.height
        );
    }

    #[tokio::test]
    async fn restart_and_reorg_schedule_property() {
        let origin = test_origin();
        let branches = [
            TestChain::from_origin(&origin, &[1, 2, 3, 4]),
            TestChain::from_origin(&origin, &[11, 12]),
            TestChain::from_origin(&origin, &[21, 22, 23, 24, 25]),
        ];
        let final_chain = branches.last().expect("non-empty schedule").clone();
        let mut baseline = TestCanonicalState::new(&origin);
        baseline
            .catch_up(&ScriptedBlockSource::stable(final_chain.clone()))
            .await;

        for restart_mask in 0u8..8 {
            let mut scheduled = TestCanonicalState::new(&origin);
            for (index, branch) in branches.iter().enumerate() {
                scheduled
                    .catch_up(&ScriptedBlockSource::stable(branch.clone()))
                    .await;
                if restart_mask & (1 << index) != 0 {
                    scheduled = TestCanonicalState::new(&origin);
                    scheduled
                        .catch_up(&ScriptedBlockSource::stable(branch.clone()))
                        .await;
                }
            }
            assert_canonical_equivalent(&mut scheduled, &mut baseline);
        }

        for split in 0..=u32::from(final_chain.tip.height() - origin.height) {
            let prefix_height = origin.height + split;
            let mut interrupted = TestCanonicalState::new(&origin);
            interrupted
                .catch_up(&ScriptedBlockSource::stable(
                    final_chain.prefix(prefix_height),
                ))
                .await;
            drop(interrupted);

            let mut restarted = TestCanonicalState::new(&origin);
            restarted
                .catch_up(&ScriptedBlockSource::stable(final_chain.clone()))
                .await;
            assert_canonical_equivalent(&mut restarted, &mut baseline);
        }
    }

    #[tokio::test]
    async fn every_commit_boundary_recovers_by_rebuild() {
        let origin = test_origin();
        let chain = TestChain::from_origin(&origin, &[1]);
        let next_height = origin.height + 1;
        let boundaries = [
            CommitBoundary::Before(CanonicalCommitStage::Scan),
            CommitBoundary::After(CanonicalCommitStage::Scan),
            CommitBoundary::Before(CanonicalCommitStage::RegistrySimulation),
            CommitBoundary::After(CanonicalCommitStage::RegistrySimulation),
            CommitBoundary::Before(CanonicalCommitStage::Wallet),
            CommitBoundary::After(CanonicalCommitStage::Wallet),
            CommitBoundary::Before(CanonicalCommitStage::Registry),
            CommitBoundary::After(CanonicalCommitStage::Registry),
            CommitBoundary::Before(CanonicalCommitStage::History),
            CommitBoundary::After(CanonicalCommitStage::History),
            CommitBoundary::Before(CanonicalCommitStage::Cursor),
            CommitBoundary::After(CanonicalCommitStage::Cursor),
        ];
        let mut baseline = TestCanonicalState::new(&origin);
        baseline
            .catch_up(&ScriptedBlockSource::stable(chain.clone()))
            .await;

        for injected in boundaries {
            let mut crashed = TestCanonicalState::new(&origin);
            let ufvks: HashMap<_, _> = crashed
                .wallet
                .ufvk_map()
                .iter()
                .map(|(account, ufvk)| (*account, ufvk.clone()))
                .collect();
            let scanning_keys = ScanningKeys::from_account_ufvks(ufvks.clone());
            let block = Block::read(
                &chain.blocks.get(&next_height).expect("successor exists")[..],
                &MAIN_NETWORK,
            )
            .expect("successor parses");
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = apply_canonical_block_with_fault(
                    block,
                    &mut crashed.wallet,
                    &mut crashed.registry,
                    &mut crashed.cursor,
                    &mut crashed.history,
                    &ufvks,
                    &scanning_keys,
                    |boundary| {
                        assert_ne!(boundary, injected, "injected canonical crash");
                    },
                );
            }));
            assert!(result.is_err(), "fault boundary was not reached: {injected:?}");

            let stage_rank = |stage| match stage {
                CanonicalCommitStage::Scan => 0,
                CanonicalCommitStage::RegistrySimulation => 1,
                CanonicalCommitStage::Wallet => 2,
                CanonicalCommitStage::Registry => 3,
                CanonicalCommitStage::History => 4,
                CanonicalCommitStage::Cursor => 5,
            };
            let committed_through = |stage| match injected {
                CommitBoundary::Before(injected_stage) => {
                    stage_rank(injected_stage) > stage_rank(stage)
                }
                CommitBoundary::After(injected_stage) => {
                    stage_rank(injected_stage) >= stage_rank(stage)
                }
            };

            assert_eq!(
                crashed.cursor.block_height() == next_height,
                committed_through(CanonicalCommitStage::Cursor)
            );
            assert_eq!(
                crashed.history.contains_key(&next_height),
                committed_through(CanonicalCommitStage::History)
            );
            assert_eq!(
                crashed
                    .wallet
                    .orchard_anchor(next_height)
                    .unwrap()
                    .is_some(),
                committed_through(CanonicalCommitStage::Wallet)
            );
            assert_eq!(
                crashed
                    .wallet
                    .ironwood_anchor(next_height)
                    .unwrap()
                    .is_some(),
                committed_through(CanonicalCommitStage::Wallet)
            );
            drop(crashed);

            let mut restarted = TestCanonicalState::new(&origin);
            restarted
                .catch_up(&ScriptedBlockSource::stable(chain.clone()))
                .await;
            assert_canonical_equivalent(&mut restarted, &mut baseline);
        }
    }
}
