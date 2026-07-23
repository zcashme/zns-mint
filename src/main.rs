use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::scanning::ScanningKeys;
use zcash_primitives::block::Block;
use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};

use zns_mint::boot::Boot;
use zns_mint::metrics;
use zns_mint::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zns_mint::registry::state::Registry;
use zns_mint::registry::{classify_registry_ironwood_note, RegistryNoteClass};
use zns_mint::sync::scan_block;
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{CanonicalBlockSource, ChainClient, TransportError};

/// Polling interval when waiting for the next best-chain block.
const BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(5);

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
    let (mut chain, mut wallet, mut registry, _, _, _) = boot.into_parts();
    let block_source = CanonicalBlockSource::new();
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

        match catch_up(
            &block_source,
            &mut wallet,
            &mut registry,
            &mut cursor,
            &mut chain_history,
        )
        .await
        {
            Ok(()) => {}
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

/// Fetches and passively folds every block from `cursor + 1` to the current tip.
///
/// This path performs no request, OTP, policy, signing, proving, or submission
/// operation. Decrypted observations remain in canonical wallet history for a
/// later Live phase to interpret after an exact rebuild boundary is established.
async fn catch_up(
    block_source: &CanonicalBlockSource,
    wallet: &mut Wallet,
    registry: &mut Registry,
    cursor: &mut BlockMetadata,
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
) -> Result<(), RuntimeError> {
    let ufvks: HashMap<zip32::AccountId, zcash_keys::keys::UnifiedFullViewingKey> = wallet
        .ufvk_map()
        .iter()
        .map(|(account_id, ufvk)| (*account_id, ufvk.clone()))
        .collect();
    let scanning_keys = ScanningKeys::from_account_ufvks(ufvks.clone());

    loop {
        let info = block_source.get_blockchain_info().await?;
        let tip = BlockHeight::from_u32(info.blocks);

        if tip <= cursor.block_height() {
            publish_canonical_gauges(wallet, cursor.block_height());
            return Ok(());
        }

        let next_height = cursor.block_height() + 1;
        let block = block_source.get_block(next_height).await?;

        if block.header().prev_block != cursor.block_hash() {
            tracing::warn!(
                height = u32::from(next_height),
                expected = %cursor.block_hash(),
                actual = %block.header().prev_block,
                "reorg detected: block prev_hash does not match cursor"
            );

            let common_ancestor = find_common_ancestor(block_source, chain_history, cursor).await?;
            rewind_canonical_state(wallet, registry, cursor, chain_history, &common_ancestor);
            continue;
        }

        let committed_height = apply_canonical_block(
            block,
            wallet,
            registry,
            cursor,
            chain_history,
            &ufvks,
            &scanning_keys,
        )?;

        publish_canonical_gauges(wallet, committed_height);
    }
}

/// Finds the exact common ancestor by comparing accepted and Zebra block hashes.
async fn find_common_ancestor(
    block_source: &CanonicalBlockSource,
    chain_history: &BTreeMap<BlockHeight, BlockMetadata>,
    cursor: &BlockMetadata,
) -> Result<BlockMetadata, RuntimeError> {
    let mut height = cursor.block_height();
    loop {
        let local = chain_history
            .get(&height)
            .ok_or(RuntimeError::ReorgBeyondHistory)?;
        let canonical = block_source.get_block(height).await?;
        if canonical.header().hash() == local.block_hash() {
            return Ok(*local);
        }
        if height == BlockHeight::from_u32(0) {
            return Err(RuntimeError::ReorgBeyondHistory);
        }
        height = BlockHeight::from_u32(u32::from(height) - 1);
    }
}

/// Rewinds every canonical subsystem to one exact accepted ancestor.
fn rewind_canonical_state(
    wallet: &mut Wallet,
    registry: &mut Registry,
    cursor: &mut BlockMetadata,
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
    common_ancestor: &BlockMetadata,
) {
    let ancestor_height = common_ancestor.block_height();

    wallet.balance_mut().truncate_to_height(ancestor_height);
    wallet
        .trees_mut()
        .truncate_to_checkpoint(ancestor_height)
        .expect("FATAL: failed to truncate commitment trees");
    registry.truncate_to_height(ancestor_height);
    chain_history.retain(|height, _| *height <= ancestor_height);
    *cursor = *common_ancestor;
    publish_canonical_gauges(wallet, ancestor_height);

    tracing::info!(
        height = u32::from(ancestor_height),
        "rewound canonical state to common ancestor"
    );
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

/// Scans and commits one continuous canonical block.
///
/// Cursor and accepted history advance only after Registry simulation and
/// Wallet application both succeed. The accepted height comes solely from the
/// scanner output; callers cannot supply duplicate height state.
fn apply_canonical_block(
    block: Block,
    wallet: &mut Wallet,
    registry: &mut Registry,
    cursor: &mut BlockMetadata,
    chain_history: &mut BTreeMap<BlockHeight, BlockMetadata>,
    ufvks: &HashMap<zip32::AccountId, zcash_keys::keys::UnifiedFullViewingKey>,
    scanning_keys: &ScanningKeys<zip32::AccountId, (zip32::AccountId, zip32::Scope)>,
) -> Result<BlockHeight, RuntimeError> {
    let output = scan_block(&MAIN_NETWORK, Some(cursor), block, ufvks, scanning_keys)?;
    let next_registry = registry.apply_block(wallet, &output)?;

    wallet.apply_block(&output, cursor.block_height())?;
    *registry = next_registry;

    let committed = *output.metadata();
    let committed_height = committed.block_height();
    *cursor = committed;
    chain_history.insert(committed_height, committed);

    Ok(committed_height)
}
