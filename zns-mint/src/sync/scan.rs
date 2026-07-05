//! Block scanning logic.

use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_client_backend::scanning::{ScanningKeys, Nullifiers, full::{decrypt_block, scan_block}};
use std::convert::Infallible;

use crate::registry::Registry;
use crate::wallet::Wallet;
use crate::sync::reorg::ReorgBuffer;
use crate::wallet::transaction::{TransactionRecord, ReceivedOrchardNote, SpentOrchardNote, SpentSaplingNote};

/// Bootstraps the scanner state from the Zebra JSON-RPC.
pub async fn bootstrap(wallet: &mut Wallet) -> ReorgBuffer {
    tracing::info!("scanner: bootstrapping state from Birthday Checkpoint");
    let birthday_height = BlockHeight::from_u32(2_999_999);
    let json_rpc = crate::zcash::zebra::JsonRpc::new();
    
    let checkpoint = json_rpc.get_checkpoint(birthday_height).await.expect("failed to get birthday checkpoint from RPC");
    
    wallet.trees.insert_sapling_frontier(
        checkpoint.sapling_tree.to_frontier(),
        birthday_height,
    );
    wallet.trees.insert_orchard_frontier(
        checkpoint.orchard_tree.to_frontier(),
        birthday_height,
    );
    
    ReorgBuffer::new(crate::sync::reorg::BlockCursor {
        height: birthday_height,
        hash: checkpoint.metadata.block_hash(),
    })
}

/// Scans a single verified block and updates the wallet state.
pub fn scan_verified_block<P: Parameters + Send + 'static>(
    params: &P,
    wallet: &mut Wallet,
    registry: &mut Registry,
    block: zcash_primitives::block::Block,
    height: BlockHeight,
) {
    let treasury_fvk = wallet
        .ufvk_for(crate::mint::TREASURY_ACCOUNT)
        .expect("missing treasury UFVK in wallet");
    let registry_fvk = wallet
        .ufvk_for(crate::mint::REGISTRY_ACCOUNT)
        .expect("missing registry UFVK in wallet");

    let scanning_keys = ScanningKeys::from_account_ufvks([
        (crate::mint::TREASURY_ACCOUNT, treasury_fvk.clone()),
        (crate::mint::REGISTRY_ACCOUNT, registry_fvk.clone()),
    ]);

    let nullifiers = Nullifiers::empty();

    // 1. Extract memos before consuming the block.
    // scan_block strips memos, so we grab them up front.
    let treasury_ivk = treasury_fvk.orchard().unwrap().to_ivk(orchard::keys::Scope::External);
    let registry_ivk = registry_fvk.orchard().unwrap().to_ivk(orchard::keys::Scope::External);
    let ivks = [treasury_ivk.clone(), registry_ivk.clone()];

    let mut orchard_memos = std::collections::HashMap::new();
    for tx in block.vtx() {
        if let Some(bundle) = tx.orchard_bundle() {
            let decrypted = bundle.decrypt_outputs_with_keys(&ivks);
            for (idx, _, _, _, memo) in decrypted {
                orchard_memos.insert((tx.txid(), idx), memo);
            }
        }
    }
    
    // 2. Trial decrypt using librustzcash
    let prior_block_metadata = zcash_client_backend::data_api::BlockMetadata::from_parts(
        height - 1,
        block.header().prev_block,
        wallet.trees.sapling_tree_size(),
        wallet.trees.orchard_tree_size(),
    );

    let (header, batch_results) = decrypt_block(params, block, &scanning_keys);
    let scanned_block = scan_block(
        params,
        height,
        &header,
        batch_results,
        &scanning_keys,
        &nullifiers,
        Some(&prior_block_metadata),
        |_| Ok::<_, Infallible>(None),
    ).expect("scan_block failed");

    // 3. Process the results into our TransactionRecords
    for tx in scanned_block.transactions() {
        let mut record = TransactionRecord {
            txid: *tx.txid().as_ref(),
            block_height: height,
            received_orchard: vec![],
            received_sapling: vec![],
            spent_orchard: vec![],
            spent_sapling: vec![],
        };

        for spend in tx.orchard_spends() {
            let nf = spend.nf().to_bytes();
            let original_note = wallet.ledger.get_orchard_note_by_nf(&nf).expect("spent note not found").clone();
            record.spent_orchard.push(SpentOrchardNote {
                account_id: *spend.account_id(),
                nullifier: nf,
                original_note,
            });
        }
        for spend in tx.sapling_spends() {
            let nf = spend.nf().0;
            let original_note = wallet.ledger.get_sapling_note_by_nf(&nf).expect("spent note not found").clone();
            record.spent_sapling.push(SpentSaplingNote {
                account_id: *spend.account_id(),
                nullifier: nf,
                original_note,
            });
        }

        // Extract Received Orchard
        for output in tx.orchard_outputs() {
            if let Some(memo) = orchard_memos.get(&(tx.txid(), output.index())) {
                let mut memo_bytes = [0u8; 512];
                memo_bytes.copy_from_slice(memo);
                
                let account_id = *output.account_id();
                record.received_orchard.push(ReceivedOrchardNote {
                    account_id,
                    note: output.note().clone(),
                    memo: memo_bytes,
                    position: output.note_commitment_tree_position(),
                    confirmed_height: height,
                });

                // If this is a Registry Name Note, parse the memo and update the
                // name-chain tip. The scanner does not own name state — it hands
                // the parsed tip to `Registry`, which owns the name chain.
                if account_id == zip32::AccountId::const_from_u32(1) { // REGISTRY_ACCOUNT
                    if let Some((name, action, ua, prev_rcm)) =
                        crate::mint::decode_name_note(&memo_bytes)
                    {
                        let (rcm, psi) = crate::mint::zns_psi_rcm(&name, action, &ua, prev_rcm);
                        use pasta_curves::group::ff::PrimeField;
                        let mut current_rcm_bytes = [0u8; 32];
                        current_rcm_bytes.copy_from_slice(rcm.to_repr().as_ref());
                        let tip = crate::registry::Tip {
                            action,
                            commitment: current_rcm_bytes,
                            rcm,
                            psi,
                        };
                        registry.set_tip(name, tip, height);
                    }
                }
            }
        }
        
        wallet.ledger.add_transaction(&record);
    }

    // 4. Update the ShardTree with all commitments
    let orchard_commitments = scanned_block.into_commitments().orchard;
    for cmx in orchard_commitments {
        wallet.trees.append_orchard(cmx.0, cmx.1);
    }
}

use zcash_primitives::block::{Block as ZcashBlock, BlockHash};
use zebra_indexer_proto::{BlockHashAndHeight, BlockRequest, Empty};

/// A best-chain block after local parse and integrity checks.
pub struct Block(pub ZcashBlock);

impl Block {
    pub fn height(&self) -> BlockHeight {
        self.0.claimed_height()
    }

    pub fn hash(&self) -> BlockHash {
        self.0.header().hash()
    }

    pub fn prev_hash(&self) -> BlockHash {
        self.0.header().prev_block
    }

    pub fn transactions(&self) -> impl Iterator<Item = &zcash_primitives::transaction::Transaction> {
        self.0.vtx().iter()
    }

    pub fn as_inner(&self) -> &ZcashBlock {
        &self.0
    }

    pub fn into_inner(self) -> ZcashBlock {
        self.0
    }
}

pub fn tip_height_hash(tip: &BlockHashAndHeight) -> (BlockHeight, BlockHash) {
    (
        BlockHeight::from_u32(tip.height),
        block_hash_from_display(&tip.hash)
            .expect("chain_tip_change returned a malformed 32-byte hash"),
    )
}

pub fn block_hash_from_display(display: &[u8]) -> Option<BlockHash> {
    let mut bytes: [u8; 32] = BlockHash::try_from_slice(display)?.0;
    bytes.reverse();
    Some(BlockHash(bytes))
}

pub async fn fetch_verified_block(client: &mut crate::zcash::zebra::ChainClient, height: BlockHeight) -> Block {
    let block_req = BlockRequest {
        hash_or_height: u32::from(height).to_be_bytes().to_vec(),
    };
    let block_resp = client
        .client()
        .get_block(block_req)
        .await
        .expect("get_block request failed");
    let block_and_hash = block_resp.into_inner();

    let parsed = ZcashBlock::read(&block_and_hash.data[..], &zcash_protocol::consensus::MAIN_NETWORK)
        .expect("get_block returned bytes that do not parse as a mainnet block");

    let getblock_hash = block_hash_from_display(&block_and_hash.hash)
        .expect("get_block returned a malformed 32-byte hash");
    assert_eq!(
        parsed.header().hash(),
        getblock_hash,
        "recomputed header hash != get_block hash"
    );
    assert_eq!(
        parsed.claimed_height(),
        height,
        "parsed block height != requested height"
    );

    Block(parsed)
}

pub async fn scan_to_tip(
    chain: &mut crate::zcash::zebra::ChainClient,
    wallet: &mut Wallet,
    registry: &mut Registry,
    reorg_buffer: &mut ReorgBuffer,
    _tip_height: BlockHeight,
) {
    let mut tip_stream = chain.client().chain_tip_change(Empty {}).await.expect("failed to open tip stream").into_inner();

    while let Some(zebra_tip) = tip_stream.message().await.expect("tip stream error") {
        let (tip_height, _tip_hash) = tip_height_hash(&zebra_tip);
        let mut next_height = reorg_buffer.blocks.back().expect("buffer empty").height + 1;

        while u32::from(next_height) <= u32::from(tip_height) {
            if u32::from(next_height) % 1_000 == 0 {
                tracing::info!("scanner: syncing... currently at block {} / {}", u32::from(next_height), u32::from(tip_height));
            }

            let block = fetch_verified_block(chain, next_height).await;
            let block_hash = block.hash();

            if block.prev_hash() == reorg_buffer.blocks.back().unwrap().hash {
                // Happy path append
                scan_verified_block(
                    &zcash_protocol::consensus::MAIN_NETWORK,
                    wallet,
                    registry,
                    block.into_inner(),
                    next_height,
                );
                
                reorg_buffer.push(crate::sync::reorg::BlockCursor {
                    height: next_height,
                    hash: block_hash,
                });
                
                next_height = next_height + 1;
            } else {
                tracing::warn!(
                    "Reorg detected at height {}. Finding common ancestor...",
                    next_height
                );

                let mut common_ancestor_height = None;

                // Walk backward through our memory buffer to find where the chain split
                for cursor in reorg_buffer.blocks.iter().rev() {
                    let remote_block = fetch_verified_block(chain, cursor.height).await;
                    if remote_block.hash() == cursor.hash {
                        common_ancestor_height = Some(cursor.height);
                        break;
                    }
                }

                let ancestor_height = common_ancestor_height
                    .expect("Reorg depth exceeded 100 blocks; fatal consensus failure");

                tracing::info!(
                    "Found common ancestor at height {}. Rewinding state.",
                    ancestor_height
                );

                // Rewind all memory state to the common ancestor
                wallet.trees.truncate_to_checkpoint(ancestor_height);
                wallet.ledger.truncate_to_height(ancestor_height);
                registry.truncate_to_height(ancestor_height);

                // Drop orphaned blocks from our reorg buffer
                while let Some(cursor) = reorg_buffer.blocks.back() {
                    if cursor.height <= ancestor_height {
                        break;
                    }
                    reorg_buffer.blocks.pop_back();
                }

                // Reset the scanner to resume from the block immediately following the ancestor
                next_height = ancestor_height + 1;
            }
        }
        // Sync complete up to tip_height
    }
}