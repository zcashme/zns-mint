//! Block scanning: turn a verified Zcash block + a set of viewing keys into a
//! `BlockOutput` describing the wallet-relevant subset and the full commitment
//! stream for tree integrity.
//!
//! Sync is a pure library: `Block` + UFVKs in, `BlockOutput` out. It touches
//! no wallet state, decodes no ZNS payload, owns no loop, detects no reorg.
//! The orchestrator (`main.rs`) owns catch-up, reorg detection, and the
//! fan-out to `wallet`/`registry`/`treasury`.
//!
//! Memo capture: upstream `decrypt_block`/`scan_block` drop the memo in their
//! output types (`WalletOutput` has no memo field), and `BatchResult` that
//! carries it is opaque. The public memo path is
//! `zcash_client_backend::decrypt_transaction` (`decrypt.rs:123`): takes UFVKs
//! directly, returns `DecryptedTransaction` with `DecryptedOutput`s carrying
//! `MemoBytes` in-band. So we call `decrypt_transaction` per tx for
//! notes + memos + accounts, and `scan_block` (upstream) for positions,
//! spends, and the full commitment stream. UFVK → memo in one call.

use std::convert::Infallible;
use std::collections::HashMap;

use incrementalmerkletree::Retention;
use zcash_client_backend::{
    data_api::BlockMetadata,
    decrypt_transaction,
    scanning::{full::{decrypt_block, scan_block as upstream_scan_block}, Nullifiers, ScanningKeys},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::Block as ZcashBlock;
use zcash_primitives::transaction::Transaction;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes as UpstreamMemoBytes;
use zip32::AccountId;

use crate::mint::Memo;

/// The result of scanning a single block.
///
/// Two concerns, both necessary:
/// - `transactions`: the *decrypted subset* — only txs where at least one
///   output decrypted to one of our accounts or one of our nullifiers was
///   spent. Most blocks yield an empty vec.
/// - `orchard_commitments` / `sapling_commitments`: the *full ordered
///   commitment stream* for the block — every action's `cmx` and every
///   output's `cmu`, wallet-relevant or not. The wallet's `ShardTree` must
///   append all of them to stay in sync with the chain's tree; skipping
///   non-wallet actions would break every Merkle witness we compute.
pub struct BlockOutput {
    pub height: BlockHeight,
    pub transactions: Vec<TxOutput>,
    pub orchard_commitments: Vec<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>,
    pub sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
}

/// A transaction in the block that is wallet-relevant.
///
/// Groups received notes (with memo + position) and spent nullifiers (without
/// original note — the wallet resolves NF → original note via its own nullifier
/// index during `apply`). One `TxOutput` = one `TxId` = one transaction.
pub struct TxOutput {
    pub txid: TxId,
    pub received_orchard: Vec<ReceivedOrchard>,
    pub received_sapling: Vec<ReceivedSapling>,
    pub spent_orchard: Vec<SpentOrchard>,
    pub spent_sapling: Vec<SpentSapling>,
}

/// An Orchard note we received, with its decrypted memo and tree position.
pub struct ReceivedOrchard {
    pub account_id: AccountId,
    pub note: orchard::note::Note,
    pub memo: Memo,
    pub position: incrementalmerkletree::Position,
}

/// A Sapling note we received, with its decrypted memo and tree position.
pub struct ReceivedSapling {
    pub account_id: AccountId,
    pub note: sapling::Note,
    pub memo: Memo,
    pub position: incrementalmerkletree::Position,
}

/// An Orchard nullifier we recognize — the wallet resolves this to the
/// original note via its nullifier index during `apply`.
pub struct SpentOrchard {
    pub account_id: AccountId,
    pub nullifier: orchard::note::Nullifier,
}

/// A Sapling nullifier we recognize.
pub struct SpentSapling {
    pub account_id: AccountId,
    pub nullifier: sapling::Nullifier,
}

/// Scans one verified block and returns the wallet-relevant subset plus the
/// full commitment stream for tree integrity.
///
/// Pure: no `&Wallet`, no `&Registry`, no ZNS decode, no tree appends, no I/O.
/// The caller owns the loop, reorg detection, and the fan-out to wallet /
/// registry / treasury.
///
/// `ufvks` is the set of `(AccountId, UnifiedFullViewingKey)` pairs the wallet
/// holds; the caller builds it once at boot and passes `&` to each call.
/// `scanning_keys` is the upstream `ScanningKeys` built from the same UFVKs —
/// `scan_block` requires it for batch decryption. `nullifiers` is the wallet's
/// tracked nullifier set for spend detection.
///
/// `prior_metadata` is the `BlockMetadata` of the previous block (or `None`
/// for the birthday block). Required by upstream `scan_block` for inter-block
/// tree-size continuity checks.
pub fn scan_block<P>(
    params: &P,
    prior_metadata: Option<&BlockMetadata>,
    block: ZcashBlock,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    scanning_keys: &ScanningKeys<AccountId, (AccountId, zip32::Scope)>,
    nullifiers: &Nullifiers<AccountId>,
) -> BlockOutput
where
    P: Parameters + Send + 'static,
{
    let height = block.claimed_height();

    // 1. Decrypt memos + notes per tx via the public memo path. We borrow
    //    `vtx` here; the block moves into `decrypt_block` next. Keyed by
    //    `(txid, output_idx)` → `Memo` so the join in step 3 is a lookup.
    let memos = decrypt_block_memos(params, block.vtx(), ufvks, height);

    // 2. Upstream decrypt + scan for positions, spends, and the full
    //    commitment stream.
    let (header, batch_results) = decrypt_block(params, block, scanning_keys);
    let scanned = upstream_scan_block(
        params,
        height,
        &header,
        batch_results,
        scanning_keys,
        nullifiers,
        prior_metadata,
    // The published Treasury UA omits a transparent receiver (shielded-only,
    // see docs/protocol/02-accounts-and-keys.md), so no transparent output
    // is ever attributed to a wallet account. The closure permanently
    // returns `Ok(None)`; this is not a stub awaiting wiring.
    |_| Ok::<Option<(AccountId, Option<transparent::keys::TransparentKeyScope>)>, Infallible>(None),
    )
    .expect("scan_block failed on a verified block");

    // 3. Walk the scanned transactions, join memos back, build TxOutputs.
    let mut transactions = Vec::new();
    for wtx in scanned.transactions() {
        let txid = wtx.txid();

        let mut received_orchard = Vec::new();
        for out in wtx.orchard_outputs() {
            if let Some(memo) = memos.get(&(txid, out.index())) {
                received_orchard.push(ReceivedOrchard {
                    account_id: *out.account_id(),
                    note: out.note().clone(),
                    memo: memo.clone(),
                    position: out.note_commitment_tree_position(),
                });
            }
        }

        let mut received_sapling = Vec::new();
        for out in wtx.sapling_outputs() {
            if let Some(memo) = memos.get(&(txid, out.index())) {
                received_sapling.push(ReceivedSapling {
                    account_id: *out.account_id(),
                    note: out.note().clone(),
                    memo: memo.clone(),
                    position: out.note_commitment_tree_position(),
                });
            }
        }

        let spent_orchard = wtx
            .orchard_spends()
            .iter()
            .map(|s| SpentOrchard {
                account_id: *s.account_id(),
                nullifier: *s.nf(),
            })
            .collect();

        let spent_sapling = wtx
            .sapling_spends()
            .iter()
            .map(|s| SpentSapling {
                account_id: *s.account_id(),
                nullifier: *s.nf(),
            })
            .collect();

        transactions.push(TxOutput {
            txid,
            received_orchard,
            received_sapling,
            spent_orchard,
            spent_sapling,
        });
    }

    // 4. Block-level commitments: every action's cmx / every output's cmu, in
    //    order, for ShardTree integrity.
    let commitments = scanned.into_commitments();
    let orchard_commitments = commitments.orchard;
    let sapling_commitments = commitments.sapling;

    BlockOutput {
        height,
        transactions,
        orchard_commitments,
        sapling_commitments,
    }
}

/// Per-tx decryption for memos + notes via `decrypt_transaction`.
///
/// `decrypt_transaction` (`zcash_client_backend/src/decrypt.rs:123`) is the
/// only public upstream path that returns the memo alongside the note. It
/// takes the UFVKs directly (no `ScanningKeys`), handles Orchard + Sapling +
/// outgoing recovery uniformly, and yields `DecryptedOutput { index, note,
/// account, memo: MemoBytes, transfer_type }`.
///
/// We return a flat `HashMap<(TxId, output_idx), Memo>` keyed across both
/// pools; output indices from `decrypt_transaction` are per-pool, and
/// `scan_block`'s `WalletOutput::index()` is also per-pool, so the join is
/// unambiguous within a pool.
fn decrypt_block_memos<'a, P>(
    params: &P,
    vtx: impl IntoIterator<Item = &'a Transaction>,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    height: BlockHeight,
) -> HashMap<(TxId, usize), Memo>
where
    P: Parameters,
{
    let mut memos: HashMap<(TxId, usize), Memo> = HashMap::new();

    for tx in vtx {
        let decrypted = decrypt_transaction(params, Some(height), None, tx, ufvks);

        for out in decrypted.orchard_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos.insert((decrypted.tx().txid(), out.index()), memo);
            }
        }

        for out in decrypted.sapling_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos.insert((decrypted.tx().txid(), out.index()), memo);
            }
        }
    }

    memos
}

pub mod scan {
    use zcash_primitives::block::{Block, BlockHash};
    use zcash_protocol::consensus::BlockHeight;
    use zebra_indexer_proto::{BlockHashAndHeight, BlockRequest};
    use crate::zcash::ChainClient;

    pub fn tip_height_hash(tip: &BlockHashAndHeight) -> (BlockHeight, BlockHash) {
        let height = BlockHeight::from_u32(tip.height);
        let hash = block_hash_from_display(&tip.hash).expect("invalid tip hash");
        (height, hash)
    }

    pub fn block_hash_from_display(bytes: &[u8]) -> Option<BlockHash> {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr.reverse();
            Some(BlockHash(arr))
        } else {
            None
        }
    }

    pub async fn fetch_verified_block(chain: &mut ChainClient, height: BlockHeight) -> Block {
        let req = BlockRequest {
            hash_or_height: u32::from(height).to_be_bytes().to_vec(),
        };
        let response = chain.client().get_block(req).await.expect("failed to fetch block").into_inner();
        let params = zcash_protocol::consensus::MAIN_NETWORK;
        Block::read(&response.data[..], &params).expect("failed to parse block")
    }
}