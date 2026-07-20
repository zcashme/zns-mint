use std::collections::HashMap;
use std::convert::Infallible;

use incrementalmerkletree::Retention;
use zcash_client_backend::{
    data_api::BlockMetadata,
    decrypt_transaction,
    scanning::{
        full::{decrypt_block, scan_block as upstream_scan_block},
        Nullifiers, ScanningKeys,
    },
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::Block as ZcashBlock;
use zcash_primitives::transaction::Transaction;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::AccountId;

use crate::mint::Memo;

/// Per-pool memo maps from `decrypt_transaction`.
///
/// Separate maps per pool because output indices are per-bundle — Orchard
/// output 0 and Sapling output 0 in the same tx would collide in a single
/// `HashMap<(TxId, usize), Memo>`.
struct BlockMemos {
    orchard: HashMap<(TxId, usize), Memo>,
    sapling: HashMap<(TxId, usize), Memo>,
    ironwood: HashMap<(TxId, usize), Memo>,
}

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
    /// Upstream scanner continuity metadata for this fully scanned block.
    ///
    /// The mint promotes this into its [`crate::mint::ChainCursor`] only after
    /// the wallet and Registry have both accepted the block.
    pub metadata: BlockMetadata,
    pub height: BlockHeight,
    pub transactions: Vec<TxOutput>,
    pub orchard_commitments: Vec<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>,
    pub sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
    pub ironwood_commitments: Vec<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>,
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
    pub received_ironwood: Vec<ReceivedIronwood>,
    pub spent_orchard: Vec<SpentOrchard>,
    pub spent_sapling: Vec<SpentSapling>,
    pub spent_ironwood: Vec<SpentIronwood>,
}

/// An Orchard note we received, with its decrypted memo and tree position.
pub struct ReceivedOrchard {
    pub account_id: AccountId,
    pub note: orchard::note::Note,
    /// Scanner-derived from the note, its position, and the account FVK.
    /// Required to detect a later spend of this exact note.
    pub nullifier: orchard::note::Nullifier,
    pub memo: Memo,
    pub position: incrementalmerkletree::Position,
}

/// A Sapling note we received, with its decrypted memo and tree position.
pub struct ReceivedSapling {
    pub account_id: AccountId,
    pub note: sapling::Note,
    /// Scanner-derived from the note, its position, and the account FVK.
    /// Required to detect a later spend of this exact note.
    pub nullifier: sapling::Nullifier,
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

/// An Ironwood (NU6.3) note we received, with its decrypted memo and tree position.
pub struct ReceivedIronwood {
    pub account_id: AccountId,
    pub note: orchard::note::Note,
    /// Scanner-derived from the note, its position, and the account FVK.
    /// Required to detect a later spend of this exact note.
    pub nullifier: orchard::note::Nullifier,
    pub memo: Memo,
    pub position: incrementalmerkletree::Position,
}

/// An Ironwood nullifier we recognize — same type as Orchard but tracked
/// separately to avoid cross-pool collision in the nullifier index.
pub struct SpentIronwood {
    pub account_id: AccountId,
    pub nullifier: orchard::note::Nullifier,
}

/// Scans one verified block and returns the wallet-relevant subset plus the
/// full commitment stream for tree integrity.
pub fn scan_block<P>(
    params: &P,
    prior_metadata: Option<&BlockMetadata>,
    block: ZcashBlock,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    scanning_keys: &ScanningKeys<AccountId, (AccountId, zip32::Scope)>,
    nullifiers: &mut Nullifiers<AccountId>,
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
        // see docs/protocol.md §2–3), so no transparent output
        // is ever attributed to a wallet account. The closure permanently
        // returns `Ok(None)`; this is not a stub awaiting wiring.
        |_| {
            Ok::<Option<(AccountId, Option<transparent::keys::TransparentKeyScope>)>, Infallible>(
                None,
            )
        },
    )
    .expect("scan_block failed on a verified block");

    // 3. Walk the scanned transactions, join memos back, build TxOutputs.
    let mut transactions = Vec::new();
    for wtx in scanned.transactions() {
        let txid = wtx.txid();

        let mut received_orchard = Vec::new();
        for out in wtx.orchard_outputs() {
            if let Some(memo) = memos.orchard.get(&(txid, out.index())) {
                received_orchard.push(ReceivedOrchard {
                    account_id: *out.account_id(),
                    // out.note() returns &(Note, ValuePool) — clone just the Note.
                    note: out.note().0,
                    // `ScanningKeys::from_account_ufvks` always supplies an nk,
                    // so a wallet output must carry a nullifier.
                    nullifier: *out.nf().expect("wallet output missing nullifier"),
                    memo: memo.clone(),
                    position: out.note_commitment_tree_position(),
                });
            }
        }

        let mut received_sapling = Vec::new();
        for out in wtx.sapling_outputs() {
            if let Some(memo) = memos.sapling.get(&(txid, out.index())) {
                received_sapling.push(ReceivedSapling {
                    account_id: *out.account_id(),
                    note: out.note().clone(),
                    // See the Orchard equivalent above.
                    nullifier: *out.nf().expect("wallet output missing nullifier"),
                    memo: memo.clone(),
                    position: out.note_commitment_tree_position(),
                });
            }
        }

        let mut received_ironwood = Vec::new();
        for out in wtx.ironwood_outputs() {
            if let Some(memo) = memos.ironwood.get(&(txid, out.index())) {
                received_ironwood.push(ReceivedIronwood {
                    account_id: *out.account_id(),
                    note: out.note().0,
                    // See the Orchard equivalent above.
                    nullifier: *out.nf().expect("wallet output missing nullifier"),
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

        let spent_ironwood = wtx
            .ironwood_spends()
            .iter()
            .map(|s| SpentIronwood {
                account_id: *s.account_id(),
                nullifier: *s.nf(),
            })
            .collect();

        transactions.push(TxOutput {
            txid,
            received_orchard,
            received_sapling,
            received_ironwood,
            spent_orchard,
            spent_sapling,
            spent_ironwood,
        });
    }

    // 4. Block-level commitments: every action's cmx / every output's cmu, in
    //    order, for ShardTree integrity.
    let metadata = scanned.to_block_metadata();

    // Preserve upstream's in-memory scanning contract: subsequent scans see
    // every currently unspent nullifier, including notes received in this
    // block, and no nullifier spent by this block.
    nullifiers.update_with(&scanned);

    let commitments = scanned.into_commitments();
    let orchard_commitments = commitments.orchard;
    let sapling_commitments = commitments.sapling;
    let ironwood_commitments = commitments.ironwood;

    BlockOutput {
        metadata,
        height,
        transactions,
        orchard_commitments,
        sapling_commitments,
        ironwood_commitments,
    }
}

/// Per-tx decryption for memos + notes via `decrypt_transaction`.
fn decrypt_block_memos<'a, P>(
    params: &P,
    vtx: impl IntoIterator<Item = &'a Transaction>,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    height: BlockHeight,
) -> BlockMemos
where
    P: Parameters,
{
    let mut memos = BlockMemos {
        orchard: HashMap::new(),
        sapling: HashMap::new(),
        ironwood: HashMap::new(),
    };

    for tx in vtx {
        let decrypted = decrypt_transaction(params, Some(height), None, tx, ufvks);

        for out in decrypted.orchard_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos
                    .orchard
                    .insert((decrypted.tx().txid(), out.index()), memo);
            }
        }

        for out in decrypted.sapling_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos
                    .sapling
                    .insert((decrypted.tx().txid(), out.index()), memo);
            }
        }

        for out in decrypted.ironwood_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos
                    .ironwood
                    .insert((decrypted.tx().txid(), out.index()), memo);
            }
        }
    }

    memos
}
