//! Treasury note-state: select a registry-owned Orchard note to fund a mint and
//! build its spend witness.
//!
//! A funded mint must spend a real note, which needs a Merkle path to a recent
//! anchor. We reconstruct the Orchard note-commitment tree by replaying every
//! action's `cmx` from the compact-block stream (genesis → `anchor_height`, in
//! consensus order), capture an [`IncrementalWitness`] at the chosen note's
//! position, and extend it to the anchor. The resulting `(note, path, anchor)`
//! is everything `zns_signer::build_funded_mint` needs.
//!
//! This is an O(chain) scan; adequate for regtest and low-rate minting. A
//! production daemon would maintain the tree incrementally (shardtree) instead
//! of rescanning each time.

use anyhow::{anyhow, Context as _};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{
    keys::{PreparedIncomingViewingKey, Scope},
    note_encryption::{CompactAction, OrchardDomain},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    Note,
};
use zcash_client_backend::proto::service::{BlockId, BlockRange};
use zcash_note_encryption::batch;

use crate::{grpc, scanner::parse_orchard, ScannerConfig};

/// Orchard note-commitment tree depth.
const ORCHARD_DEPTH: u8 = 32;

/// A registry-owned Orchard note that can fund a mint, with its spend witness.
pub struct SpendableNote {
    /// The note to spend.
    pub note: Note,
    /// Its value in zatoshis.
    pub value_zat: u64,
    /// Merkle path authenticating the note to [`Self::anchor`].
    pub merkle_path: MerklePath,
    /// The tree root the path authenticates to (the bundle's spend anchor).
    pub anchor: Anchor,
}

/// Scan the Orchard commitment tree from genesis to `anchor_height`, find a
/// registry-owned note worth at least `min_value_zat`, and build its witness.
///
/// Returns `None` if no eligible note exists. Note: this does not yet track
/// nullifiers, so it can return an already-spent note; the daemon must avoid
/// double-spends until nullifier tracking lands.
pub async fn select_funding(
    config: &ScannerConfig,
    min_value_zat: u64,
    anchor_height: u32,
) -> anyhow::Result<Option<SpendableNote>> {
    let ivk = PreparedIncomingViewingKey::new(&config.registry_fvk.to_ivk(Scope::External));
    let mut client = grpc::connect(&config.lwd_url)
        .await
        .map_err(|e| anyhow!("connect to {}: {e:?}", config.lwd_url))?;

    let mut stream = client
        .get_block_range(BlockRange {
            start: Some(BlockId { height: 1, hash: vec![] }),
            end: Some(BlockId { height: anchor_height as u64, hash: vec![] }),
            pool_types: vec![],
        })
        .await
        .context("get_block_range")?
        .into_inner();

    let mut tree: CommitmentTree<MerkleHashOrchard, ORCHARD_DEPTH> = CommitmentTree::empty();
    // Once a note is chosen we hold its witness and keep extending it with every
    // subsequent leaf, in lock-step with the tree.
    let mut chosen: Option<(Note, u64, IncrementalWitness<MerkleHashOrchard, ORCHARD_DEPTH>)> = None;

    while let Some(block) = stream.message().await.context("block stream")? {
        for tx in &block.vtx {
            let actions: Vec<CompactAction> = tx.actions.iter().filter_map(parse_orchard).collect();
            if actions.is_empty() {
                continue;
            }

            // Trial-decrypt this tx's actions to spot registry-owned notes.
            let inputs: Vec<(OrchardDomain, CompactAction)> = actions
                .iter()
                .cloned()
                .map(|a| (OrchardDomain::for_compact_action(&a), a))
                .collect();
            let hits = batch::try_compact_note_decryption(std::slice::from_ref(&ivk), &inputs);

            for (i, action) in actions.iter().enumerate() {
                let leaf = MerkleHashOrchard::from_cmx(&action.cmx());

                // Extend the witness with leaves that come after the chosen note.
                if let Some((_, _, witness)) = chosen.as_mut() {
                    witness
                        .append(leaf)
                        .map_err(|_| anyhow!("witness append failed (tree full)"))?;
                }
                tree.append(leaf)
                    .map_err(|_| anyhow!("tree append failed (tree full)"))?;

                // First eligible registry note: witness the leaf we just added.
                if chosen.is_none() {
                    if let Some(((note, _addr), _ivk_idx)) = hits.get(i).cloned().flatten() {
                        if note.value().inner() >= min_value_zat {
                            let witness = IncrementalWitness::from_tree(tree.clone())
                                .ok_or_else(|| anyhow!("cannot witness an empty tree"))?;
                            let value = note.value().inner();
                            chosen = Some((note, value, witness));
                        }
                    }
                }
            }
        }
    }

    Ok(chosen.map(|(note, value_zat, witness)| {
        let path = witness.path().expect("witnessed note always has a path");
        SpendableNote {
            note,
            value_zat,
            merkle_path: MerklePath::from(path),
            anchor: Anchor::from(witness.root()),
        }
    }))
}
