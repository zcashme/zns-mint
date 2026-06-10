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
use zcash_primitives::merkle_tree::read_commitment_tree;

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

/// The outcome of funding selection: the chosen unspent note (if any meets
/// the floor) plus the total unspent registry balance seen in the window —
/// the *hot balance* the signer's low-watermark gate runs against.
pub struct FundingSelection {
    /// The first unspent note worth at least the floor, with its witness.
    pub note: Option<SpendableNote>,
    /// Sum of every unspent registry note in the window (floor or not).
    pub spendable_total_zat: u64,
}

/// Find an **unspent** registry-owned note worth at least `min_value_zat`
/// somewhere in `[start_height, anchor_height]` and build its spend witness
/// anchored at `anchor_height`.
///
/// The commitment tree is seeded from the `GetTreeState` frontier just before
/// `start_height` (so we only replay the window, not the whole chain — essential
/// on testnet/mainnet). The funding note must therefore land at/after
/// `start_height`; set the daemon birthday below where the registry was funded.
///
/// Spentness: every compact action carries the nullifier of the note it
/// spends, so the same window scan collects all spends; a candidate whose
/// nullifier (computed under the registry FVK) has appeared is excluded.
/// A spend *below* the window can't be seen — acceptable under the same
/// "birthday below funding" rule the frontier already imposes.
///
/// Returns `None` if no eligible unspent note exists.
pub async fn select_funding(
    config: &ScannerConfig,
    min_value_zat: u64,
    start_height: u32,
    anchor_height: u32,
) -> anyhow::Result<FundingSelection> {
    let ivk = PreparedIncomingViewingKey::new(&config.registry_fvk.to_ivk(Scope::External));
    let mut client = grpc::connect(&config.lwd_url)
        .await
        .map_err(|e| anyhow!("connect to {}: {e:?}", config.lwd_url))?;

    // Seed the tree from the frontier just before the window, so the positions
    // of leaves we append match the real chain tree.
    let mut tree: CommitmentTree<MerkleHashOrchard, ORCHARD_DEPTH> = if start_height > 1 {
        let state = client
            .get_tree_state(BlockId { height: (start_height - 1) as u64, hash: vec![] })
            .await
            .context("get_tree_state")?
            .into_inner();
        if state.orchard_tree.is_empty() {
            CommitmentTree::empty()
        } else {
            let bytes = hex::decode(state.orchard_tree.trim()).context("decode orchard tree")?;
            read_commitment_tree::<MerkleHashOrchard, _, ORCHARD_DEPTH>(&bytes[..])
                .context("read orchard tree frontier")?
        }
    } else {
        CommitmentTree::empty()
    };

    let mut stream = client
        .get_block_range(BlockRange {
            start: Some(BlockId { height: start_height as u64, hash: vec![] }),
            end: Some(BlockId { height: anchor_height as u64, hash: vec![] }),
            pool_types: vec![],
        })
        .await
        .context("get_block_range")?
        .into_inner();

    // Every eligible registry note becomes a candidate whose witness is
    // extended in lock-step with the tree; every action's nullifier is
    // collected so spent candidates can be excluded at the end. (A "pick the
    // first and stop tracking" scheme cannot work: the spend that disqualifies
    // a candidate may appear later in the stream.)
    type Witness = IncrementalWitness<MerkleHashOrchard, ORCHARD_DEPTH>;
    let mut candidates: Vec<(Note, u64, Witness, [u8; 32])> = Vec::new();
    let mut spent: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    // Every registry-owned note (no witness — value/nullifier only), for the
    // hot-balance total.
    let mut owned: Vec<(u64, [u8; 32])> = Vec::new();

    while let Some(block) = stream.message().await.context("block stream")? {
        for tx in &block.vtx {
            // Parse failures are errors, not skips: a dropped action here
            // would desync the rebuilt commitment tree from the real chain
            // tree, yielding an anchor consensus rejects.
            let actions: Vec<CompactAction> = tx
                .actions
                .iter()
                .map(|a| {
                    parse_orchard(a)
                        .ok_or_else(|| anyhow!("unparseable compact Orchard action in funding scan"))
                })
                .collect::<anyhow::Result<_>>()?;
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
                // The action spends some prior note; record its nullifier.
                spent.insert(action.nullifier().to_bytes());

                let leaf = MerkleHashOrchard::from_cmx(&action.cmx());
                for (_, _, witness, _) in candidates.iter_mut() {
                    witness
                        .append(leaf)
                        .map_err(|_| anyhow!("witness append failed (tree full)"))?;
                }
                tree.append(leaf)
                    .map_err(|_| anyhow!("tree append failed (tree full)"))?;

                // Eligible registry note: witness the leaf we just added.
                if let Some(((note, _addr), _ivk_idx)) = hits.get(i).cloned().flatten() {
                    let value = note.value().inner();
                    let nf = note.nullifier(&config.registry_fvk).to_bytes();
                    owned.push((value, nf));
                    if value >= min_value_zat {
                        let witness = IncrementalWitness::from_tree(tree.clone())
                            .ok_or_else(|| anyhow!("cannot witness an empty tree"))?;
                        candidates.push((note, value, witness, nf));
                    }
                }
            }
        }
    }

    let spendable_total_zat =
        owned.iter().filter(|(_, nf)| !spent.contains(nf)).map(|(v, _)| v).sum();
    let note = candidates.into_iter().find(|(_, _, _, nf)| !spent.contains(nf)).map(
        |(note, value_zat, witness, _)| {
            let path = witness.path().expect("witnessed note always has a path");
            SpendableNote {
                note,
                value_zat,
                merkle_path: MerklePath::from(path),
                anchor: Anchor::from(witness.root()),
            }
        },
    );
    Ok(FundingSelection { note, spendable_total_zat })
}
