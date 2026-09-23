//! The best chain: where it is, and what's in it.

use std::time::Duration;

use futures_util::StreamExt as _;
use incrementalmerkletree::frontier::Frontier;
use sapling::Node as SaplingNode;
use serde::Deserialize;
use time::Timestamp;
use zcash_client_backend::data_api::chain::{ChainState, CommitmentTreeRoot};
use zcash_primitives::block::{Block, BlockHash};
use zcash_primitives::merkle_tree::{read_commitment_tree, HashSer};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zebra_indexer_proto::{BlockHashAndHeight, Empty, ZebraClient};

use super::{
    not_on_best_chain, CanonicalBlockSource, JsonRpc, TransportError, REQUEST_TIMEOUT, RETRY_PAUSE,
};
use orchard::tree::MerkleHashOrchard;

/// The indexer's gRPC endpoint.
#[cfg(not(all(feature = "testnet", not(feature = "regtest"))))]
const ZEBRA_INDEXER_URL: &str = "http://127.0.0.1:8230";
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
const ZEBRA_INDEXER_URL: &str = "http://127.0.0.1:18230";

/// TCP connect timeout for a fresh gRPC connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Keep-alive ping interval on the gRPC connection.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Unanswered keep-alive pings before the connection is declared dead.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// A client for the node's gRPC announcements about the chain.
#[derive(Clone)]
pub struct ChainClient(pub(crate) ZebraClient);

impl ChainClient {
    /// Connects to the indexer's gRPC endpoint, keep-alive on: the tip
    /// stream hangs silently on a dead peer otherwise.
    pub(crate) async fn connect() -> Result<Self, tonic::transport::Error> {
        let endpoint = tonic::transport::Endpoint::from_static(ZEBRA_INDEXER_URL)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
            .keep_alive_while_idle(true);

        let client = ZebraClient::connect(endpoint).await?;
        Ok(Self(client))
    }

    /// Change-only tip stream.
    pub(crate) async fn chain_tip_change_stream(&mut self) -> Result<TipStream, TransportError> {
        self.0
            .chain_tip_change(Empty {})
            .await
            .map(|r| r.into_inner())
            .map_err(TransportError::from)
    }
}

/// The live gRPC tip stream: one notification per canonical tip change.
pub(crate) type TipStream = tonic::codec::Streaming<BlockHashAndHeight>;

/// A tip announcement, decoded: `(height, hash)` from one message.
/// A malformed hash is bad node data — the typed verdict, never a panic.
pub(crate) fn tip_height_hash(
    tip: &BlockHashAndHeight,
) -> Result<(BlockHeight, BlockHash), TransportError> {
    let bytes = tip
        .hash_display_order()
        .ok_or(TransportError::BadNodeData("tip hash length"))?;
    let hash =
        block_hash_from_display(bytes).ok_or(TransportError::BadNodeData("tip hash length"))?;
    Ok((BlockHeight::from_u32(tip.height), hash))
}

// ============================================================================
// The tip session — the stream's one owner
// ============================================================================

/// The tip stream's one owner: subscription, client, repair.
pub struct TipSession {
    client: ChainClient,
    stream: TipStream,
}

impl TipSession {
    /// Subscribes to the change-only tip stream.
    pub async fn open(client: ChainClient) -> Self {
        let stream = Self::subscribe(client.clone()).await;
        Self { client, stream }
    }

    /// One wake-up, answered with the node's canonical tip; the stream
    /// is repaired on death. `Err` is a fatal data verdict.
    pub async fn next_tip(
        &mut self,
        source: &CanonicalBlockSource,
    ) -> Result<(BlockHeight, BlockHash), TransportError> {
        let announced = match self.stream.next().await {
            Some(Ok(notification)) => {
                let announced = tip_height_hash(&notification)?;
                tracing::info!(height = u32::from(announced.0), "tip notification received");
                Some(announced)
            }
            Some(Err(error)) => {
                tracing::warn!(%error, "Zebra tip stream failed; repairing");
                self.repair().await;
                None
            }
            None => {
                tracing::warn!("Zebra tip stream ended; repairing");
                self.repair().await;
                None
            }
        };

        // Truth is self-derived: the announcement may have coalesced
        // every change since the last wake-up, so the node's answer —
        // not the stream's promise — is what the mint acts on.
        let best = source.canonical_tip().await?;
        if let Some((height, hash)) = announced {
            if best != (height, hash) {
                tracing::debug!(
                    announced_height = u32::from(height),
                    announced_hash = %hash,
                    best_height = u32::from(best.0),
                    best_hash = %best.1,
                    "coalesced Zebra tip notification"
                );
            }
        }
        Ok(best)
    }

    /// Pause, reopen.
    async fn repair(&mut self) {
        tokio::time::sleep(RETRY_PAUSE).await;
        self.stream = Self::subscribe(self.client.clone()).await;
    }

    /// Opens the tip stream, retrying until Zebra answers.
    async fn subscribe(mut client: ChainClient) -> TipStream {
        loop {
            match client.chain_tip_change_stream().await {
                Ok(stream) => return stream,
                Err(error) => {
                    tracing::warn!(%error, "Zebra tip stream unavailable; reconnecting");
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
            }
        }
    }
}

/// Reverses Zebra's display-order bytes into a `BlockHash`.
pub(crate) fn block_hash_from_display(bytes: &[u8]) -> Option<BlockHash> {
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        arr.reverse();
        Some(BlockHash(arr))
    } else {
        None
    }
}

impl JsonRpc {
    /// Fetches blockchain state info, used for boot-time cross-validation.
    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo, TransportError> {
        self.send_request("getblockchaininfo", [(); 0])
            .await?
            .ok_or(TransportError::BadNodeData(
                "getblockchaininfo returned null",
            ))
    }

    /// Fetches a best-chain block hash by height, for reorg walks — the
    /// genesis block is fetched this way because [`Block::read`] rejects it.
    pub async fn get_block_hash(&self, height: BlockHeight) -> Result<BlockHash, TransportError> {
        let index = i32::try_from(u32::from(height))
            .map_err(|_| TransportError::BadNodeData("getblockhash height"))?;
        let hash_hex: String = self
            .send_request("getblockhash", [index])
            .await
            .map_err(not_on_best_chain)?
            .ok_or(TransportError::BadNodeData("getblockhash returned null"))?;

        let display_bytes =
            hex::decode(hash_hex).map_err(|_| TransportError::BadNodeData("getblockhash hex"))?;
        block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("getblockhash length"))
    }

    /// Fetches the shielded tree state for a block, as the upstream
    /// [`ChainState`] — the connection point for `WalletWrite::put_blocks`.
    pub async fn chain_state_at(&self, height: BlockHeight) -> Result<ChainState, TransportError> {
        let response: TreeStateResponse = self
            .send_request("z_gettreestate", [u32::from(height).to_string()])
            .await
            .map_err(not_on_best_chain)?
            .ok_or(TransportError::BadNodeData("z_gettreestate returned null"))?;

        if response.height != u32::from(height) {
            return Err(TransportError::BadNodeData(
                "z_gettreestate answered a different height than requested",
            ));
        }

        chain_state_from_rpc_response(response)
    }

    /// Fetches every completed subtree root for one shielded pool, from
    /// `start_index` upward, via Zebra's `z_getsubtreesbyindex`.
    ///
    /// `pool` is a Zebra pool name (`"sapling"`, `"orchard"`, `"ironwood"`).
    /// The mint's boot fetches Sapling and Ironwood only; Orchard is
    /// intentionally omitted — see the boot sequence.
    ///
    /// Each returned root pairs the shard's immutable subtree root hash
    /// with the block height at which the shard completed
    /// (`CommitmentTreeRoot::from_parts`). Zebra only ever returns
    /// completed shards, never the rightmost partial one — that comes from
    /// `z_gettreestate` (see [`Self::chain_state_at`]).
    ///
    /// Byte order: subtree `root` hex is canonical [`HashSer`] bytes, not
    /// display-order reversal. Zebra's RPC does
    /// `sapling: node.to_bytes().encode_hex()` and
    /// `orchard|ironwood: node.encode_hex()` where orchard `encode_hex` is
    /// `to_repr()` with no reverse (`zcashd` also does not reverse subtree
    /// roots). Contrast `z_gettreestate` `finalRoot`, which *is* display-order
    /// — we never parse that field. `finalState` is the HashSer tree, same
    /// convention as these roots.
    pub async fn get_subtree_roots<Node>(
        &self,
        pool: &'static str,
        start_index: u64,
    ) -> Result<Vec<CommitmentTreeRoot<Node>>, TransportError>
    where
        Node: HashSer,
    {
        let response: SubtreesResponse = self
            .send_request("z_getsubtreesbyindex", (pool, start_index))
            .await?
            .ok_or(TransportError::BadNodeData(
                "z_getsubtreesbyindex returned null",
            ))?;
        subtrees_response_to_roots(response, pool, start_index)
    }

    /// Fetches a block header as `(hash, height, time)`, for MTP backfill.
    pub async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<(BlockHash, BlockHeight, Timestamp), TransportError> {
        let response: BlockHeaderResponse = self
            .send_request("getblockheader", (u32::from(height).to_string(), true))
            .await
            .map_err(not_on_best_chain)?
            .ok_or(TransportError::BadNodeData("getblockheader returned null"))?;

        if response.height != u32::from(height) {
            return Err(TransportError::BadNodeData(
                "getblockheader answered a different height than requested",
            ));
        }

        let display_bytes = hex::decode(&response.hash)
            .map_err(|_| TransportError::BadNodeData("getblockheader hash hex"))?;
        let hash = block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("getblockheader hash length"))?;

        let time = Timestamp::from_seconds(response.time as i64)
            .map_err(|_| TransportError::BadNodeData("getblockheader time"))?;

        Ok((hash, BlockHeight::from_u32(response.height), time))
    }

    /// Fetches a full block by height and parses it under the compiled
    /// consensus parameters — best-chain membership remains Zebra's word.
    pub async fn get_block<P: Parameters>(
        &self,
        network: &P,
        height: BlockHeight,
    ) -> Result<Block, TransportError> {
        let hex_str: String = self
            .send_request("getblock", (u32::from(height).to_string(), 0))
            .await
            .map_err(not_on_best_chain)?
            .ok_or(TransportError::BadNodeData("getblock returned null"))?;

        let bytes =
            hex::decode(hex_str).map_err(|_| TransportError::BadNodeData("getblock hex"))?;
        let block = Block::read(&bytes[..], network)
            .map_err(|_| TransportError::BadNodeData("getblock parse"))?;
        if block.claimed_height() != height {
            return Err(TransportError::BadNodeData(
                "getblock returned the wrong height",
            ));
        }
        Ok(block)
    }
}

impl super::CanonicalBlockSource {
    /// Returns the exact `(height, hash)` pair for the current best-chain
    /// tip, parsed from one `getblockchaininfo` response so observations
    /// from different tips cannot be combined.
    pub async fn exact_tip(&self) -> Result<(BlockHeight, BlockHash), TransportError> {
        self.0.get_blockchain_info().await?.canonical_tip()
    }

    /// The canonical tip, retrying while the node is merely unavailable.
    pub async fn canonical_tip(&self) -> Result<(BlockHeight, BlockHash), TransportError> {
        loop {
            match self.exact_tip().await {
                Ok(tip) => return Ok(tip),
                Err(error) if error.is_retryable() => {
                    tracing::warn!(%error, "exact Zebra tip unavailable; retrying");
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Fetches a full canonical block by height (see [`JsonRpc::get_block`]).
    pub async fn get_block<P: Parameters>(
        &self,
        network: &P,
        height: BlockHeight,
    ) -> Result<Block, TransportError> {
        self.0.get_block(network, height).await
    }

    /// A best-chain block hash by height (see [`JsonRpc::get_block_hash`]).
    pub async fn get_block_hash(&self, height: BlockHeight) -> Result<BlockHash, TransportError> {
        self.0.get_block_hash(height).await
    }

    /// The shielded tree state at a height (see [`JsonRpc::chain_state_at`]).
    pub async fn chain_state_at(&self, height: BlockHeight) -> Result<ChainState, TransportError> {
        self.0.chain_state_at(height).await
    }

    /// A block header's `(hash, height, time)` (see [`JsonRpc::get_block_header`]).
    pub async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<(BlockHash, BlockHeight, Timestamp), TransportError> {
        self.0.get_block_header(height).await
    }
}

// ============================================================================
// Typed responses
// ============================================================================

/// The `getblockchaininfo` answer.
#[derive(Debug, Deserialize)]
pub struct BlockchainInfo {
    pub blocks: u32,
    pub bestblockhash: String,
}

impl BlockchainInfo {
    /// Parses the height/hash pair carried by this one response.
    pub fn canonical_tip(&self) -> Result<(BlockHeight, BlockHash), TransportError> {
        let display_bytes = hex::decode(&self.bestblockhash)
            .map_err(|_| TransportError::BadNodeData("bestblockhash hex"))?;
        let hash = block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("bestblockhash length"))?;

        Ok((BlockHeight::from_u32(self.blocks), hash))
    }
}

#[derive(Debug, Deserialize)]
struct BlockHeaderResponse {
    hash: String,
    height: u32,
    time: u32,
}

/// The `z_getsubtreesbyindex` answer.
#[derive(Debug, Deserialize)]
struct SubtreesResponse {
    pool: String,
    start_index: u64,
    subtrees: Vec<SubtreeInfo>,
}

/// One completed subtree entry inside [`SubtreesResponse`].
#[derive(Debug, Deserialize)]
struct SubtreeInfo {
    /// The subtree root, hex-encoded internal bytes ([`HashSer`]).
    root: String,
    /// The block height at which this shard completed.
    end_height: u32,
}

/// Decodes a `z_getsubtreesbyindex` response into pool-typed roots.
/// Extracted so the wire decode is testable without Zebra.
///
/// Cross-checks `pool` and `start_index` against the server echo — a
/// mismatch is `BadNodeData` (silent wrong-pool parse would poison the
/// wallet's shard store).
fn subtrees_response_to_roots<Node>(
    response: SubtreesResponse,
    expected_pool: &str,
    expected_start_index: u64,
) -> Result<Vec<CommitmentTreeRoot<Node>>, TransportError>
where
    Node: HashSer,
{
    if response.pool != expected_pool {
        return Err(TransportError::BadNodeData(
            "z_getsubtreesbyindex answered a different pool than requested",
        ));
    }
    if response.start_index != expected_start_index {
        return Err(TransportError::BadNodeData(
            "z_getsubtreesbyindex answered a different start_index than requested",
        ));
    }

    let mut roots = Vec::with_capacity(response.subtrees.len());
    for entry in response.subtrees {
        // Canonical HashSer bytes. Do not reverse: that is the block-hash /
        // txid convention, and Zebra's subtree-root hex is not that.
        let bytes = hex::decode(&entry.root)
            .map_err(|_| TransportError::BadNodeData("z_getsubtreesbyindex root hex"))?;
        if bytes.len() != 32 {
            return Err(TransportError::BadNodeData(
                "z_getsubtreesbyindex root length",
            ));
        }
        let node = Node::read(&bytes[..])
            .map_err(|_| TransportError::BadNodeData("z_getsubtreesbyindex root parse"))?;
        roots.push(CommitmentTreeRoot::from_parts(
            BlockHeight::from_u32(entry.end_height),
            node,
        ));
    }
    Ok(roots)
}

#[derive(Debug, Deserialize)]
struct TreeStateResponse {
    height: u32,
    hash: String,
    sapling: ShieldedTreeState,
    orchard: ShieldedTreeState,
    ironwood: ShieldedTreeState,
}

#[derive(Debug, Deserialize)]
struct ShieldedTreeState {
    commitments: TreeCommitments,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TreeCommitments {
    final_state: Option<String>,
}

/// `z_gettreestate` parsed into the upstream [`ChainState`]; every
/// pool's treestate is mandatory — a missing section is a malformed
/// response, rejected at the type.
fn chain_state_from_rpc_response(
    response: TreeStateResponse,
) -> Result<ChainState, TransportError> {
    let sapling_final_state = response
        .sapling
        .commitments
        .final_state
        .ok_or(TransportError::BadNodeData("missing Sapling finalState"))?;
    let sapling_tree = decode_tree::<SaplingNode>(&sapling_final_state, "Sapling")?;

    let orchard_final_state = response
        .orchard
        .commitments
        .final_state
        .ok_or(TransportError::BadNodeData("missing Orchard finalState"))?;
    let orchard_tree = decode_tree::<MerkleHashOrchard>(&orchard_final_state, "Orchard")?;

    let ironwood_final_state = response
        .ironwood
        .commitments
        .final_state
        .ok_or(TransportError::BadNodeData("missing Ironwood finalState"))?;
    let ironwood_tree = decode_tree::<MerkleHashOrchard>(&ironwood_final_state, "Ironwood")?;

    let expected_hash_bytes =
        hex::decode(&response.hash).map_err(|_| TransportError::BadNodeData("invalid hash hex"))?;
    let expected_hash = block_hash_from_display(&expected_hash_bytes)
        .ok_or(TransportError::BadNodeData("malformed 32-byte hash"))?;

    Ok(ChainState::new(
        BlockHeight::from_u32(response.height),
        expected_hash,
        sapling_tree,
        orchard_tree,
        ironwood_tree,
    ))
}

/// Decodes one `finalState` hex into the upstream frontier value.
fn decode_tree<Node>(
    hex_state: &str,
    name: &'static str,
) -> Result<Frontier<Node, 32>, TransportError>
where
    Node: HashSer + incrementalmerkletree::Hashable + Clone,
{
    let bytes = hex::decode(hex_state).map_err(|e| {
        TransportError::BadCheckpoint(format!("{name} tree hex decode failed: {e}"))
    })?;

    read_commitment_tree::<Node, _, 32>(&bytes[..])
        .map(|tree| tree.to_frontier())
        .map_err(|e| TransportError::BadCheckpoint(format!("{name} tree decode failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `z_getsubtreesbyindex` fixture: shape matches Zebra's
    /// live reply (`pool`, `start_index`, `subtrees[{root, end_height}]`).
    const SAPLING_FIXTURE: &str = r#"{
        "pool": "sapling",
        "start_index": 0,
        "subtrees": [
            { "root": "0100000000000000000000000000000000000000000000000000000000000000", "end_height": 100000 },
            { "root": "0200000000000000000000000000000000000000000000000000000000000000", "end_height": 200000 }
        ]
    }"#;

    #[test]
    fn subtrees_response_deserialises_wire_shape() {
        let response: SubtreesResponse =
            serde_json::from_str(SAPLING_FIXTURE).expect("valid fixture");
        assert_eq!(response.pool, "sapling");
        assert_eq!(response.start_index, 0);
        assert_eq!(response.subtrees.len(), 2);
        assert_eq!(response.subtrees[0].end_height, 100_000);
        assert_eq!(response.subtrees[1].end_height, 200_000);
    }

    #[test]
    fn subtrees_response_to_roots_preserves_index_and_height() {
        let response: SubtreesResponse =
            serde_json::from_str(SAPLING_FIXTURE).expect("valid fixture");
        let roots =
            subtrees_response_to_roots::<SaplingNode>(response, "sapling", 0).expect("parse ok");
        assert_eq!(roots.len(), 2);
        assert_eq!(
            roots[0].subtree_end_height(),
            BlockHeight::from_u32(100_000)
        );
        assert_eq!(
            roots[1].subtree_end_height(),
            BlockHeight::from_u32(200_000)
        );
    }

    #[test]
    fn subtrees_response_pool_mismatch_is_bad_node_data() {
        let response: SubtreesResponse =
            serde_json::from_str(SAPLING_FIXTURE).expect("valid fixture");
        // Requested "ironwood", server answered "sapling".
        match subtrees_response_to_roots::<MerkleHashOrchard>(response, "ironwood", 0) {
            Err(TransportError::BadNodeData(_)) => {}
            other => panic!("expected BadNodeData, got {other:?}"),
        }
    }

    #[test]
    fn subtrees_response_start_index_mismatch_is_bad_node_data() {
        let response: SubtreesResponse =
            serde_json::from_str(SAPLING_FIXTURE).expect("valid fixture");
        // Requested 5, server answered 0.
        match subtrees_response_to_roots::<SaplingNode>(response, "sapling", 5) {
            Err(TransportError::BadNodeData(_)) => {}
            other => panic!("expected BadNodeData, got {other:?}"),
        }
    }

    #[test]
    fn subtrees_response_bad_root_length_is_bad_node_data() {
        let json = r#"{
            "pool": "sapling",
            "start_index": 0,
            "subtrees": [
                { "root": "01", "end_height": 100 }
            ]
        }"#;
        let response: SubtreesResponse = serde_json::from_str(json).expect("valid fixture");
        match subtrees_response_to_roots::<SaplingNode>(response, "sapling", 0) {
            Err(TransportError::BadNodeData(_)) => {}
            other => panic!("expected BadNodeData, got {other:?}"),
        }
    }

    #[test]
    fn subtrees_response_bad_root_hex_is_bad_node_data() {
        let json = r#"{
            "pool": "sapling",
            "start_index": 0,
            "subtrees": [
                { "root": "zz", "end_height": 100 }
            ]
        }"#;
        let response: SubtreesResponse = serde_json::from_str(json).expect("valid fixture");
        match subtrees_response_to_roots::<SaplingNode>(response, "sapling", 0) {
            Err(TransportError::BadNodeData(_)) => {}
            other => panic!("expected BadNodeData, got {other:?}"),
        }
    }

    #[test]
    fn subtrees_response_empty_list_is_ok() {
        let json = r#"{ "pool": "ironwood", "start_index": 0, "subtrees": [] }"#;
        let response: SubtreesResponse = serde_json::from_str(json).expect("valid fixture");
        let roots = subtrees_response_to_roots::<MerkleHashOrchard>(response, "ironwood", 0)
            .expect("parse ok");
        assert!(roots.is_empty());
    }

    /// Asymmetric canonical field element: byte 0 = 1, rest 0. Palindromes
    /// cannot distinguish HashSer order from display-order reversal.
    fn asymmetric_field_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes
    }

    fn hashser_bytes<Node: HashSer>(node: &Node) -> [u8; 32] {
        let mut out = [0u8; 32];
        node.write(&mut out[..]).expect("HashSer node is 32 bytes");
        out
    }

    /// Zebra sapling: `subtree.root.to_bytes().encode_hex()` — `to_bytes` is
    /// HashSer. Display-order reversal would produce a different node.
    #[test]
    fn sapling_subtree_root_hex_is_hashser_not_display_order() {
        subtree_root_hex_matches_hashser::<SaplingNode>("sapling");
    }

    /// Zebra orchard/ironwood: `subtree.root.encode_hex()` where orchard
    /// `Node::bytes_in_display_order` is `to_repr()` with no reverse
    /// ("zcashd does not reverse the byte order of subtree roots").
    #[test]
    fn orchard_subtree_root_hex_is_hashser_not_display_order() {
        subtree_root_hex_matches_hashser::<MerkleHashOrchard>("orchard");
        subtree_root_hex_matches_hashser::<MerkleHashOrchard>("ironwood");
    }

    fn subtree_root_hex_matches_hashser<Node>(pool: &str)
    where
        Node: HashSer + PartialEq + std::fmt::Debug,
    {
        let bytes = asymmetric_field_bytes();
        let expected = Node::read(&bytes[..]).expect("canonical field element");
        assert_eq!(hashser_bytes(&expected), bytes);

        let mut reversed = bytes;
        reversed.reverse();
        assert_ne!(bytes, reversed, "fixture must not be a palindrome");

        let json = format!(
            r#"{{"pool":"{pool}","start_index":0,"subtrees":[{{"root":"{}","end_height":1}}]}}"#,
            hex::encode(bytes)
        );
        let response: SubtreesResponse = serde_json::from_str(&json).expect("valid fixture");
        let roots = subtrees_response_to_roots::<Node>(response, pool, 0).expect("parse ok");
        assert_eq!(*roots[0].root_hash(), expected);

        let json_rev = format!(
            r#"{{"pool":"{pool}","start_index":0,"subtrees":[{{"root":"{}","end_height":1}}]}}"#,
            hex::encode(reversed)
        );
        let response_rev: SubtreesResponse =
            serde_json::from_str(&json_rev).expect("valid fixture");
        let reversed_roots = subtrees_response_to_roots::<Node>(response_rev, pool, 0)
            .expect("reversed still 32 bytes");
        assert_ne!(
            *reversed_roots[0].root_hash(),
            expected,
            "display-order reversal must not round-trip to the HashSer node"
        );
    }
    /// A commitment tree's hex, as `finalState` carries it — built with
    /// the upstream writer so the fixtures exercise our reader against
    /// the real encoding.
    fn tree_hex<Node>() -> String
    where
        Node: HashSer + incrementalmerkletree::Hashable + Clone,
    {
        let mut bytes = Vec::new();
        zcash_primitives::merkle_tree::write_commitment_tree::<Node, _, 32>(
            &incrementalmerkletree::frontier::CommitmentTree::<Node, 32>::empty(),
            &mut bytes,
        )
        .expect("an empty tree serializes");
        hex::encode(bytes)
    }

    fn treestate(ironwood: String) -> TreeStateResponse {
        TreeStateResponse {
            height: 1000,
            hash: hex::encode([0u8; 32]),
            sapling: ShieldedTreeState {
                commitments: TreeCommitments {
                    final_state: Some(tree_hex::<SaplingNode>()),
                },
            },
            orchard: ShieldedTreeState {
                commitments: TreeCommitments {
                    final_state: Some(tree_hex::<MerkleHashOrchard>()),
                },
            },
            ironwood: ShieldedTreeState {
                commitments: TreeCommitments {
                    final_state: Some(ironwood),
                },
            },
        }
    }

    #[test]
    fn treestate_garbage_ironwood_hex_is_a_bad_checkpoint() {
        let garbage = treestate("zz".to_string());
        assert!(matches!(
            chain_state_from_rpc_response(garbage),
            Err(TransportError::BadCheckpoint(_))
        ));
    }

    #[test]
    fn treestate_malformed_hash_is_bad_node_data() {
        let mut garbage = treestate(tree_hex::<MerkleHashOrchard>());
        garbage.hash = "not-hex!".to_string();
        assert!(matches!(
            chain_state_from_rpc_response(garbage),
            Err(TransportError::BadNodeData(_))
        ));
    }

    #[test]
    fn treestate_missing_sapling_state_is_bad_node_data() {
        let mut garbage = treestate(tree_hex::<MerkleHashOrchard>());
        garbage.sapling.commitments.final_state = None;
        assert!(matches!(
            chain_state_from_rpc_response(garbage),
            Err(TransportError::BadNodeData(_))
        ));
    }
}
