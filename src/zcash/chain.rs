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
use zcash_protocol::constants::MAX_BLOCK_BYTES;
use zebra_indexer_proto::{BlockAndHash, BlockHashAndHeight, BlockRequest, Empty, ZebraClient};

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

/// The gRPC answer bound: a consensus-max block fits twice over —
/// 4,000,000 bytes, strictly tighter than tonic's 4 MiB default, so the
/// limit is ours in effect as well as by declaration.
const GRPC_MAX_RESPONSE_BYTES: usize = 2 * MAX_BLOCK_BYTES;

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

        let client = ZebraClient::connect(endpoint)
            .await?
            .max_decoding_message_size(GRPC_MAX_RESPONSE_BYTES);
        Ok(Self(client))
    }

    /// One `Indexer.GetBlock` by height: the block's raw consensus bytes
    /// and its wire hash, from the node's best chain. A miss answers
    /// `not_found` — the verdict [`not_on_best_chain`] turns into a
    /// re-converge, never a retry.
    pub(crate) async fn block_and_hash(
        &mut self,
        height: BlockHeight,
    ) -> Result<BlockAndHash, TransportError> {
        Ok(self
            .0
            .get_block(block_request_at_height(height))
            .await
            .map_err(|status| not_on_best_chain(status.into()))?
            .into_inner())
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
    /// is repaired on death. A malformed announcement is dropped.
    /// `Err` is the canonical tip's data verdict.
    pub async fn next_tip(
        &mut self,
        source: &CanonicalBlockSource,
    ) -> Result<(BlockHeight, BlockHash), TransportError> {
        let announced = match self.stream.next().await {
            Some(Ok(notification)) => match tip_height_hash(&notification) {
                Ok(announced) => {
                    tracing::info!(height = u32::from(announced.0), "tip notification received");
                    Some(announced)
                }
                Err(error) => {
                    tracing::warn!(%error, "Zebra tip announcement malformed; using canonical tip");
                    None
                }
            },
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

/// A height on the `BlockRequest` wire: exactly four big-endian bytes —
/// 32 would name a hash instead (the server reads the length: a 32-byte
/// value is a display-order hash, a 4-byte value is a big-endian height,
/// anything else is rejected as `invalid_argument`).
fn block_request_at_height(height: BlockHeight) -> BlockRequest {
    BlockRequest {
        hash_or_height: u32::from(height).to_be_bytes().to_vec(),
    }
}

/// Parses an Indexer block answer under the compiled consensus parameters
/// and refuses an answer that names another height: the node's bytes are
/// adopted only when they are the block we asked for.
fn block_from_wire<P: Parameters>(
    data: &[u8],
    network: &P,
    height: BlockHeight,
) -> Result<Block, TransportError> {
    let block = Block::read(data, network)
        .map_err(|_| TransportError::BadNodeData("indexer block parse"))?;
    if block.claimed_height() != height {
        return Err(TransportError::BadNodeData(
            "indexer block answered a different height than requested",
        ));
    }
    Ok(block)
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
        loop {
            let result: Result<_, TransportError> = async {
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
            .await;

            match result {
                Ok(header) => return Ok(header),
                Err(error)
                    if error.is_retryable() || matches!(&error, TransportError::NotOnBestChain) =>
                {
                    tracing::warn!(
                        %error,
                        height = u32::from(height),
                        "MTP header unavailable or unusable; retrying"
                    );
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl super::CanonicalBlockSource {
    /// Returns the exact `(height, hash)` pair for the current best-chain
    /// tip, parsed from one `getblockchaininfo` response so observations
    /// from different tips cannot be combined.
    pub async fn exact_tip(&self) -> Result<(BlockHeight, BlockHash), TransportError> {
        self.rpc.get_blockchain_info().await?.canonical_tip()
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

    /// Fetches a full canonical block by height over the Indexer gRPC —
    /// raw consensus bytes, no hex detour — and parses it under the
    /// compiled consensus parameters. Best-chain membership remains
    /// Zebra's word: the bytes are the state-committed block's own
    /// serialization.
    pub async fn get_block<P: Parameters>(
        &self,
        network: &P,
        height: BlockHeight,
    ) -> Result<Block, TransportError> {
        let fetched = self.chain.clone().block_and_hash(height).await?;
        block_from_wire(&fetched.data, network, height)
    }

    /// A best-chain block hash by height, for reorg walks. The hash rides
    /// the wire, so genesis answers where [`Block::read`] refuses to
    /// parse. The Indexer serves no hash-only call: the walk pays one
    /// whole-block fetch per step — rare path, loopback, accepted.
    pub async fn get_block_hash(&self, height: BlockHeight) -> Result<BlockHash, TransportError> {
        let fetched = self.chain.clone().block_and_hash(height).await?;
        block_hash_from_display(&fetched.hash)
            .ok_or(TransportError::BadNodeData("indexer block hash length"))
    }

    /// The shielded tree state at a height (see the `chain_state_at`
    /// JSON-RPC reader).
    pub async fn chain_state_at(&self, height: BlockHeight) -> Result<ChainState, TransportError> {
        self.rpc.chain_state_at(height).await
    }

    /// Every completed subtree root for one shielded pool, from
    /// `start_index` upward (see the `get_subtree_roots` JSON-RPC reader).
    pub async fn get_subtree_roots<Node>(
        &self,
        pool: &'static str,
        start_index: u64,
    ) -> Result<Vec<CommitmentTreeRoot<Node>>, TransportError>
    where
        Node: HashSer,
    {
        self.rpc.get_subtree_roots(pool, start_index).await
    }

    /// A block header's `(hash, height, time)` (see the `get_block_header`
    /// JSON-RPC reader).
    pub async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<(BlockHash, BlockHeight, Timestamp), TransportError> {
        self.rpc.get_block_header(height).await
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

    #[test]
    fn tip_height_hash_rejects_a_short_hash() {
        let tip = BlockHashAndHeight {
            hash: vec![0u8; 31],
            height: 1,
        };
        assert!(matches!(
            tip_height_hash(&tip),
            Err(TransportError::BadNodeData(_))
        ));
    }

    #[test]
    fn tip_height_hash_accepts_32_bytes() {
        let mut hash = vec![0u8; 32];
        hash[0] = 0xab;
        let tip = BlockHashAndHeight { hash, height: 7 };
        let (height, block_hash) = tip_height_hash(&tip).expect("32-byte hash");
        assert_eq!(height, BlockHeight::from_u32(7));
        assert_eq!(block_hash.0[31], 0xab);
    }

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

    #[test]
    fn block_requests_name_heights_as_four_big_endian_bytes() {
        // The protocol reads 32 bytes as a hash; four bytes must name a
        // height, or the fetch silently means something else.
        for (height, wire) in [
            (BlockHeight::from_u32(0), vec![0, 0, 0, 0]),
            (BlockHeight::from_u32(1), vec![0, 0, 0, 1]),
            (BlockHeight::from_u32(1000), vec![0, 0, 3, 232]),
            (BlockHeight::from_u32(u32::MAX), vec![255, 255, 255, 255]),
        ] {
            assert_eq!(block_request_at_height(height).hash_or_height, wire);
        }
    }

    /// Upstream's own mainnet block fixture (zcash_primitives 0.30.1,
    /// src/block.rs): the real consensus encoding, whose coinbase carries
    /// the height in its scriptSig — no synthetic block survives
    /// `Block::read`.
    const BLOCK_MAINNET_415000: [u8; 1640] = [
        0x04, 0x00, 0x00, 0x00, 0x52, 0x74, 0xb4, 0x3b, 0x9e, 0x4a, 0xd8, 0xf4, 0x3e, 0x93, 0xf7,
        0x84, 0x63, 0xd2, 0x4d, 0xcf, 0xe5, 0x31, 0xae, 0xb4, 0x71, 0x98, 0x19, 0xf4, 0xf9, 0x7f,
        0x7e, 0x03, 0x00, 0x00, 0x00, 0x00, 0x66, 0x30, 0x73, 0xbc, 0x4b, 0xfa, 0x95, 0xc9, 0xbe,
        0xc3, 0x6a, 0xad, 0x72, 0x68, 0xa5, 0x73, 0x04, 0x97, 0x97, 0xbd, 0xfc, 0x5a, 0xa4, 0xc7,
        0x43, 0xfb, 0xe4, 0x82, 0x0a, 0xa3, 0x93, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xbe, 0xcc, 0x5b, 0xe1,
        0xab, 0x03, 0x1c, 0xc2, 0xfd, 0x60, 0x7c, 0x77, 0x6a, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x3e, 0xb2, 0x18, 0x19, 0xfd, 0x40, 0x05, 0x00, 0x94, 0x9d, 0x55, 0xde, 0x0c, 0xc6,
        0x33, 0xe0, 0xcc, 0xe4, 0x1e, 0x46, 0x49, 0xef, 0x4a, 0xa3, 0x34, 0x9f, 0x01, 0x00, 0x29,
        0x0f, 0xfe, 0x28, 0x1b, 0x94, 0x7b, 0x3b, 0x53, 0xfb, 0xd2, 0xf3, 0x5b, 0x1c, 0xe2, 0x92,
        0x64, 0x9b, 0x96, 0xac, 0x6e, 0x08, 0x83, 0xaf, 0x3a, 0x68, 0x44, 0xb9, 0x55, 0x92, 0xe7,
        0x45, 0x56, 0xda, 0x34, 0x4b, 0x47, 0x01, 0x96, 0x1c, 0xd4, 0x13, 0x0c, 0x68, 0x21, 0x9c,
        0xfa, 0x13, 0x41, 0xd5, 0xaf, 0xb5, 0x04, 0x9e, 0xb0, 0xe8, 0xbe, 0x4a, 0x2d, 0x92, 0xd6,
        0x78, 0xc4, 0x07, 0x85, 0xe3, 0x37, 0x05, 0x54, 0x8b, 0x5f, 0x3a, 0x54, 0xf0, 0xa4, 0xc3,
        0x9a, 0x2f, 0x58, 0xee, 0x78, 0x4a, 0x24, 0x16, 0x3c, 0xd8, 0x6f, 0x54, 0x81, 0x23, 0x27,
        0xdf, 0x55, 0xe1, 0xd5, 0x5c, 0xa8, 0x4b, 0x6e, 0x7b, 0x88, 0x7a, 0x7c, 0xbf, 0xb9, 0x09,
        0x1a, 0x58, 0x5b, 0xdb, 0x8e, 0xa4, 0x75, 0x93, 0x07, 0xc5, 0x6c, 0x1b, 0x3d, 0xaf, 0xc6,
        0x69, 0x24, 0x5a, 0x6f, 0x65, 0x4b, 0x6f, 0x73, 0x00, 0x52, 0x26, 0x6a, 0x01, 0xad, 0x4f,
        0x9c, 0x0b, 0x59, 0xed, 0x4e, 0x17, 0x71, 0x2b, 0x3e, 0x72, 0xdf, 0x04, 0x98, 0xaa, 0x8d,
        0xe4, 0x88, 0x8f, 0x99, 0x35, 0x31, 0xc6, 0x0a, 0xcd, 0xed, 0x1d, 0x4b, 0x66, 0xe8, 0x9d,
        0xe0, 0xb6, 0x48, 0x2c, 0xcc, 0xd4, 0xa7, 0x12, 0xf5, 0xcf, 0x9d, 0x4c, 0xa8, 0x3b, 0xe0,
        0xf9, 0x22, 0xde, 0x2c, 0x1d, 0xbb, 0x3a, 0x14, 0x07, 0x48, 0x0d, 0xbe, 0x87, 0x95, 0x99,
        0x3d, 0x8b, 0xe6, 0x40, 0x98, 0x8a, 0xbf, 0xe7, 0xa8, 0xa1, 0xb3, 0x3a, 0x12, 0x13, 0x1c,
        0x45, 0x1e, 0x1a, 0xbc, 0x0d, 0x83, 0xfb, 0x85, 0x18, 0x62, 0xc6, 0x37, 0xce, 0x72, 0x4d,
        0x5f, 0xe9, 0x7a, 0xa9, 0xa8, 0x06, 0xcf, 0x34, 0xba, 0xb5, 0x09, 0xf4, 0x55, 0x4b, 0x0c,
        0xd1, 0x0a, 0x7d, 0xdf, 0xd5, 0x82, 0x1b, 0x09, 0x1a, 0xd2, 0xc9, 0x0c, 0x1a, 0xa1, 0xd8,
        0x1e, 0xb3, 0xd7, 0x2d, 0xb4, 0x19, 0x93, 0xb6, 0x48, 0xf4, 0x1e, 0x21, 0x38, 0xff, 0x95,
        0x31, 0xa3, 0x0f, 0xf7, 0x3b, 0x22, 0x14, 0x0e, 0x4e, 0xbd, 0x7b, 0xaa, 0x33, 0x84, 0x8e,
        0x51, 0x2d, 0x99, 0x30, 0x0c, 0x5c, 0x13, 0x1c, 0x6e, 0x75, 0xf5, 0x71, 0x4a, 0x5c, 0x6d,
        0xcb, 0x17, 0x8b, 0x4a, 0x49, 0x78, 0xda, 0xc8, 0x3a, 0xd4, 0x12, 0xfb, 0xd6, 0x92, 0x01,
        0x92, 0x50, 0xc5, 0x53, 0x04, 0x9a, 0xad, 0x45, 0x79, 0x84, 0xbe, 0xdf, 0xc9, 0x6a, 0xe7,
        0x01, 0xc6, 0x59, 0xbc, 0x70, 0x07, 0xa9, 0x7d, 0x0a, 0x90, 0x02, 0xb9, 0x45, 0xbd, 0xec,
        0x45, 0xa9, 0x45, 0xef, 0x62, 0x85, 0xb2, 0xcd, 0x55, 0x3b, 0x4c, 0x09, 0xd9, 0x07, 0xc6,
        0x27, 0x86, 0x3f, 0x03, 0x99, 0xe8, 0x72, 0x5b, 0x4f, 0xf7, 0xfc, 0x59, 0x79, 0xe3, 0xcf,
        0xf2, 0x28, 0x14, 0x50, 0x84, 0x48, 0xef, 0x8b, 0x98, 0x31, 0xc2, 0x85, 0x95, 0x93, 0x33,
        0x39, 0x6a, 0xa3, 0x62, 0xa5, 0x1c, 0xf2, 0x05, 0x09, 0x7a, 0xfa, 0xbe, 0xc1, 0x5e, 0x41,
        0xfb, 0x6e, 0x30, 0xb6, 0x22, 0x37, 0x4b, 0xf5, 0x8b, 0x37, 0xef, 0x9d, 0x1b, 0x24, 0x1e,
        0xad, 0x5a, 0x68, 0x2b, 0x98, 0xb6, 0x57, 0x49, 0xa5, 0x75, 0x68, 0xe2, 0x38, 0xd5, 0x0a,
        0xfd, 0x41, 0x7e, 0x1e, 0x96, 0x0e, 0x7b, 0x5a, 0x06, 0x4f, 0xd9, 0xf6, 0x94, 0xd7, 0x83,
        0xa2, 0xcb, 0xcd, 0x58, 0x55, 0x2d, 0xed, 0xbb, 0x9e, 0x5e, 0x11, 0x23, 0x67, 0x4e, 0xf7,
        0x3a, 0x52, 0x41, 0x96, 0xcf, 0x05, 0xd3, 0xe5, 0x24, 0x66, 0x05, 0x49, 0xff, 0xe7, 0xbd,
        0x65, 0x68, 0x05, 0x71, 0x35, 0xff, 0xd5, 0xaf, 0xd9, 0x43, 0xf6, 0xda, 0x11, 0xcb, 0xb5,
        0x97, 0xe8, 0xcc, 0xec, 0xd7, 0x7e, 0xcb, 0xe9, 0x09, 0xde, 0x06, 0x31, 0xbf, 0xa2, 0x9c,
        0xd3, 0xe3, 0xd5, 0x54, 0x46, 0x71, 0xba, 0x80, 0x25, 0x61, 0x53, 0xd6, 0xe9, 0x99, 0x0b,
        0x88, 0xad, 0x8e, 0x0c, 0xf4, 0x98, 0x9b, 0xef, 0x4b, 0xe4, 0x57, 0xf9, 0xc7, 0xb0, 0xf1,
        0xaa, 0xcd, 0x6e, 0x0e, 0xf3, 0x20, 0x60, 0x5c, 0x29, 0xed, 0x0c, 0xd2, 0xeb, 0x6c, 0xfc,
        0xe2, 0x16, 0xc5, 0x2a, 0x31, 0x75, 0x80, 0x20, 0x1c, 0xad, 0x7a, 0x09, 0x43, 0xd2, 0x4b,
        0x7b, 0x06, 0xd5, 0xbf, 0x75, 0x87, 0x61, 0xdd, 0x96, 0xe1, 0x19, 0x70, 0xb5, 0xde, 0xd6,
        0x97, 0x22, 0x2b, 0x2c, 0x77, 0xe7, 0xf2, 0x56, 0xa6, 0x05, 0xac, 0x75, 0x55, 0x49, 0xc1,
        0x65, 0x1f, 0x25, 0xad, 0xfc, 0x9d, 0x53, 0xd9, 0x11, 0x7e, 0x3a, 0x0b, 0xb4, 0x09, 0xee,
        0xe4, 0xa6, 0x00, 0x12, 0x04, 0x72, 0x94, 0x9c, 0x7d, 0xda, 0x1c, 0x2e, 0xdb, 0x3c, 0x33,
        0x0c, 0x7f, 0x96, 0x17, 0x99, 0x82, 0x91, 0x64, 0x57, 0xd3, 0x31, 0xe9, 0x63, 0x09, 0xdd,
        0x24, 0xdf, 0x74, 0xee, 0xdd, 0x00, 0xe7, 0xdb, 0x49, 0x7e, 0xe1, 0x30, 0xf7, 0x7d, 0xe6,
        0x66, 0xeb, 0x55, 0x7f, 0xb3, 0x16, 0xe8, 0x7a, 0xda, 0xf1, 0x81, 0x3c, 0xe4, 0x26, 0xa4,
        0x58, 0xa6, 0xee, 0xe3, 0xa8, 0x5b, 0x2a, 0xb8, 0x8f, 0x65, 0x53, 0xaa, 0xda, 0xe8, 0xde,
        0x65, 0x2e, 0x21, 0x1a, 0x1d, 0x9f, 0x33, 0x4d, 0x59, 0x6b, 0x5e, 0xb6, 0x17, 0x34, 0x07,
        0xef, 0xcc, 0x2e, 0x81, 0x54, 0xbb, 0x9c, 0xa1, 0x21, 0x2a, 0xa9, 0xa1, 0xa1, 0x12, 0x1d,
        0x2f, 0x5a, 0x77, 0x12, 0xcf, 0x25, 0xcc, 0x81, 0x48, 0xb8, 0x05, 0x2e, 0x0d, 0x2e, 0x09,
        0xf2, 0x0e, 0x5b, 0xa2, 0xa9, 0x82, 0x77, 0xe9, 0x75, 0xb0, 0xee, 0xd9, 0xa8, 0x92, 0x06,
        0x96, 0x63, 0x37, 0x16, 0x3f, 0x21, 0x5c, 0x9d, 0x04, 0xa6, 0x59, 0x8b, 0x09, 0x58, 0xd3,
        0x33, 0xd8, 0x46, 0x77, 0x3c, 0x69, 0xe5, 0xab, 0xfd, 0x0a, 0x04, 0x27, 0xf3, 0x66, 0x06,
        0x14, 0xdd, 0x82, 0xb7, 0x9a, 0xdb, 0x85, 0x1a, 0x0d, 0x58, 0xb6, 0x2d, 0xf5, 0xf0, 0xb3,
        0xac, 0x83, 0x6e, 0x6e, 0x25, 0xf3, 0xa5, 0x1f, 0x49, 0xa9, 0x9a, 0xde, 0x57, 0x79, 0x6f,
        0xe9, 0xfc, 0xc2, 0x6f, 0x0a, 0x1f, 0x94, 0xff, 0x08, 0x19, 0xfe, 0x52, 0xb7, 0x50, 0x87,
        0xed, 0xbe, 0xd3, 0xa8, 0x16, 0x26, 0xeb, 0x54, 0x16, 0xc6, 0x65, 0x57, 0xf1, 0x1c, 0x0f,
        0xce, 0xdf, 0xf2, 0x23, 0xd6, 0xaa, 0x8c, 0xd5, 0xc3, 0x53, 0x86, 0xe5, 0xb4, 0xb9, 0x5a,
        0x0f, 0x03, 0x92, 0xca, 0x30, 0x1a, 0x38, 0xb3, 0x68, 0x7d, 0x09, 0x44, 0x93, 0xb9, 0xe9,
        0xd2, 0x64, 0xd0, 0x7a, 0x19, 0x0c, 0xe5, 0x7d, 0x11, 0x68, 0x04, 0x38, 0x2a, 0x3f, 0xab,
        0xe1, 0x5a, 0xf4, 0xdf, 0x4f, 0xa0, 0x43, 0xf0, 0x28, 0x7a, 0xa1, 0xed, 0x55, 0x68, 0xd9,
        0xef, 0x5d, 0x12, 0x51, 0x0d, 0x01, 0x0c, 0xcd, 0xab, 0x4e, 0xb6, 0x16, 0xf6, 0xdf, 0x13,
        0xbb, 0x31, 0x26, 0xef, 0x43, 0xd9, 0xd6, 0x57, 0x35, 0xe4, 0xe4, 0xc0, 0x4b, 0x57, 0x63,
        0x48, 0xd0, 0x40, 0xb5, 0x35, 0x05, 0x5a, 0x3d, 0x5a, 0xe1, 0x91, 0xb7, 0x5f, 0x06, 0x12,
        0xf3, 0xb2, 0x40, 0x66, 0xa0, 0x52, 0x45, 0xf2, 0x7f, 0xe5, 0x7b, 0xda, 0x66, 0xbd, 0x6d,
        0xec, 0x7e, 0x4f, 0xc9, 0xcb, 0x23, 0x68, 0x02, 0x06, 0x2a, 0xdd, 0xe3, 0xcd, 0x0e, 0x31,
        0x34, 0x82, 0xc9, 0x2a, 0x0c, 0x72, 0x11, 0x02, 0xb1, 0xf3, 0x8b, 0x01, 0x5a, 0xb8, 0xd0,
        0x15, 0x59, 0xcb, 0xcb, 0x40, 0xf6, 0x74, 0xe9, 0xef, 0xad, 0x5e, 0xe9, 0xc2, 0xfe, 0x13,
        0x3f, 0xaa, 0x55, 0xca, 0x1d, 0xd0, 0xff, 0x26, 0x71, 0x0f, 0x9d, 0xa8, 0x19, 0xcc, 0x14,
        0x59, 0xcb, 0x7e, 0xd2, 0x60, 0xda, 0xd3, 0xdb, 0x05, 0x96, 0x25, 0x8d, 0x47, 0xc7, 0x4c,
        0x32, 0xa8, 0xb8, 0x52, 0xb6, 0x71, 0xc5, 0xa0, 0xca, 0xa2, 0x00, 0x16, 0x03, 0xd9, 0x0c,
        0x91, 0xa7, 0xdf, 0x2e, 0x2d, 0x4e, 0xe9, 0xae, 0x9b, 0xf1, 0xa6, 0xb1, 0xec, 0x88, 0x15,
        0x1c, 0x62, 0x36, 0x0d, 0x03, 0x02, 0x4d, 0x2e, 0x2d, 0x01, 0x14, 0x08, 0x4f, 0x6b, 0x88,
        0xc5, 0xbb, 0xa2, 0x4a, 0xa7, 0xce, 0xcf, 0xac, 0x16, 0xe9, 0x1e, 0x0b, 0xaf, 0x3d, 0x86,
        0x53, 0xe2, 0x18, 0x09, 0x3e, 0x81, 0xd2, 0xa6, 0x3c, 0x32, 0xef, 0xf1, 0xd9, 0x03, 0x0f,
        0x9e, 0x14, 0x14, 0xec, 0xe4, 0x20, 0xda, 0xa2, 0x4e, 0x0d, 0xd5, 0xb8, 0x45, 0xb3, 0x27,
        0x4b, 0xb8, 0x39, 0xca, 0x1c, 0x53, 0xbc, 0xc0, 0x19, 0x42, 0x42, 0xd7, 0x4b, 0x26, 0x31,
        0xb9, 0x49, 0x5a, 0x65, 0x4f, 0xbb, 0xdc, 0xbf, 0xad, 0x77, 0x9f, 0x73, 0x22, 0xb6, 0x07,
        0x36, 0x24, 0x98, 0x80, 0x60, 0x48, 0x21, 0xd9, 0x69, 0x24, 0xe3, 0xfa, 0x39, 0x7f, 0x35,
        0x4a, 0x5e, 0xcc, 0xa3, 0x4f, 0x61, 0x4d, 0xa5, 0x45, 0x6f, 0x9b, 0x36, 0x33, 0x8c, 0x37,
        0xd8, 0xf6, 0xfb, 0xf6, 0x26, 0xbe, 0x98, 0x34, 0x77, 0x76, 0x60, 0x22, 0x87, 0x27, 0x46,
        0xda, 0x10, 0xa1, 0x77, 0x1c, 0xeb, 0x02, 0xdd, 0x8a, 0xac, 0x01, 0xba, 0x18, 0x6b, 0xf1,
        0x48, 0x86, 0x30, 0x47, 0x9e, 0x12, 0x84, 0xda, 0x01, 0x90, 0xfc, 0xe8, 0xb5, 0x9a, 0xc6,
        0xb0, 0xfd, 0x41, 0x6b, 0xee, 0x56, 0xb7, 0x2f, 0x0a, 0x58, 0x45, 0x15, 0x35, 0x57, 0xff,
        0x0f, 0x49, 0x50, 0xa0, 0xdc, 0x5b, 0xe6, 0x5c, 0xe9, 0x42, 0xd2, 0x2e, 0x18, 0x53, 0x4c,
        0x4e, 0x0e, 0xfa, 0xbb, 0x2d, 0x15, 0x25, 0xdc, 0x48, 0x58, 0xb9, 0xb0, 0xf7, 0x7d, 0x47,
        0x4a, 0x12, 0x5e, 0xbc, 0x25, 0x0e, 0x08, 0xfe, 0xdb, 0xfa, 0xa6, 0x6f, 0x45, 0x3d, 0x90,
        0x93, 0x2c, 0xab, 0x3f, 0xf4, 0x52, 0x21, 0x90, 0x99, 0x68, 0xe5, 0x1e, 0x6b, 0xc2, 0x54,
        0xd5, 0x09, 0xad, 0xeb, 0x75, 0xcb, 0xa7, 0x6d, 0x48, 0xfe, 0x02, 0x4e, 0x3e, 0x66, 0xd8,
        0xdf, 0x5e, 0x01, 0x03, 0x00, 0x00, 0x80, 0x70, 0x82, 0xc4, 0x03, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
        0xff, 0xff, 0xff, 0x1a, 0x03, 0x18, 0x55, 0x06, 0x15, 0x2f, 0x56, 0x69, 0x61, 0x42, 0x54,
        0x43, 0x2f, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x2f,
        0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0xca, 0x9a, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76,
        0xa9, 0x14, 0xfb, 0x8a, 0x6a, 0x4c, 0x11, 0xcb, 0x21, 0x6c, 0xe2, 0x1f, 0x9f, 0x37, 0x1d,
        0xfc, 0x92, 0x71, 0xa4, 0x69, 0xbd, 0x6d, 0x88, 0xac, 0x80, 0xb2, 0xe6, 0x0e, 0x00, 0x00,
        0x00, 0x00, 0x17, 0xa9, 0x14, 0xe0, 0xa5, 0xea, 0x13, 0x40, 0xcc, 0x6b, 0x1d, 0x6a, 0x82,
        0xc0, 0x6c, 0x0a, 0x9c, 0x60, 0xb9, 0x89, 0x8b, 0x6a, 0xe9, 0x87, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn indexer_block_wire_parses_under_the_compiled_parameters() {
        let block = block_from_wire(
            &BLOCK_MAINNET_415000,
            &zcash_protocol::consensus::MAIN_NETWORK,
            BlockHeight::from_u32(415_000),
        )
        .expect("the real block parses");
        assert_eq!(block.claimed_height(), BlockHeight::from_u32(415_000));

        // The wire field is the consensus serialization: what we hand to
        // `Block::read` re-encodes to the very same bytes.
        let mut encoded = Vec::new();
        block.write(&mut encoded).expect("block writes");
        assert_eq!(&BLOCK_MAINNET_415000[..], &encoded[..]);
    }

    #[test]
    fn indexer_block_wire_refuses_another_height() {
        match block_from_wire(
            &BLOCK_MAINNET_415000,
            &zcash_protocol::consensus::MAIN_NETWORK,
            BlockHeight::from_u32(415_001),
        ) {
            Err(TransportError::BadNodeData(_)) => {}
            other => panic!("expected BadNodeData, got {other:?}"),
        }
    }
}
