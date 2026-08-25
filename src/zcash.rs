//! Zcash Chain I/O boundary for the mint.

use std::{any::type_name, fmt, time::Duration};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client as HyperClient};
use hyper_util::rt::TokioExecutor;
use incrementalmerkletree::frontier::Frontier;
use sapling::Node as SaplingNode;
use serde::{Deserialize, Serialize};
use time::Timestamp;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_primitives::block::{Block, BlockHash};
use zcash_primitives::merkle_tree::{read_commitment_tree, HashSer};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BranchId, BlockHeight, Parameters};
use zebra_indexer_proto::{BlockHashAndHeight, Empty, MempoolChangeKind, ZebraClient};

use orchard::tree::MerkleHashOrchard;

const ZEBRA_INDEXER_URL: &str = "http://127.0.0.1:8230";
const ZEBRA_JSON_RPC_URL: &str = "http://127.0.0.1:8232";

/// The mainnet genesis block hash, in `BlockHash` internal byte order.
pub const MAINNET_GENESIS_HASH: BlockHash = BlockHash([
    0x08, 0xce, 0x3d, 0x97, 0x31, 0xb0, 0x00, 0xc0, 0x83, 0x38, 0x45, 0x5c, 0x8a, 0x4a, 0x6b, 0xd0,
    0x5d, 0xa1, 0x6e, 0x26, 0xb1, 0x1d, 0xaa, 0x1b, 0x91, 0x71, 0x84, 0xec, 0xe8, 0x0f, 0x04, 0x00,
]);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// gRPC Chain Observer
// ============================================================================

/// A client for observing best-chain tip changes.
#[derive(Clone)]
pub struct ChainClient(ZebraClient);

impl ChainClient {
    pub(crate) async fn connect() -> Result<Self, tonic::transport::Error> {
        let endpoint = tonic::transport::Endpoint::from_static(ZEBRA_INDEXER_URL)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT);

        let client = ZebraClient::connect(endpoint).await?;
        Ok(Self(client))
    }

    /// Opens the gRPC stream of best-chain tip changes.
    pub async fn chain_tip_change_stream(
        &mut self,
    ) -> Result<tonic::codec::Streaming<BlockHashAndHeight>, TransportError> {
        self.0
            .chain_tip_change(Empty {})
            .await
            .map(|r| r.into_inner())
            .map_err(TransportError::from)
    }

    /// Opens the gRPC stream of mempool lifecycle changes as
    /// `(MempoolChangeKind, TxId)` pairs — the proto crate's typed layer
    /// plus this module's display-order → `TxId` reversal. The generated
    /// message type does not cross this module boundary.
    ///
    /// Items are `Result`: transport and decode failures surface as
    /// `Err(TransportError)`. An error is terminal — the stream yields
    /// nothing after it — so the caller's response to any `Err` is
    /// reconnect plus re-baseline. The server drops consumers whose reads
    /// stall beyond its send timeout, so a gap after a reconnect is a
    /// when, not an if: re-baseline with [`JsonRpc::get_raw_mempool`] and
    /// diff against the pending set.
    pub async fn mempool_events(
        &mut self,
    ) -> Result<impl Stream<Item = Result<(MempoolChangeKind, TxId), TransportError>>, TransportError>
    {
        let stream = self
            .0
            .mempool_change(Empty {})
            .await
            .map_err(TransportError::from)?
            .into_inner();

        Ok(stream.map(|result| {
            result.map_err(TransportError::from).and_then(|message| {
                let kind = message
                    .kind()
                    .ok_or(TransportError::BadNodeData("mempool change type"))?;
                let mut txid_bytes = [0u8; 32];
                txid_bytes.copy_from_slice(
                    message
                        .tx_hash_display_order()
                        .ok_or(TransportError::BadNodeData("mempool tx hash"))?,
                );
                txid_bytes.reverse();
                let txid = TxId::from_bytes(txid_bytes);
                Ok((kind, txid))
            })
        }))
    }
}

pub fn tip_height_hash(tip: &BlockHashAndHeight) -> (BlockHeight, BlockHash) {
    let height = BlockHeight::from_u32(tip.height);
    let hash = block_hash_from_display(&tip.hash).expect("invalid tip hash");
    (height, hash)
}

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

// ============================================================================
// JSON-RPC Client
// ============================================================================

/// Stateless JSON-RPC transport over plaintext HTTP/1.1 to the local Zebra node.
///
/// Each call fires one POST, collects the response, and returns. The
/// `hyper-util` legacy client pools connections internally, but we don't rely
/// on that — every call is independent. No TLS, no auth, no config: Zebra lives
/// in the same TEE and the URL is hardcoded.
///
/// **Body-first error handling:** The JSON-RPC envelope is parsed *before*
/// checking HTTP status. Zebra returns HTTP 500 with a JSON error body for
/// RPC-level rejections (Bitcoin Core convention). Checking status first would
/// treat every RPC error as an HTTP error and discard the structured error
/// message. This matches `zecd`'s approach.
#[derive(Clone)]
pub struct JsonRpc {
    client: HyperClient<HttpConnector, Full<Bytes>>,
}

impl JsonRpc {
    pub fn new() -> Self {
        let client = HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new());

        Self { client }
    }

    /// Fetches blockchain state info, used for boot-time cross-validation.
    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo, TransportError> {
        self.send_request("getblockchaininfo", [(); 0])
            .await?
            .ok_or(TransportError::BadNodeData(
                "getblockchaininfo returned null",
            ))
    }

    /// Fetches a best-chain block hash by height without parsing its block bytes.
    ///
    /// This is required for genesis identity checks: upstream [`Block::read`]
    /// intentionally rejects the genesis block because its coinbase input
    /// predates the BIP 34 height commitment.
    pub async fn get_block_hash(&self, height: BlockHeight) -> Result<BlockHash, TransportError> {
        let index = i32::try_from(u32::from(height))
            .map_err(|_| TransportError::BadNodeData("getblockhash height"))?;
        let hash_hex: String = self
            .send_request("getblockhash", [index])
            .await?
            .ok_or(TransportError::BadNodeData("getblockhash returned null"))?;

        let display_bytes =
            hex::decode(hash_hex).map_err(|_| TransportError::BadNodeData("getblockhash hex"))?;
        block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("getblockhash length"))
    }

    /// Fetches the shielded tree state for a block through Zebra JSON-RPC and
    /// returns it as the upstream [`ChainState`] value — the same type the
    /// run loop hands to `WalletWrite::put_blocks` as its connection point.
    pub async fn chain_state_at(
        &self,
        height: BlockHeight,
    ) -> Result<ChainState, TransportError> {
        let response: TreeStateResponse = self
            .send_request("z_gettreestate", [u32::from(height).to_string()])
            .await?
            .ok_or(TransportError::BadNodeData("z_gettreestate returned null"))?;

        chain_state_from_rpc_response(response)
    }

    /// Fetches a block header by height through Zebra JSON-RPC.
    ///
    /// Returns `(hash, height, time)` using proper upstream types. Used
    /// for cold-start MTP warmup and historical MTP lookups; during
    /// normal scan operation, `get_block` already provides the timestamp.
    pub async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<(BlockHash, BlockHeight, Timestamp), TransportError> {
        let response: BlockHeaderResponse = self
            .send_request("getblockheader", (u32::from(height).to_string(), true))
            .await?
            .ok_or(TransportError::BadNodeData("getblockheader returned null"))?;

        let display_bytes = hex::decode(&response.hash)
            .map_err(|_| TransportError::BadNodeData("getblockheader hash hex"))?;
        let hash = block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("getblockheader hash length"))?;

        let time = Timestamp::from_seconds(response.time as i64)
            .map_err(|_| TransportError::BadNodeData("getblockheader time"))?;

        Ok((hash, BlockHeight::from_u32(response.height), time))
    }

    /// Fetches a full block by height through Zebra JSON-RPC and parses it.
    ///
    /// This proves the node returned bytes that are structurally parseable under
    /// the boot-proven consensus parameters. Best-chain membership and full
    /// consensus validity remain Zebra's responsibility.
    pub async fn get_block<P: Parameters>(
        &self,
        network: &P,
        height: BlockHeight,
    ) -> Result<Block, TransportError> {
        let hex_str: String = self
            .send_request("getblock", (u32::from(height).to_string(), 0))
            .await?
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

    /// Fetches a transaction by ID — Zebra's `getrawtransaction` checks the
    /// mempool first, then the chain — parses it under the boot-proven
    /// consensus parameters, and returns it.
    ///
    /// `branch_id` is the consensus branch ID to parse under; callers should
    /// pass `BranchId::for_height(network, target_height)` for the block they
    /// expect the transaction to confirm in. It is only consulted for
    /// pre-v5 transaction versions; every transaction the mint produces or
    /// observes at NU6.3+ is v5/v6, where it is unused.
    ///
    /// `Ok(None)` means the transaction is in neither the mempool nor the
    /// chain (RPC -5): a normal outcome when racing an `Invalidated`
    /// event, not a transport failure.
    pub async fn get_raw_transaction(
        &self,
        branch_id: BranchId,
        txid: TxId,
    ) -> Result<Option<Transaction>, TransportError> {
        let txid_hex = txid.to_string();
        match self
            .send_request::<_, String>("getrawtransaction", (txid_hex, 0))
            .await
        {
            Ok(Some(hex_str)) => {
                let bytes = hex::decode(hex_str)
                    .map_err(|_| TransportError::BadNodeData("getrawtransaction hex"))?;
                let tx = Transaction::read(&bytes[..], branch_id)
                    .map_err(|_| TransportError::BadNodeData("getrawtransaction parse"))?;
                Ok(Some(tx))
            }
            Ok(None) => Ok(None),
            // "No information about the transaction" — racing a mempool
            // eviction or a chain reorg; indistinguishable from never-existed,
            // which is the caller's normal not-found case.
            Err(TransportError::Rpc(ref rpc)) if rpc.code == -5 => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetches every transaction ID currently in the mempool — the
    /// re-baseline snapshot after a [`ChainClient::mempool_events`]
    /// reconnect. Diff against the pending set: unseen IDs are `Added`,
    /// missing IDs are `Invalidated`.
    pub async fn get_raw_mempool(&self) -> Result<Vec<TxId>, TransportError> {
        let txids: Vec<String> = self
            .send_request("getrawmempool", [(); 0])
            .await?
            .ok_or(TransportError::BadNodeData("getrawmempool returned null"))?;

        txids
            .iter()
            .map(|hex| {
                TxId::from_hex(hex).ok_or(TransportError::BadNodeData("getrawmempool txid"))
            })
            .collect()
    }

    /// Broadcasts a signed raw transaction hex to the network and returns its transaction ID.
    pub async fn send(&self, raw_tx_hex: &str) -> Result<String, TransportError> {
        self.send_request("sendrawtransaction", [raw_tx_hex])
            .await?
            .ok_or(TransportError::BadNodeData(
                "sendrawtransaction returned null",
            ))
    }

    /// Fires one JSON-RPC POST at the local Zebra node and returns the result.
    ///
    /// Returns `Ok(None)` when the JSON-RPC response has no `result` field
    /// (i.e. the method legitimately returns null). Returns `Err` on transport
    /// failures, non-success HTTP status (after body parsing), or a JSON-RPC
    /// `error` object.
    async fn send_request<T: fmt::Debug + Serialize, R: fmt::Debug + for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: T,
    ) -> Result<Option<R>, TransportError> {
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: 0,
        };
        let body = serde_json::to_string(&req)?;

        let (status, body_bytes) = self.round_trip(body).await?;

        // Parse the JSON-RPC envelope regardless of HTTP status — Zebra returns
        // HTTP 500 with a JSON error body for RPC-level rejections (Bitcoin Core
        // convention). The body is always checked first; status is the fallback.
        let response: RpcResponse<R> = serde_json::from_slice(&body_bytes)
            .map_err(|_| TransportError::BadNodeData(type_name::<R>()))?;

        if let Some(error) = response.error {
            return Err(TransportError::Rpc(error));
        }

        if !status.is_success() {
            return Err(TransportError::HttpStatus(status.as_u16()));
        }

        Ok(response.result)
    }

    /// Opens a connection to the local Zebra node, performs a single HTTP/1.1
    /// POST, collects the response body, and returns.
    async fn round_trip(&self, body: String) -> Result<(http::StatusCode, Bytes), TransportError> {
        let request = Request::builder()
            .method("POST")
            .uri(ZEBRA_JSON_RPC_URL)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))?;

        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| TransportError::Timeout)??;

        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();

        Ok((status, body))
    }
}


/// The outcome of submitting a signed transaction to the node.
#[derive(Debug)]
pub enum SubmitOutcome {
    /// The node accepted the transaction.
    Accepted,
    /// The transaction was already in the chain (node returned -27).
    AlreadyInChain,
    /// The canonical tip changed between assembly and submission.
    TipChanged,
    /// The node returned a different txid than what we signed.
    TxIdMismatch { returned_txid: String },
    /// The node rejected the transaction (non-retryable error).
    Rejected(TransportError),
}

/// Read-only JSON-RPC capability for canonical block reconstruction.
///
/// The wrapped transport is private and this facade intentionally exposes no
/// raw-transaction lookup or submission method.
#[derive(Clone)]
pub struct CanonicalBlockSource(JsonRpc);

impl CanonicalBlockSource {
    pub fn new() -> Self {
        Self(JsonRpc::new())
    }

    /// Returns the exact `(height, hash)` pair for the current best-chain
    /// tip. Both values are parsed from a single `getblockchaininfo`
    /// response (see [`BlockchainInfo::canonical_tip`]), so callers cannot
    /// combine observations from different tips — the same tuple shape as
    /// the gRPC side's [`tip_height_hash`].
    pub async fn exact_tip(&self) -> Result<(BlockHeight, BlockHash), TransportError> {
        self.0.get_blockchain_info().await?.canonical_tip()
    }

    pub async fn get_block<P: Parameters>(
        &self,
        network: &P,
        height: BlockHeight,
    ) -> Result<Block, TransportError> {
        self.0.get_block(network, height).await
    }

    /// Verifies the canonical tip hasn't moved, then broadcasts a signed transaction.
    ///
    /// Returns [`SubmitOutcome`] for application-level results (accepted, rejected,
    /// tip changed) or `Err(TransportError)` for retryable transport failures.
    pub async fn submit_transaction(
        &self,
        hex: &str,
        expected_txid: &str,
        expected_height: BlockHeight,
        expected_hash: BlockHash,
    ) -> Result<SubmitOutcome, TransportError> {
        let (tip_height, tip_hash) = self.exact_tip().await?;
        if tip_height != expected_height || tip_hash != expected_hash {
            return Ok(SubmitOutcome::TipChanged);
        }
        match self.0.send(hex).await {
            Ok(returned_txid) if returned_txid == expected_txid => Ok(SubmitOutcome::Accepted),
            Ok(returned_txid) => Ok(SubmitOutcome::TxIdMismatch { returned_txid }),
            Err(TransportError::Rpc(ref rpc_err)) if rpc_err.is_tx_already_in_chain() => {
                Ok(SubmitOutcome::AlreadyInChain)
            }
            Err(e) if e.is_retryable() => Err(e),
            Err(e) => Ok(SubmitOutcome::Rejected(e)),
        }
    }
}

impl Default for CanonicalBlockSource {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// JSON-RPC Envelopes and Errors
// ============================================================================

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct RpcRequest<T> {
    jsonrpc: String,
    method: String,
    params: T,
    id: i32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct RpcResponse<T> {
    id: i64,
    jsonrpc: Option<String>,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RpcError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    /// Bitcoin Core / Zebra RPC error -27: transaction already in chain.
    pub fn is_tx_already_in_chain(&self) -> bool {
        self.code == -27
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("hyper-util client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("http error: {0}")]
    Http(#[from] http::Error),
    #[error("request timeout")]
    Timeout,
    #[error("HTTP {0}")]
    HttpStatus(u16),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("bad node data for {0}")]
    BadNodeData(&'static str),
    #[error("bad checkpoint: {0}")]
    BadCheckpoint(String),
    #[error("{0}")]
    Rpc(RpcError),
    #[error("gRPC status: {0}")]
    Tonic(#[from] tonic::Status),
}

impl TransportError {
    /// Whether repeating the same read can recover without trusting new data.
    ///
    /// Decode, checkpoint, request-construction, and RPC-semantic failures are
    /// fatal trust-path errors. Only connection/body transport failures,
    /// timeouts, and server-side HTTP availability failures are retried.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Client(_) | Self::Hyper(_) | Self::Timeout | Self::HttpStatus(500..=599)
        ) || matches!(self, Self::Tonic(status) if matches!(status.code(), tonic::Code::Unavailable))
    }
}

// ============================================================================
// Typed JSON-RPC Responses
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct BlockchainInfo {
    pub blocks: u32,
    pub bestblockhash: String,
}

impl BlockchainInfo {
    /// Parses the exact height/hash pair carried by this one response.
    ///
    /// Both values come from the same `getblockchaininfo` response — the
    /// one place this guarantee lives — so callers cannot combine
    /// observations from different tips.
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

#[derive(Debug, Deserialize)]
struct TreeStateResponse {
    height: u32,
    hash: String,
    time: u32,
    sapling: ShieldedTreeState,
    orchard: ShieldedTreeState,
    ironwood: Option<ShieldedTreeState>,
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

// ============================================================================
// ZNS Birthday Checkpoint
// ============================================================================

/// `z_gettreestate` parsed into the upstream [`ChainState`].
///
/// "No tree at this height yet" is normalized to an empty frontier, not an
/// `Option`: an absent Ironwood tree (pre-NU6.3 block) and an empty Ironwood
/// tree are the same value to every consumer — `Frontier::empty()`.
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

    // An absent `ironwood` section (zebra omits the key entirely for
    // blocks before NU6.3 activation) and an empty Ironwood tree are the
    // same value: `Frontier::empty()`. The boot checkpoint is fetched at
    // activation-1, exactly the height where zebra omits the key.
    let ironwood_tree = match response
        .ironwood
        .and_then(|state| state.commitments.final_state)
    {
        Some(hex) if !hex.is_empty() => decode_tree::<MerkleHashOrchard>(&hex, "Ironwood")?,
        _ => Frontier::empty(),
    };

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
