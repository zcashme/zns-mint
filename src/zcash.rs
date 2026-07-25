//! Zcash Blockchain I/O boundary for the mint.
//!
//! This module provides the clients for interacting with the Zebra node:
//! - `ChainClient`: a streaming HTTP/2 gRPC client for tip wake-ups.
//! - `CanonicalBlockSource`: read-only JSON-RPC capability for passive replay.
//! - `JsonRpc`: the underlying point-in-time JSON-RPC client, including
//!   transaction lookup and submission for a future Live owner.
//!
//! This module owns transport, not submission lifecycle state.

use std::{any::type_name, fmt, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client as HyperClient};
use hyper_util::rt::TokioExecutor;
use incrementalmerkletree::frontier::CommitmentTree;
use sapling::Node as SaplingNode;
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::BlockMetadata;
use zcash_primitives::block::{Block, BlockHash};
use zcash_primitives::merkle_tree::{read_commitment_tree, HashSer};
use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};
use zebra_indexer_proto::{BlockHashAndHeight, ZebraClient};

use orchard::tree::MerkleHashOrchard;

const ZEBRA_INDEXER_URL: &str = "http://127.0.0.1:8230";
const ZEBRA_JSON_RPC_URL: &str = "http://127.0.0.1:8232";

/// The mainnet genesis block hash, in `BlockHash` internal byte order.
///
/// Display-form RPC responses (e.g. `getblockchaininfo`) reverse these bytes.
/// This protocol constant is used as a secondary network-identity check at boot.
pub const MAINNET_GENESIS_HASH: BlockHash = BlockHash([
    0x08, 0xce, 0x3d, 0x97, 0x31, 0xb0, 0x00, 0xc0, 0x83, 0x38, 0x45, 0x5c, 0x8a, 0x4a, 0x6b,
    0xd0, 0x5d, 0xa1, 0x6e, 0x26, 0xb1, 0x1d, 0xaa, 0x1b, 0x91, 0x71, 0x84, 0xec, 0xe8, 0x0f,
    0x04, 0x00,
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

    pub fn client(&mut self) -> &mut ZebraClient {
        &mut self.0
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

/// One point-in-time Zebra best-chain identity.
///
/// Height and hash are parsed from the same `getblockchaininfo` response so
/// callers cannot accidentally combine observations from different tips.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTip {
    height: BlockHeight,
    hash: BlockHash,
}

impl CanonicalTip {
    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn hash(&self) -> BlockHash {
        self.hash
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

    /// Fetches the shielded tree state for a block through Zebra JSON-RPC.
    pub(crate) async fn get_checkpoint(
        &self,
        height: BlockHeight,
    ) -> Result<CheckpointData, TransportError> {
        let response: TreeStateResponse = self
            .send_request("z_gettreestate", [u32::from(height).to_string()])
            .await?
            .ok_or(TransportError::BadNodeData("z_gettreestate returned null"))?;

        CheckpointData::from_rpc_response(response)
    }

    /// Fetches a full block by height through Zebra JSON-RPC and parses it.
    ///
    /// This proves the node returned bytes that are structurally parseable as a
    /// Zcash mainnet block. Best-chain membership and full consensus validity
    /// remain Zebra's responsibility.
    pub async fn get_block(&self, height: BlockHeight) -> Result<Block, TransportError> {
        let hex_str: String = self
            .send_request("getblock", (u32::from(height).to_string(), 0))
            .await?
            .ok_or(TransportError::BadNodeData("getblock returned null"))?;

        let bytes =
            hex::decode(hex_str).map_err(|_| TransportError::BadNodeData("getblock hex"))?;
        let block = Block::read(&bytes[..], &MAIN_NETWORK)
            .map_err(|_| TransportError::BadNodeData("getblock parse"))?;
        if block.claimed_height() != height {
            return Err(TransportError::BadNodeData(
                "getblock returned the wrong height",
            ));
        }
        Ok(block)
    }

    /// Fetches the raw transaction hex for a given transaction ID.
    pub(crate) async fn raw(&self, txid_hex: &str) -> Result<String, TransportError> {
        self.send_request("getrawtransaction", (txid_hex, 0))
            .await?
            .ok_or(TransportError::BadNodeData(
                "getrawtransaction returned null",
            ))
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

impl Default for JsonRpc {
    fn default() -> Self {
        Self::new()
    }
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

    pub async fn exact_tip(&self) -> Result<CanonicalTip, TransportError> {
        self.0.get_blockchain_info().await?.canonical_tip()
    }

    pub async fn get_block(&self, height: BlockHeight) -> Result<Block, TransportError> {
        self.0.get_block(height).await
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

// We hand-roll these narrow JSON-RPC 2.0 envelopes instead of pulling in `jsonrpsee`.

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
        )
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
    pub fn canonical_tip(&self) -> Result<CanonicalTip, TransportError> {
        let display_bytes = hex::decode(&self.bestblockhash)
            .map_err(|_| TransportError::BadNodeData("bestblockhash hex"))?;
        let hash = block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("bestblockhash length"))?;

        Ok(CanonicalTip {
            height: BlockHeight::from_u32(self.blocks),
            hash,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TreeStateResponse {
    height: u32,
    hash: String,
    time: u32,
    sapling: ShieldedTreeState,
    orchard: ShieldedTreeState,
    /// Ironwood tree state. Absent in Zebra responses for pre-NU6.3 blocks.
    #[serde(default)]
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

/// Tree state parsed from Zebra's `z_gettreestate` JSON-RPC response.
///
/// `ironwood_tree` is `None` for blocks before NU6.3 activation — Zebra
/// omits the `ironwood` field entirely in the JSON response for pre-NU6.3
/// blocks.
pub struct CheckpointData {
    pub metadata: BlockMetadata,
    pub sapling_tree: CommitmentTree<SaplingNode, 32>,
    pub orchard_tree: CommitmentTree<MerkleHashOrchard, 32>,
    pub ironwood_tree: Option<CommitmentTree<MerkleHashOrchard, 32>>,
}

impl CheckpointData {
    fn from_rpc_response(response: TreeStateResponse) -> Result<Self, TransportError> {
        let sapling_final_state = response
            .sapling
            .commitments
            .final_state
            .ok_or(TransportError::BadNodeData("missing Sapling finalState"))?;
        let orchard_final_state = response
            .orchard
            .commitments
            .final_state
            .ok_or(TransportError::BadNodeData("missing Orchard finalState"))?;

        let sapling_tree = decode_tree::<SaplingNode>(&sapling_final_state, "Sapling")?;
        let orchard_tree = decode_tree::<MerkleHashOrchard>(&orchard_final_state, "Orchard")?;

        // Ironwood is optional: pre-NU6.3 blocks do not have an Ironwood tree.
        // Zebra may either omit the `ironwood` field entirely or return an empty
        // `finalState`. We treat both as "no Ironwood tree at this height".
        let ironwood_tree = response
            .ironwood
            .and_then(|state| state.commitments.final_state)
            .and_then(|hex_state| decode_tree::<MerkleHashOrchard>(&hex_state, "Ironwood").ok());

        let expected_hash_bytes = hex::decode(&response.hash)
            .map_err(|_| TransportError::BadNodeData("invalid hash hex"))?;

        let expected_hash = block_hash_from_display(&expected_hash_bytes)
            .ok_or(TransportError::BadNodeData("malformed 32-byte hash"))?;

        let ironwood_tree_size = ironwood_tree
            .as_ref()
            .map(|t| {
                t.size()
                    .try_into()
                    .map_err(|_| TransportError::BadCheckpoint("Ironwood tree too large".into()))
            })
            .transpose()?;

        let metadata =
            BlockMetadata::from_parts(
                BlockHeight::from_u32(response.height),
                expected_hash,
                Some(
                    sapling_tree.size().try_into().map_err(|_| {
                        TransportError::BadCheckpoint("Sapling tree too large".into())
                    })?,
                ),
                Some(
                    orchard_tree.size().try_into().map_err(|_| {
                        TransportError::BadCheckpoint("Orchard tree too large".into())
                    })?,
                ),
                ironwood_tree_size,
            );

        Ok(Self {
            metadata,
            sapling_tree,
            orchard_tree,
            ironwood_tree,
        })
    }
}

fn decode_tree<Node>(
    hex_state: &str,
    name: &'static str,
) -> Result<CommitmentTree<Node, 32>, TransportError>
where
    Node: HashSer,
{
    let bytes = hex::decode(hex_state).map_err(|e| {
        TransportError::BadCheckpoint(format!("{name} tree hex decode failed: {e}"))
    })?;

    read_commitment_tree::<Node, _, 32>(&bytes[..])
        .map_err(|e| TransportError::BadCheckpoint(format!("{name} tree decode failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_tip_keeps_one_checked_height_hash_pair() {
        let info = BlockchainInfo {
            blocks: 42,
            bestblockhash:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    .to_owned(),
        };

        let tip = info.canonical_tip().expect("valid display-order hash");
        assert_eq!(tip.height(), BlockHeight::from_u32(42));
        assert_eq!(
            tip.hash(),
            BlockHash([
                0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06,
                0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            ])
        );
    }

    #[test]
    fn canonical_tip_rejects_malformed_hashes() {
        for bestblockhash in ["zz".to_owned(), "00".to_owned(), "00".repeat(33)] {
            let info = BlockchainInfo {
                blocks: 42,
                bestblockhash,
            };
            assert!(matches!(
                info.canonical_tip(),
                Err(TransportError::BadNodeData(_))
            ));
        }
    }

    #[test]
    fn mainnet_genesis_hash_matches_display_form() {
        let display = "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";
        let bytes = hex::decode(display).expect("valid hex");
        let from_display = block_hash_from_display(&bytes).expect("valid 32-byte hash");
        assert_eq!(from_display, MAINNET_GENESIS_HASH);
    }
}
