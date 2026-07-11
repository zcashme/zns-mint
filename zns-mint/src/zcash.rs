//! Zcash Blockchain I/O boundary for the mint.
//!
//! This module provides the clients for interacting with the Zebra node.
//! It defines two distinct clients to separate concerns:
//! - `ChainClient`: A streaming, stateful HTTP/2 gRPC client for observing chain state.
//! - `JsonRpc`: A stateless, point-in-time HTTP POST client for JSON-RPC requests.
//!
//! The [`submit`] submodule adds a stateful outbound layer on top of `JsonRpc`:
//! it broadcasts assembled transactions and tracks their lifecycle from submission
//! through confirmation or permanent failure.

pub mod submit;
pub use submit::{Origin, SubmissionState, Submitter};

use std::{any::type_name, fmt, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use incrementalmerkletree::frontier::CommitmentTree;
use sapling::Node as SaplingNode;
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::BlockMetadata;
use zcash_primitives::merkle_tree::{read_commitment_tree, HashSer};
use zcash_protocol::consensus::BlockHeight;
use zebra_indexer_proto::ZebraClient;

use orchard::tree::MerkleHashOrchard;

const ZEBRA_INDEXER_URL: &str = "http://127.0.0.1:8230";
const ZEBRA_JSON_RPC_URL: &str = "http://127.0.0.1:8232";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// gRPC Chain Observer
// ============================================================================

/// A client for reading best-chain blocks and tips.
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
pub(crate) struct JsonRpc {
    client: HyperClient<HttpConnector, Full<Bytes>>,
}

impl JsonRpc {
    pub(crate) fn new() -> Self {
        let client = HyperClient::builder(TokioExecutor::new())
            .build(HttpConnector::new());

        Self { client }
    }

    /// Fetches blockchain state info, used for boot-time cross-validation.
    pub(crate) async fn get_blockchain_info(&self) -> Result<BlockchainInfo, TransportError> {
        self.send_request("getblockchaininfo", [(); 0])
            .await?
            .ok_or(TransportError::BadNodeData("getblockchaininfo returned null"))
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

    /// Fetches the raw transaction hex for a given transaction ID.
    pub(crate) async fn raw(&self, txid_hex: &str) -> Result<String, TransportError> {
        self.send_request("getrawtransaction", (txid_hex, 0))
            .await?
            .ok_or(TransportError::BadNodeData("getrawtransaction returned null"))
    }

    /// Broadcasts a signed raw transaction hex to the network and returns its transaction ID.
    pub(crate) async fn send(&self, raw_tx_hex: &str) -> Result<String, TransportError> {
        self.send_request("sendrawtransaction", [raw_tx_hex])
            .await?
            .ok_or(TransportError::BadNodeData("sendrawtransaction returned null"))
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

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("hyper-util client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
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

// ============================================================================
// Typed JSON-RPC Responses
// ============================================================================

#[derive(Debug, Deserialize)]
pub(crate) struct BlockchainInfo {
    pub blocks: u32,
    pub bestblockhash: String,
}

#[derive(Debug, Deserialize)]
struct TreeStateResponse {
    height: u32,
    hash: String,
    time: u32,
    sapling: ShieldedTreeState,
    orchard: ShieldedTreeState,
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

pub(crate) struct CheckpointData {
    pub metadata: BlockMetadata,
    pub sapling_tree: CommitmentTree<SaplingNode, 32>,
    pub orchard_tree: CommitmentTree<MerkleHashOrchard, 32>,
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

        let expected_hash_bytes = hex::decode(&response.hash)
            .map_err(|_| TransportError::BadNodeData("invalid hash hex"))?;

        let expected_hash = crate::sync::scan::block_hash_from_display(&expected_hash_bytes)
            .ok_or(TransportError::BadNodeData("malformed 32-byte hash"))?;

        let metadata = BlockMetadata::from_parts(
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
        );

        Ok(Self {
            metadata,
            sapling_tree,
            orchard_tree,
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