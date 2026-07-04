//! Zebra client construction.
//!
//! This module provides the clients for interacting with the Zebra node.
//! It defines two distinct clients to separate concerns:
//! - `ChainClient`: A streaming, stateful HTTP/2 gRPC client for observing chain state.
//! - `JsonRpc`: A stateless, point-in-time HTTP POST client for JSON-RPC requests.

use std::{any::type_name, fmt, fs, path::Path, time::Duration};

use incrementalmerkletree::frontier::CommitmentTree;
use reqwest::ClientBuilder;
use sapling::Node as SaplingNode;
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::BlockMetadata;
use zcash_primitives::{
    block::BlockHash,
    merkle_tree::{read_commitment_tree, HashSer},
};
use zcash_protocol::consensus::BlockHeight;
use zebra_indexer_proto::ZebraClient;

use orchard::tree::MerkleHashOrchard;

const ZEBRA_INDEXER_URL: &str = "http://light.zcash.me:8230";
const ZEBRA_JSON_RPC_URL: &str = "http://light.zcash.me:8232";
const CHECKPOINT_NETWORK: &str = "main";

// ============================================================================
// gRPC Chain Observer
// ============================================================================

#[derive(Clone)]
pub(crate) struct ChainClient(ZebraClient);

impl ChainClient {
    pub(crate) async fn connect() -> Self {
        Self(
            ZebraClient::connect(ZEBRA_INDEXER_URL)
                .await
                .expect("zebra indexer gRPC connect failed"),
        )
    }

    pub(crate) fn client(&mut self) -> &mut ZebraClient {
        &mut self.0
    }
}

// ============================================================================
// JSON-RPC Client
// ============================================================================

#[derive(Clone)]
pub(crate) struct JsonRpc {
    rpc: reqwest::Client,
}

impl JsonRpc {
    pub(crate) fn new() -> Self {
        let rpc = ClientBuilder::new()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("zebra JSON-RPC client construction failed");

        Self { rpc }
    }

    /// Fetches blockchain state info, used for boot-time cross-validation.
    pub(crate) async fn get_blockchain_info(&self) -> Result<BlockchainInfo, TransportError> {
        self.send_request("getblockchaininfo", [(); 0]).await
    }

    /// Fetches the shielded tree state for a block through Zebra JSON-RPC.
    pub(crate) async fn tree_state(
        &self,
        height: BlockHeight,
    ) -> Result<BirthdayCheckpoint, TransportError> {
        let response: TreeStateResponse = self
            .send_request("z_gettreestate", [u32::from(height).to_string()])
            .await?;

        BirthdayCheckpoint::from_rpc_response(response)
    }

    /// Loads the ZNS birthday checkpoint if it exists, otherwise creates it
    /// from the trusted in-TEE Zebra node.
    pub(crate) async fn load_or_create_birthday_checkpoint(
        &self,
        path: impl AsRef<Path>,
        height: BlockHeight,
    ) -> Result<BirthdayCheckpoint, TransportError> {
        let path = path.as_ref();
        if path.exists() {
            let checkpoint = BirthdayCheckpoint::read(path)?;
            checkpoint.validate_height(height)?;
            Ok(checkpoint)
        } else {
            let checkpoint = self.tree_state(height).await?;
            checkpoint.write(path)?;
            Ok(checkpoint)
        }
    }

    /// Fetches the raw transaction hex for a given transaction ID.
    pub(crate) async fn raw(&self, txid_hex: &str) -> Result<String, TransportError> {
        self.send_request("getrawtransaction", (txid_hex, 0)).await
    }

    /// Broadcasts a signed raw transaction hex to the network and returns its transaction ID.
    pub(crate) async fn send(&self, raw_tx_hex: &str) -> Result<String, TransportError> {
        self.send_request("sendrawtransaction", [raw_tx_hex]).await
    }

    async fn send_request_allow_null<T: fmt::Debug + Serialize>(
        &self,
        method: &str,
        params: T,
    ) -> Result<(), TransportError> {
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: 0,
        };

        let response = self
            .rpc
            .post(ZEBRA_JSON_RPC_URL)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&req)?)
            .send()
            .await?;

        let status = response.status();
        let body_bytes = response.bytes().await?;

        match status.as_u16() {
            200..300 => {
                let response: RpcResponse<serde_json::Value> = serde_json::from_slice(&body_bytes)
                    .map_err(|_| TransportError::BadNodeData(type_name::<T>()))?;

                if let Some(error) = response.error {
                    return Err(TransportError::Rpc(error));
                }
                Ok(())
            }
            100..200 | 300..400 => Err(TransportError::UnexpectedStatusCode(status.as_u16())),
            code => Err(TransportError::InvalidStatusCode(code)),
        }
    }

    async fn send_request<T: fmt::Debug + Serialize, R: fmt::Debug + for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, TransportError> {
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: 0,
        };

        let response = self
            .rpc
            .post(ZEBRA_JSON_RPC_URL)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&req)?)
            .send()
            .await?;

        let status = response.status();
        let body_bytes = response.bytes().await?;

        match status.as_u16() {
            200..300 => {
                let response: RpcResponse<R> = serde_json::from_slice(&body_bytes)
                    .map_err(|_| TransportError::BadNodeData(type_name::<R>()))?;

                match (response.error, response.result) {
                    (Some(error), _) => Err(TransportError::Rpc(error)),
                    (None, Some(result)) => Ok(result),
                    (None, None) => Err(TransportError::EmptyResponseBody),
                }
            }
            100..200 | 300..400 => Err(TransportError::UnexpectedStatusCode(status.as_u16())),
            code => Err(TransportError::InvalidStatusCode(code)),
        }
    }
}

// ============================================================================
// JSON-RPC Envelopes and Errors
// ============================================================================

// We hand-roll these narrow JSON-RPC 2.0 envelopes instead of pulling in `jsonrpsee`.
// For a TEE environment, we only need to serialize a few specific HTTP POST payloads,
// so avoiding the bloat keeps our footprint minimal and our security boundary auditable.

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
pub(crate) struct RpcError {
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
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("invalid status code: {0}")]
    InvalidStatusCode(u16),
    #[error("unexpected status code: {0}")]
    UnexpectedStatusCode(u16),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad node data for {0}")]
    BadNodeData(&'static str),
    #[error("bad checkpoint: {0}")]
    BadCheckpoint(String),
    #[error("empty response body")]
    EmptyResponseBody,
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

/// ZNS-owned checkpoint format for the scan birthday.
///
/// This mirrors the useful payload returned by Zebra's `z_gettreestate`, but it
/// is deliberately not the lightwalletd protobuf `TreeState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BirthdayCheckpoint {
    pub network: String,
    pub height: u32,
    pub hash: String,
    pub time: u32,
    pub sapling_final_state: String,
    pub orchard_final_state: String,
}

impl BirthdayCheckpoint {
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

        Ok(Self {
            network: CHECKPOINT_NETWORK.to_string(),
            height: response.height,
            hash: response.hash,
            time: response.time,
            sapling_final_state,
            orchard_final_state,
        })
    }

    fn read(path: &Path) -> Result<Self, TransportError> {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write(&self, path: &Path) -> Result<(), TransportError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub(crate) fn block_metadata(
        &self,
        expected_hash: BlockHash,
    ) -> Result<BlockMetadata, TransportError> {
        if self.network != CHECKPOINT_NETWORK {
            return Err(TransportError::BadCheckpoint(format!(
                "checkpoint network {} != {}",
                self.network, CHECKPOINT_NETWORK
            )));
        }

        if self.hash != expected_hash.to_string() {
            return Err(TransportError::BadCheckpoint(
                "checkpoint hash != Zebra block hash".to_string(),
            ));
        }

        let sapling_tree = decode_tree::<SaplingNode>(&self.sapling_final_state, "Sapling")?;
        let orchard_tree = decode_tree::<MerkleHashOrchard>(&self.orchard_final_state, "Orchard")?;

        Ok(BlockMetadata::from_parts(
            BlockHeight::from_u32(self.height),
            expected_hash,
            Some(
                sapling_tree
                    .size()
                    .try_into()
                    .map_err(|_| TransportError::BadCheckpoint("Sapling tree too large".into()))?,
            ),
            Some(
                orchard_tree
                    .size()
                    .try_into()
                    .map_err(|_| TransportError::BadCheckpoint("Orchard tree too large".into()))?,
            ),
        ))
    }

    fn validate_height(&self, expected: BlockHeight) -> Result<(), TransportError> {
        if self.height == u32::from(expected) {
            Ok(())
        } else {
            Err(TransportError::BadCheckpoint(format!(
                "checkpoint height {} != {}",
                self.height,
                u32::from(expected)
            )))
        }
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
