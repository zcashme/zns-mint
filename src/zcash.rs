//! The seam between the mint and its Zebra full node.
//!
//! One node, two dialects: gRPC streams announce change, JSON-RPC answers
//! questions. The files are the conversations — the chain, the mempool,
//! submission — and this root is what they share: the error policy, the wire
//! machinery, and the display-order decoding. The node's identity is not on
//! the wire: it is the SEV-SNP measurement of the image this process lives in.

pub mod chain;
pub mod mempool;
pub mod submit;

pub use chain::{tip_height_hash, BlockchainInfo, ChainClient};
pub use submit::SubmitOutcome;

use std::{any::type_name, fmt, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client as HyperClient};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};

/// The wait between retries of a retryable transport call.
pub const RETRY_PAUSE: Duration = Duration::from_secs(5);

pub(crate) const ZEBRA_INDEXER_URL: &str = "http://127.0.0.1:8230";
pub(crate) const ZEBRA_JSON_RPC_URL: &str = "http://127.0.0.1:8232";

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// The JSON-RPC dialect — one type, impls in every conversation file
// ============================================================================

/// A stateless JSON-RPC transport: one POST per call to the local Zebra.
#[derive(Clone)]
pub struct JsonRpc {
    client: HyperClient<HttpConnector, Full<Bytes>>,
}

impl JsonRpc {
    /// One client for one node — plaintext HTTP, no TLS, no auth, no config.
    pub fn new() -> Self {
        let client = HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new());

        Self { client }
    }

    /// Fires one JSON-RPC POST and returns the result.
    ///
    /// `Ok(None)` means the method legitimately returned null.
    pub(crate) async fn send_request<
        T: fmt::Debug + Serialize,
        R: fmt::Debug + for<'de> Deserialize<'de>,
    >(
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
        // Serializing our own envelope cannot fail: every param type we send
        // has infallible Serialize.
        let body = serde_json::to_string(&req).expect("serializing our own request cannot fail");

        let (status, body_bytes) = self.round_trip(body).await?;

        // Parse the envelope regardless of HTTP status; status is the
        // fallback, never the first word.
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

    /// One connection, one POST, one collected body.
    async fn round_trip(&self, body: String) -> Result<(http::StatusCode, Bytes), TransportError> {
        // The request is entirely static, so building it cannot fail.
        let request = Request::builder()
            .method("POST")
            .uri(ZEBRA_JSON_RPC_URL)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .expect("building the static request cannot fail");

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

// ============================================================================
// The orchestrator's handle — impls in every conversation file
// ============================================================================

/// The orchestrator's view of the node: canonical reads and the one place a
/// transaction is ever broadcast.
#[derive(Clone)]
pub struct CanonicalBlockSource(pub(crate) JsonRpc);

impl CanonicalBlockSource {
    /// Same transport, same hardcoded node — a view, not a connection.
    pub fn new() -> Self {
        Self(JsonRpc::new())
    }
}

impl Default for CanonicalBlockSource {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Envelopes and the error policy
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

/// A JSON-RPC error object, as answered by the node.
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

/// Maps the node's -8 rejection to [`TransportError::NotOnBestChain`], so a
/// tip race never reads as malformed data.
pub(crate) fn not_on_best_chain(error: TransportError) -> TransportError {
    match error {
        TransportError::Rpc(ref rpc) if rpc.code == -8 => TransportError::NotOnBestChain,
        error => error,
    }
}

/// Everything that can go wrong talking to the node, classified once.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("hyper-util client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("request timeout")]
    Timeout,
    #[error("HTTP {0}")]
    HttpStatus(u16),
    #[error("bad node data for {0}")]
    BadNodeData(&'static str),
    #[error("bad checkpoint: {0}")]
    BadCheckpoint(String),
    /// The node's answer that the requested hash or height is not on its
    /// current best chain — a tip race, not bad data and not transport.
    #[error("hash or height is not on the node's current best chain")]
    NotOnBestChain,
    #[error("{0}")]
    Rpc(RpcError),
    #[error("gRPC status: {0}")]
    Tonic(#[from] tonic::Status),
}

impl TransportError {
    /// Whether repeating the same read can recover without trusting new data.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Client(_) | Self::Hyper(_) | Self::Timeout | Self::HttpStatus(500..=599)
        ) || matches!(self, Self::Tonic(status) if matches!(status.code(), tonic::Code::Unavailable))
    }
}
