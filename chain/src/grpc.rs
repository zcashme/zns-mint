//! lightwalletd gRPC client — connection + transaction broadcast.
//!

use orchard::tree::{Anchor, MerkleHashOrchard};
use thiserror::Error;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::{
    compact_formats::{CompactBlock, CompactTx},
    service::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
        GetMempoolTxRequest, RawTransaction, TxFilter,
    },
};
use zcash_primitives::merkle_tree::read_commitment_tree;

/// A raw, serialised Zcash transaction ready for broadcast.
pub type RawTx = Vec<u8>;

/// The lightwalletd `CompactTxStreamer` client over a tonic channel.
pub type LwdClient = CompactTxStreamerClient<Channel>;

/// Errors from talking to a lightwalletd endpoint — connection, RPC, and
/// orchard-tree-state decoding. Pure transport: no domain (scan/treasury)
/// concerns.
#[derive(Debug, Error)]
pub enum GrpcError {
    #[error("invalid lightwalletd url: {0}")]
    InvalidUrl(#[from] http::uri::InvalidUri),

    #[error("lightwalletd transport: {}", error_chain(.0))]
    Transport(#[from] tonic::transport::Error),

    #[error("{call}: {source}")]
    Rpc {
        call: &'static str,
        #[source]
        source: tonic::Status,
    },

    #[error("node rejected transaction (code {code}): {message}")]
    Rejected { code: i32, message: String },

    #[error("hex-decoding orchard tree state: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("decoding orchard tree state: {0}")]
    TreeDecode(#[from] std::io::Error),
}

/// `tonic::transport::Error`'s `Display` is a fixed, contextless string (e.g.
/// "transport error") — the actual cause (DNS failure, connection refused,
/// TLS handshake failure, ...) lives only in its `source()` chain. Join the
/// whole chain so the message is useful in logs.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(": ")
}

/// Connect to a lightwalletd endpoint over TLS (webpki roots).
pub async fn connect(url: &str) -> Result<LwdClient, GrpcError> {
    let endpoint = Channel::from_shared(url.to_owned())?
        .tls_config(ClientTlsConfig::new().with_webpki_roots())?;
    let channel = endpoint.connect().await?;
    Ok(CompactTxStreamerClient::new(channel))
}

/// Thin gRPC client that broadcasts raw transactions to a lightwalletd endpoint.
///
/// Cheaply cloneable (holds only the URL). A fresh connection is established per
/// broadcast, keeping it `Send + Sync` without a mutex — adequate for the
/// low-frequency minting path (one broadcast per name registration).
#[derive(Clone)]
pub struct GrpcClient {
    lwd_url: String,
}

impl GrpcClient {
    /// Create a client pointing at `lwd_url`
    /// (e.g. `"http://127.0.0.1:9067"` or `"https://zec.rocks:443"`).
    pub fn new(lwd_url: impl Into<String>) -> Self {
        GrpcClient {
            lwd_url: lwd_url.into(),
        }
    }

    /// Return the current chain tip height via `GetLatestBlock`.
    pub async fn tip_height(&self) -> Result<u32, GrpcError> {
        let mut client = connect(&self.lwd_url).await?;
        let block = client
            .get_latest_block(ChainSpec {})
            .await
            .map_err(|source| GrpcError::Rpc {
                call: "get_latest_block",
                source,
            })?
            .into_inner();
        Ok(block.height as u32)
    }

    /// Fetch the Orchard note-commitment-tree root at `height` for use as a
    /// spend anchor.
    pub async fn orchard_anchor(&self, height: u32) -> Result<Anchor, GrpcError> {
        let mut client = connect(&self.lwd_url).await?;
        let state = client
            .get_tree_state(BlockId {
                height: height as u64,
                hash: vec![],
            })
            .await
            .map_err(|source| GrpcError::Rpc {
                call: "get_tree_state",
                source,
            })?
            .into_inner();
        let bytes = hex::decode(state.orchard_tree.trim())?;
        let tree = read_commitment_tree::<MerkleHashOrchard, _, 32>(&bytes[..])?;
        Ok(Anchor::from(tree.root()))
    }

    /// Broadcast a serialised transaction via `SendTransaction`.
    pub async fn broadcast(&self, raw_tx: RawTx) -> Result<(), GrpcError> {
        let mut client = connect(&self.lwd_url).await?;
        let resp = client
            .send_transaction(RawTransaction {
                data: raw_tx,
                height: 0,
            })
            .await
            .map_err(|source| GrpcError::Rpc {
                call: "send_transaction",
                source,
            })?
            .into_inner();
        if resp.error_code != 0 {
            return Err(GrpcError::Rejected {
                code: resp.error_code,
                message: resp.error_message,
            });
        }
        Ok(())
    }

    /// Stream compact blocks in `[start, end]` (inclusive), all shielded pools.
    pub async fn block_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<tonic::Streaming<CompactBlock>, GrpcError> {
        let mut client = connect(&self.lwd_url).await?;
        let stream = client
            .get_block_range(BlockRange {
                start: Some(BlockId {
                    height: start as u64,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: end as u64,
                    hash: vec![],
                }),
                // empty = all shielded pools (callers filter to their pool of interest)
                pool_types: vec![],
            })
            .await
            .map_err(|source| GrpcError::Rpc {
                call: "get_block_range",
                source,
            })?
            .into_inner();
        Ok(stream)
    }

    /// Fetch the current mempool as a list of compact transactions.
    ///
    /// The caller is responsible for trial-decrypting and fetching full txs for
    /// any outputs of interest.
    pub async fn mempool_compact_txs(&self) -> Result<Vec<CompactTx>, GrpcError> {
        let mut client = connect(&self.lwd_url).await?;
        let mut stream = client
            .get_mempool_tx(GetMempoolTxRequest {
                exclude_txid_suffixes: vec![],
                // empty = legacy/all shielded pools
                pool_types: vec![],
            })
            .await
            .map_err(|source| GrpcError::Rpc {
                call: "get_mempool_tx",
                source,
            })?
            .into_inner();

        let mut out = Vec::new();
        while let Some(tx) = stream.message().await.map_err(|source| GrpcError::Rpc {
            call: "mempool stream",
            source,
        })? {
            out.push(tx);
        }
        Ok(out)
    }

    /// Fetch a transaction's raw serialised bytes by txid.
    pub async fn fetch_transaction(&self, txid: &[u8; 32]) -> Result<RawTx, GrpcError> {
        let mut client = connect(&self.lwd_url).await?;
        let raw = client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid.to_vec(),
            })
            .await
            .map_err(|source| GrpcError::Rpc {
                call: "get_transaction",
                source,
            })?
            .into_inner();
        Ok(raw.data)
    }

    /// Whether the chain (or mempool) knows `txid` — the mint-intent
    /// reconciliation probe. `Ok(false)` only for a definitive not-found;
    /// transport failures surface as errors so reconciliation can't mistake
    /// an outage for "the mint never landed".
    pub async fn transaction_exists(&self, txid: &[u8; 32]) -> Result<bool, GrpcError> {
        let mut client = connect(&self.lwd_url).await?;
        match client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid.to_vec(),
            })
            .await
        {
            Ok(_) => Ok(true),
            // lightwalletd's GetTransaction returns NotFound for any
            // getrawtransaction RPC error, including zcashd's "No such
            // mempool or main chain transaction" for a missing tx.
            Err(status) if status.code() == tonic::Code::NotFound => Ok(false),
            Err(source) => Err(GrpcError::Rpc {
                call: "get_transaction",
                source,
            }),
        }
    }
}
