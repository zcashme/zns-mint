//! lightwalletd gRPC client — connection + transaction broadcast.
//!
//! Host owns its chain I/O now: this uses `zcash_client_backend`'s generated
//! `CompactTxStreamer` proto client over a tonic [`Channel`], replacing the
//! former `seer-sync` dependency. Plaintext for `http://` (a local regtest
//! zebrad/lightwalletd); TLS with webpki roots for `https://` (public servers).

use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction,
};

use zns_core::RegistryError;

/// gRPC endpoint for a local zebrad node (default for regtest).
pub const DEFAULT_GRPC_ADDR: &str = "http://127.0.0.1:9067";

/// A raw, serialised Zcash transaction ready for broadcast.
pub type RawTx = Vec<u8>;

/// The lightwalletd `CompactTxStreamer` client over a tonic channel.
pub type LwdClient = CompactTxStreamerClient<Channel>;

/// Connect to a lightwalletd endpoint.
///
/// TLS (webpki roots) for `https://`; plaintext otherwise, so a local regtest
/// `http://127.0.0.1:9067` needs no certificates.
pub async fn connect(url: &str) -> Result<LwdClient, RegistryError> {
    let endpoint = Channel::from_shared(url.to_owned())
        .map_err(|e| RegistryError::Broadcast(format!("invalid lwd url {url}: {e}")))?;
    let endpoint = if url.starts_with("https://") {
        endpoint
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .map_err(|e| RegistryError::Broadcast(format!("tls config for {url}: {e}")))?
    } else {
        endpoint
    };
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| RegistryError::Broadcast(format!("connect to {url}: {e}")))?;
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
        GrpcClient { lwd_url: lwd_url.into() }
    }

    /// Create a client pointing at the default local zebrad/regtest endpoint.
    pub fn default_local() -> Self {
        Self::new(DEFAULT_GRPC_ADDR)
    }

    /// Broadcast a serialised transaction via `SendTransaction`.
    ///
    /// Returns [`RegistryError::Broadcast`] if the connection fails or the node
    /// returns a non-zero `errorCode`.
    pub async fn broadcast(&self, raw_tx: RawTx) -> Result<(), RegistryError> {
        let mut client = connect(&self.lwd_url).await?;
        let resp = client
            .send_transaction(RawTransaction { data: raw_tx, height: 0 })
            .await
            .map_err(|e| RegistryError::Broadcast(e.to_string()))?
            .into_inner();
        if resp.error_code != 0 {
            return Err(RegistryError::Broadcast(format!(
                "node rejected tx (code {}): {}",
                resp.error_code, resp.error_message
            )));
        }
        Ok(())
    }
}
