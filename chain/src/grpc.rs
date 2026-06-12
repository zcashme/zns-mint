//! lightwalletd gRPC client — connection + transaction broadcast.
//!
//! Host owns its chain I/O now: this uses `zcash_client_backend`'s generated
//! `CompactTxStreamer` proto client over a tonic [`Channel`], replacing the
//! former `seer-sync` dependency. Plaintext for `http://` (a local regtest
//! zebrad/lightwalletd); TLS with webpki roots for `https://` (public servers).

use anyhow::{anyhow, bail, Context as _};
use orchard::tree::{Anchor, MerkleHashOrchard};
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec, RawTransaction,
    TxFilter,
};
use zcash_primitives::merkle_tree::read_commitment_tree;

/// A raw, serialised Zcash transaction ready for broadcast.
pub type RawTx = Vec<u8>;

/// The lightwalletd `CompactTxStreamer` client over a tonic channel.
pub type LwdClient = CompactTxStreamerClient<Channel>;

/// Connect to a lightwalletd endpoint.
///
/// TLS (webpki roots) for `https://`; plaintext otherwise, so a local regtest
/// `http://127.0.0.1:9067` needs no certificates.
pub async fn connect(url: &str) -> anyhow::Result<LwdClient> {
    let endpoint = Channel::from_shared(url.to_owned())
        .map_err(|e| anyhow!("invalid lwd url {url}: {e}"))?;
    let endpoint = if url.starts_with("https://") {
        endpoint
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .with_context(|| format!("tls config for {url}"))?
    } else {
        endpoint
    };
    let channel = endpoint
        .connect()
        .await
        .with_context(|| format!("connect to {url}"))?;
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

    /// Return the current chain tip height via `GetLatestBlock`.
    pub async fn tip_height(&self) -> anyhow::Result<u32> {
        let mut client = connect(&self.lwd_url).await?;
        let block = client
            .get_latest_block(ChainSpec {})
            .await
            .context("get_latest_block")?
            .into_inner();
        Ok(block.height as u32)
    }

    /// Fetch the Orchard note-commitment-tree root at `height` for use as a
    /// spend anchor.
    pub async fn orchard_anchor(&self, height: u32) -> anyhow::Result<Anchor> {
        let mut client = connect(&self.lwd_url).await?;
        let state = client
            .get_tree_state(BlockId { height: height as u64, hash: vec![] })
            .await
            .context("get_tree_state")?
            .into_inner();
        let bytes = hex::decode(state.orchard_tree.trim())
            .context("decode orchard tree")?;
        let tree = read_commitment_tree::<MerkleHashOrchard, _, 32>(&bytes[..])
            .context("read orchard tree")?;
        Ok(Anchor::from(tree.root()))
    }

    /// Broadcast a serialised transaction via `SendTransaction`.
    pub async fn broadcast(&self, raw_tx: RawTx) -> anyhow::Result<()> {
        let mut client = connect(&self.lwd_url).await?;
        let resp = client
            .send_transaction(RawTransaction { data: raw_tx, height: 0 })
            .await
            .context("send_transaction")?
            .into_inner();
        if resp.error_code != 0 {
            bail!(
                "node rejected tx (code {}): {}",
                resp.error_code,
                resp.error_message
            );
        }
        Ok(())
    }

    /// Whether the chain (or mempool) knows `txid` — the mint-intent
    /// reconciliation probe. `Ok(false)` only for a definitive not-found;
    /// transport failures surface as errors so reconciliation can't mistake
    /// an outage for "the mint never landed".
    pub async fn transaction_exists(&self, txid: &[u8; 32]) -> anyhow::Result<bool> {
        let mut client = connect(&self.lwd_url).await?;
        match client
            .get_transaction(TxFilter { block: None, index: 0, hash: txid.to_vec() })
            .await
        {
            Ok(_) => Ok(true),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(false),
            // lightwalletd wraps zebra's "no such transaction" in Unknown.
            Err(status)
                if status.message().contains("No such mempool or main chain transaction") =>
            {
                Ok(false)
            }
            Err(status) => Err(anyhow!("GetTransaction: {status}")),
        }
    }
}
