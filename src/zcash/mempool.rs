//! The mempool: what is pending, where our broadcasts stand.

use std::pin::Pin;

use futures_util::{Stream, StreamExt};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;
use zebra_indexer_proto::{Empty, MempoolChangeKind};

use super::{chain::ChainClient, JsonRpc, TransportError};

impl ChainClient {
    /// Opens the gRPC stream of mempool changes as `(MempoolChangeKind, TxId)`
    /// pairs.
    ///
    /// `Added` fires on verification into the mempool, `Mined` on mining into
    /// a best-chain block, and `Invalidated` on removal by a mined spend
    /// conflict or by expiry at the new tip. The mined id equals the `TxId`
    /// for every transaction version the mint builds; the auth digest is
    /// discarded. Reorgs emit nothing for transactions that were in abandoned
    /// blocks. Stream endings — silent or errored — mean reconnect, then
    /// re-baseline with [`JsonRpc::get_raw_mempool`].
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

impl JsonRpc {
    /// Fetches a transaction by ID — Zebra checks the mempool first, then any
    /// chain, side-chains included — so a hit never means "best-chain
    /// confirmed"; confirmation is chain application.
    ///
    /// `branch_id` is only consulted for pre-v5 transaction versions, which
    /// the mint never builds at NU6.3+. `Ok(None)` means the transaction is
    /// nowhere (RPC -5): normal when racing an `Invalidated` event.
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
            // eviction or a chain reorg; indistinguishable from never-existed.
            Err(TransportError::Rpc(ref rpc)) if rpc.code == -5 => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetches every transaction ID currently in the mempool — the
    /// re-baseline snapshot after a stream reconnect; diff it against the
    /// pending set.
    pub async fn get_raw_mempool(&self) -> Result<Vec<TxId>, TransportError> {
        let txids: Vec<String> = self
            .send_request("getrawmempool", [(); 0])
            .await?
            .ok_or(TransportError::BadNodeData("getrawmempool returned null"))?;

        txids
            .iter()
            .map(|hex| TxId::from_hex(hex).ok_or(TransportError::BadNodeData("getrawmempool txid")))
            .collect()
    }
}

// ===========================================================================
// The mempool session — the stream's one owner
// ===========================================================================

/// The live gRPC mempool-change stream, boxed so the session can own it.
pub(crate) type MempoolStream =
    Pin<Box<dyn Stream<Item = Result<(MempoolChangeKind, TxId), TransportError>> + Send>>;

/// The mempool stream's one owner: subscription, repair — the mempool's
/// twin of [`TipSession`](super::chain::TipSession). It announces the
/// node's mempool changes and answers nothing else; a gap in the stream
/// is a gap in quickness, never in truth: what it misses, the block path
/// decides.
pub struct MempoolSession {
    client: ChainClient,
    stream: MempoolStream,
}

impl MempoolSession {
    /// Subscribes to the mempool-change stream.
    pub async fn open(client: ChainClient) -> Self {
        let stream = Self::subscribe(client.clone()).await;
        Self { client, stream }
    }

    /// One mempool change, decoded; the stream is repaired on death.
    pub async fn next(&mut self) -> (MempoolChangeKind, TxId) {
        loop {
            match self.stream.next().await {
                Some(Ok(event)) => return event,
                Some(Err(error)) => {
                    tracing::warn!(%error, "Zebra mempool stream failed; repairing");
                    self.repair().await;
                }
                None => {
                    tracing::warn!("Zebra mempool stream ended; repairing");
                    self.repair().await;
                }
            }
        }
    }

    /// Pause, reopen.
    async fn repair(&mut self) {
        tokio::time::sleep(super::RETRY_PAUSE).await;
        self.stream = Self::subscribe(self.client.clone()).await;
    }

    /// Opens the mempool stream, retrying until Zebra answers.
    async fn subscribe(mut client: ChainClient) -> MempoolStream {
        loop {
            match client.mempool_events().await {
                Ok(stream) => return Box::pin(stream),
                Err(error) => {
                    tracing::warn!(%error, "Zebra mempool stream unavailable; reconnecting");
                    tokio::time::sleep(super::RETRY_PAUSE).await;
                }
            }
        }
    }
}
