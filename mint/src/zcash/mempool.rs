//! The mempool: what is pending, where our broadcasts stand.

use std::pin::Pin;

use futures_util::{Stream, StreamExt};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;
use zebra_indexer_proto::lightwalletd::TxFilter;
use zebra_indexer_proto::{Empty, MempoolChangeKind};

use super::{chain::ChainClient, TransportError};

impl ChainClient {
    /// Opens the gRPC stream of mempool changes as `(MempoolChangeKind, TxId)`
    /// pairs.
    ///
    /// The mined id equals the `TxId` for every transaction version the mint
    /// builds; the auth digest is discarded. Reorgs emit nothing for
    /// transactions that were in abandoned blocks. Stream endings — silent or
    /// errored — mean reconnect; what a gap missed, the block path decides —
    /// the re-baseline the doc once promised is deliberately not built
    /// (best-effort is the doctrine).
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
                let mut txid_bytes = *message
                    .tx_hash_display_order()
                    .ok_or(TransportError::BadNodeData("mempool tx hash"))?;
                txid_bytes.reverse();
                let txid = TxId::from_bytes(txid_bytes);
                Ok((kind, txid))
            })
        }))
    }
}

impl super::CanonicalBlockSource {
    /// Fetches a transaction by ID over `CompactTxStreamer` `GetTransaction`
    /// — Zebra checks the best chain, then the mempool, then side chains —
    /// so a hit never means "best-chain confirmed"; confirmation is chain
    /// application.
    ///
    /// `branch_id` is only consulted for pre-v5 transaction versions, which
    /// the mint never builds at NU6.3+. `Ok(None)` means the transaction is
    /// nowhere (`not_found`): normal when racing an `Invalidated` event.
    pub async fn get_raw_transaction(
        &self,
        branch_id: BranchId,
        txid: TxId,
    ) -> Result<Option<Transaction>, TransportError> {
        let filter = TxFilter::from_txid_internal_order(*txid.as_ref());
        match self.lightwalletd.clone().get_transaction(filter).await {
            Ok(response) => {
                let tx = Transaction::read(&response.into_inner().data[..], branch_id)
                    .map_err(|_| TransportError::BadNodeData("GetTransaction parse"))?;
                Ok(Some(tx))
            }
            // "No information about the transaction" — racing a mempool
            // eviction or a chain reorg; indistinguishable from never-existed.
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(status.into()),
        }
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
    pub async fn open(client: ChainClient) -> Result<Self, TransportError> {
        let stream = Self::subscribe(client.clone()).await?;
        Ok(Self { client, stream })
    }

    /// One mempool change, decoded; the stream is repaired on death. A
    /// change the mint cannot decode is skipped: the stream is healthy.
    pub async fn next(&mut self) -> Result<(MempoolChangeKind, TxId), TransportError> {
        loop {
            match self.stream.next().await {
                Some(Ok(event)) => return Ok(event),
                Some(Err(TransportError::BadNodeData(what))) => {
                    tracing::warn!(what, "Zebra mempool change unreadable; skipped");
                }
                Some(Err(error)) if error.is_retryable() => {
                    tracing::warn!(%error, "Zebra mempool stream failed; repairing");
                    self.repair().await?;
                }
                // A verdict: no reopen changes it.
                Some(Err(error)) => return Err(error),
                None => {
                    tracing::warn!("Zebra mempool stream ended; repairing");
                    self.repair().await?;
                }
            }
        }
    }

    /// Pause, reopen.
    async fn repair(&mut self) -> Result<(), TransportError> {
        tokio::time::sleep(super::RETRY_PAUSE).await;
        self.stream = Self::subscribe(self.client.clone()).await?;
        Ok(())
    }

    /// Opens the mempool stream, retrying while the node is merely
    /// unavailable.
    async fn subscribe(mut client: ChainClient) -> Result<MempoolStream, TransportError> {
        loop {
            match client.mempool_events().await {
                Ok(stream) => return Ok(Box::pin(stream)),
                Err(error) if error.is_retryable() => {
                    tracing::warn!(%error, "Zebra mempool stream unavailable; reconnecting");
                    tokio::time::sleep(super::RETRY_PAUSE).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
