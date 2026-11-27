//! Submission: one broadcast attempt and its retrying caller.

use zcash_primitives::transaction::{Transaction, TxId};
use zebra_indexer_proto::lightwalletd::RawTransaction;

use super::RETRY_PAUSE;

use super::TransportError;

/// What Zebra's answer means for the mint.
#[derive(Debug)]
pub enum SubmitOutcome {
    /// Zebra holds the transaction: its mempool took it now or already had it.
    Accepted,
    /// Zebra's mempool did not take it.
    Refused,
}

impl super::CanonicalBlockSource {
    /// Broadcasts a transaction, retrying transport uncertainty until the
    /// node decides. `label` names the flow in the logs.
    pub async fn submit(&self, tx: &Transaction, label: &'static str) -> bool {
        loop {
            match self.send_transaction(tx).await {
                Ok(SubmitOutcome::Accepted) => {
                    tracing::info!(txid = %tx.txid(), what = label, "submitted");
                    return true;
                }
                Ok(SubmitOutcome::Refused) => {
                    tracing::error!(txid = %tx.txid(), what = label, "refused");
                    return false;
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        txid = %tx.txid(),
                        what = label,
                        "submission uncertain; retrying"
                    );
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
            }
        }
    }

    /// Broadcasts a signed transaction — one honest attempt, no retries, no
    /// hidden tip guard.
    ///
    /// `Ok` means the node answered; `Err` means no answer was obtained.
    /// Retransmission is the caller's standing obligation, per upstream:
    /// stored transactions "should be retransmitted while it is still
    /// possible that they could be mined."
    pub async fn send_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SubmitOutcome, TransportError> {
        let mut tx_bytes = Vec::new();
        // Serializing a completed Transaction into a Vec cannot fail; the
        // io::Result exists for streaming writers.
        tx.write(&mut tx_bytes)
            .expect("serializing a completed transaction cannot fail");

        let Some(request) = RawTransaction::new(tx_bytes) else {
            tracing::error!(txid = %tx.txid(), "transaction exceeds Zebra's size limit");
            return Ok(SubmitOutcome::Refused);
        };
        let response = match self.lightwalletd.clone().send_transaction(request).await {
            Ok(response) => response.into_inner(),
            Err(status) => {
                let error = TransportError::from(status);
                return if error.is_retryable() {
                    Err(error)
                } else {
                    tracing::error!(%error, txid = %tx.txid(), "Zebra refused the transaction");
                    Ok(SubmitOutcome::Refused)
                };
            }
        };

        // Zebra answers submission errors inside the response, with its
        // JSON-RPC code and message.
        match response.result() {
            Ok(returned_txid) => match TxId::from_hex(returned_txid) {
                Some(txid) if txid == tx.txid() => Ok(SubmitOutcome::Accepted),
                // A success envelope that names another transaction — or
                // no transaction at all — is a node verdict, not ours.
                _ => {
                    tracing::error!(
                        returned_txid,
                        txid = %tx.txid(),
                        "SendTransaction named a different transaction"
                    );
                    Ok(SubmitOutcome::Refused)
                }
            },
            // Zebra's `MempoolError::InMempool`, which shares -1 with every
            // other mempool refusal.
            Err((_, "transaction already exists in mempool")) => Ok(SubmitOutcome::Accepted),
            Err((code, message)) => {
                tracing::error!(code, message, txid = %tx.txid(), "Zebra refused the transaction");
                Ok(SubmitOutcome::Refused)
            }
        }
    }
}
