//! Submission: one broadcast attempt and its retrying caller.

use zcash_primitives::transaction::{Transaction, TxId};
use zebra_indexer_proto::lightwalletd::RawTransaction;

use super::RETRY_PAUSE;

use super::{RpcError, TransportError};

/// The node's answer to "carry this".
#[derive(Debug)]
pub enum SubmitOutcome {
    /// The node admitted the transaction to its mempool.
    Accepted,
    /// The node rejected the transaction under its consensus or policy
    /// rules: an answer, not a transport failure.
    Rejected(TransportError),
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
                Ok(SubmitOutcome::Rejected(error)) => {
                    tracing::error!(%error, txid = %tx.txid(), what = label, "rejected");
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

        // Zebra judges the size too: past its limit is `invalid_argument`,
        // a verdict.
        let request = RawTransaction {
            data: tx_bytes,
            height: 0,
        };
        let response = match self.lightwalletd.clone().send_transaction(request).await {
            Ok(response) => response.into_inner(),
            Err(status) => {
                let error = TransportError::from(status);
                return if error.is_retryable() {
                    Err(error)
                } else {
                    Ok(SubmitOutcome::Rejected(error))
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
                _ => Ok(SubmitOutcome::Rejected(TransportError::BadNodeData(
                    "SendTransaction named a different transaction",
                ))),
            },
            Err((code, message)) => {
                let rpc = RpcError {
                    code: code.into(),
                    message: message.to_string(),
                };
                if rpc.is_already_in_mempool() {
                    Ok(SubmitOutcome::Accepted)
                } else {
                    Ok(SubmitOutcome::Rejected(TransportError::Rpc(rpc)))
                }
            }
        }
    }
}
