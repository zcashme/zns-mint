//! Submission: one broadcast attempt and its retrying caller.

use zcash_primitives::transaction::{Transaction, TxId};

use super::RETRY_PAUSE;

use super::{JsonRpc, TransportError};

/// The node's answer to "carry this".
#[derive(Debug)]
pub enum SubmitOutcome {
    /// The node admitted the transaction to its mempool.
    Accepted,
    /// The node reports the transaction is already in the chain (−27) — an
    /// earlier broadcast was mined; also success.
    Mined,
    /// The node rejected the transaction under its consensus or policy
    /// rules: an answer, not a transport failure.
    Rejected(TransportError),
}

impl JsonRpc {
    /// Broadcasts a signed raw transaction hex; `Ok` carries the node's
    /// identifier for it.
    pub async fn send(&self, raw_tx_hex: &str) -> Result<String, TransportError> {
        self.send_request("sendrawtransaction", [raw_tx_hex])
            .await?
            .ok_or(TransportError::BadNodeData(
                "sendrawtransaction returned null",
            ))
    }
}

impl super::CanonicalBlockSource {
    /// Broadcasts a transaction, retrying transport uncertainty until the
    /// node decides. `label` names the flow in the logs.
    pub async fn submit(&self, tx: &Transaction, label: &'static str) -> bool {
        loop {
            match self.send_transaction(tx).await {
                Ok(SubmitOutcome::Accepted | SubmitOutcome::Mined) => {
                    tracing::info!(txid = %tx.txid(), what = label, "submitted");
                    return true;
                }
                Ok(SubmitOutcome::Rejected(error)) => {
                    tracing::error!(%error, txid = %tx.txid(), what = label, "rejected");
                    return false;
                }
                Err(error) if error.is_retryable() => {
                    tracing::warn!(
                        %error,
                        txid = %tx.txid(),
                        what = label,
                        "submission uncertain; retrying"
                    );
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
                Err(error) => panic!("FATAL: {label} submission failed: {error}"),
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

        match self.0.send(&hex::encode(tx_bytes)).await {
            Ok(returned_txid) => match TxId::from_hex(&returned_txid) {
                Some(txid) if txid == tx.txid() => Ok(SubmitOutcome::Accepted),
                // A success envelope that names another transaction — or
                // no transaction at all — is a node verdict, not ours.
                _ => Ok(SubmitOutcome::Rejected(TransportError::BadNodeData(
                    "sendrawtransaction named a different transaction",
                ))),
            },
            Err(TransportError::Rpc(ref rpc)) if rpc.is_tx_already_in_chain() => {
                Ok(SubmitOutcome::Mined)
            }
            Err(TransportError::Rpc(ref rpc)) if rpc.is_already_in_mempool() => {
                Ok(SubmitOutcome::Accepted)
            }
            Err(error) if error.is_retryable() => Err(error),
            Err(error) => Ok(SubmitOutcome::Rejected(error)),
        }
    }
}
