//! Submission: "carry this" — one honest attempt, the node's answer.

use zcash_primitives::transaction::Transaction;

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
    /// node decides; both acceptance and rejection return `false`-or-`true`
    /// respectively — what the caller does with the verdict is its own.
    /// `label` names the flow in the logs ("registration", "controller
    /// challenge", …).
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
            .map_err(|_| TransportError::BadNodeData("transaction serialization failed"))?;

        match self.0.send(&hex::encode(tx_bytes)).await {
            Ok(returned_txid) => {
                debug_assert_eq!(returned_txid, tx.txid().to_string());
                Ok(SubmitOutcome::Accepted)
            }
            Err(TransportError::Rpc(ref rpc)) if rpc.is_tx_already_in_chain() => {
                Ok(SubmitOutcome::Mined)
            }
            Err(error) if error.is_retryable() => Err(error),
            Err(error) => Ok(SubmitOutcome::Rejected(error)),
        }
    }
}
