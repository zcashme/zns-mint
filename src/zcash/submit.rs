//! Outbound transaction tracking — broadcasts assembled transactions to Zebra
//! and tracks their lifecycle through confirmation or failure.
//!
//! This is the stateful outbound counterpart to the stateless [`super::JsonRpc`]
//! transport: `JsonRpc` fires-and-forgets a `sendrawtransaction`, while `Submitter`
//! records the result and watches each transaction until it confirms or
//! permanently fails.

use std::collections::HashMap;
use zcash_protocol::consensus::BlockHeight;

use super::JsonRpc;

/// The intent or original action that produced this transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Claim(String),
    Update(String),
    Release(String),
    OtpRelay(String),
    RegistryFunding,
    Sweep,
}

/// The lifecycle state of a submitted transaction.
#[derive(Debug, Clone)]
pub struct SubmissionState {
    pub txid: String,
    pub origin: Origin,
    pub first_submit_height: BlockHeight,
    pub first_submit_time: std::time::SystemTime,
    pub retry_count: u32,
    pub confirmation_height: Option<BlockHeight>,
    pub failure_reason: Option<String>,
}

/// Broadcasts transactions and tracks their status.
pub struct Submitter {
    pending: HashMap<String, SubmissionState>,
    rpc: JsonRpc,
}

impl Default for Submitter {
    fn default() -> Self {
        Self::new()
    }
}

impl Submitter {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            rpc: JsonRpc::new(),
        }
    }

    /// Broadcasts a transaction and begins tracking it.
    pub async fn submit(
        &mut self,
        raw_tx_hex: &str,
        origin: Origin,
        current_height: BlockHeight,
    ) -> Result<String, String> {
        match self.rpc.send(raw_tx_hex).await {
            Ok(txid) => {
                self.pending.insert(
                    txid.clone(),
                    SubmissionState {
                        txid: txid.clone(),
                        origin,
                        first_submit_height: current_height,
                        first_submit_time: std::time::SystemTime::now(),
                        retry_count: 0,
                        confirmation_height: None,
                        failure_reason: None,
                    },
                );
                Ok(txid)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Records that a transaction was confirmed in a block.
    pub fn mark_confirmed(&mut self, txid: &str, height: BlockHeight) {
        if let Some(state) = self.pending.get_mut(txid) {
            state.confirmation_height = Some(height);
        }
    }

    /// Records that a transaction has permanently failed.
    pub fn mark_failed(&mut self, txid: &str, reason: String) {
        if let Some(state) = self.pending.get_mut(txid) {
            state.failure_reason = Some(reason);
        }
    }

    /// Reads the current state of a tracked transaction.
    pub fn state(&self, txid: &str) -> Option<&SubmissionState> {
        self.pending.get(txid)
    }

    /// Returns all currently pending (unconfirmed and un-failed) transactions.
    pub fn pending_transactions(&self) -> impl Iterator<Item = &SubmissionState> {
        self.pending
            .values()
            .filter(|s| s.confirmation_height.is_none() && s.failure_reason.is_none())
    }
}
