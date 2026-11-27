//! The seam between the mint and its Zebra full node.

pub mod chain;
pub mod mempool;
pub mod submit;

pub use chain::{ChainClient, TipSession};
pub use mempool::MempoolSession;
pub use submit::SubmitOutcome;
pub use zebra_indexer_proto::MempoolChangeKind;

use std::time::Duration;

use thiserror::Error;
use zebra_indexer_proto::LightwalletdClient;

/// The wait between retries of a retryable transport call.
pub const RETRY_PAUSE: Duration = Duration::from_secs(5);

pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// The orchestrator's handle — impls in every conversation file
// ============================================================================

/// The one node handle: both gRPC services behind one door. Canonical
/// blocks, reorg-walk hashes and MTP header times ride the Indexer; the
/// tip, tree state, raw transactions and broadcast ride the
/// `CompactTxStreamer`.
/// Unary gRPC calls go out on a fresh handle to the shared HTTP/2
/// connection — `Channel` is an `Arc` — so every public method stays
/// `&self`.
#[derive(Clone)]
pub struct CanonicalBlockSource {
    pub(crate) chain: ChainClient,
    pub(crate) lightwalletd: LightwalletdClient,
}

impl CanonicalBlockSource {
    /// Binds the connected gRPC clients (boot's connect product). Same
    /// hardcoded node — a view, not a connection.
    pub fn new(chain: ChainClient, lightwalletd: LightwalletdClient) -> Self {
        Self {
            chain,
            lightwalletd,
        }
    }
}

// ============================================================================
// The error policy
// ============================================================================

/// Maps the node's tip-race verdict to [`TransportError::NotOnBestChain`],
/// so a race never reads as malformed data or transport death: gRPC
/// `not_found` for a hash or height off the best chain.
pub(crate) fn not_on_best_chain(error: TransportError) -> TransportError {
    match error {
        TransportError::Tonic(ref status) if status.code() == tonic::Code::NotFound => {
            TransportError::NotOnBestChain
        }
        error => error,
    }
}

/// Everything that can go wrong talking to the node, classified once.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("bad node data for {0}")]
    BadNodeData(&'static str),
    #[error("bad checkpoint: {0}")]
    BadCheckpoint(String),
    /// The node's answer that the requested hash or height is not on its
    /// current best chain — a tip race, not bad data and not transport.
    #[error("hash or height is not on the node's current best chain")]
    NotOnBestChain,
    #[error("gRPC status: {0}")]
    Tonic(#[from] tonic::Status),
}

impl TransportError {
    /// Whether repeating the same operation can recover without trusting new data.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::BadNodeData(_) | Self::BadCheckpoint(_))
            || matches!(
                self,
                // Anything but a verdict retries: tonic reports a dropped
                // connection as Unknown, Internal, Aborted or OutOfRange as well
                // as Unavailable, and the endpoint's REQUEST_TIMEOUT as Cancelled.
                Self::Tonic(status) if !matches!(
                    status.code(),
                    // Zebra's verdicts: the same request gets the same answer.
                    tonic::Code::InvalidArgument
                        | tonic::Code::NotFound
                        | tonic::Code::AlreadyExists
                        | tonic::Code::PermissionDenied
                        | tonic::Code::FailedPrecondition
                        | tonic::Code::Unimplemented
                        | tonic::Code::Unauthenticated
                )
            )
    }
}
