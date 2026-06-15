//! `zns-chain` — ZNS chain I/O.
//!
//! The untrusted edge that talks to the network: the intake [`scanner`] reads
//! lightwalletd compact blocks and trial-decrypts Orchard notes addressed to
//! the registry, and [`grpc`] broadcasts minted transactions to the node. Named
//! for its function, not its trust position — it holds no keys and makes no
//! policy decisions; the `zns-mint` daemon drives it.

pub mod grpc;
pub mod scanner;
pub mod wallet_sync;

pub use grpc::{GrpcClient, GrpcError};
pub use scanner::{
    scan_blocks, scan_incoming, scan_incoming_all, scan_mempool, IncomingNote, ScanError,
    ScannerConfig,
};
pub use wallet_sync::EphemeralCompactBlockCache;
pub use grpc::connect;
