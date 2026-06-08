//! `zns-chain` — ZNS chain I/O.
//!
//! The untrusted edge that talks to the network: the intake [`scanner`] reads
//! lightwalletd compact blocks and trial-decrypts Orchard notes addressed to
//! the registry, and [`grpc`] broadcasts minted transactions to zebrad. Named
//! for its function (cf. `zebra-network`), not its trust position — it holds no
//! keys and makes no policy decisions; the `zns-mint` daemon drives it.

pub mod grpc;
pub mod scanner;

pub use grpc::GrpcClient;
pub use scanner::{scan_incoming, scan_incoming_all, IncomingNote, ScannerConfig};
