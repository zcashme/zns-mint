//! `zns-registry` — ZNS name registry orchestration.
//!

// ---------------------------------------------------------------------------
// Convenience re-exports (flat surface the rest of the workspace likes)
// ---------------------------------------------------------------------------

pub use zns_chain::{
    connect, scan_incoming, scan_incoming_all, scan_mempool, EphemeralCompactBlockCache,
    GrpcClient, GrpcError, IncomingNote, ScannerConfig,
};
pub use zns_core::{memo, parse_memo, Action, MemoError, ParsedMemo, ZERO_PREV_RCM};
pub use zns_mint::{
    build_name_note, test_orchard_ivk, test_registry_address, FundingInput, MintParams, MintResult,
    RequestId, Signer, SpendPolicy,
};
pub use zns_state::{
    FundingSelection, MintedAction, Name, NoteState, SpendableNote, TreasuryConfig, TreasuryError,
};

// ---------------------------------------------------------------------------
// Our own modules (the actual modularity)
// ---------------------------------------------------------------------------

pub mod constants;
pub mod error;
pub mod processor;
pub mod rpc;
pub mod store;
pub mod types;

// Re-export the main types under the old names for minimal caller churn in
// the short term. Callers should prefer being explicit about store vs.
// processor in new code.
pub use error::RegistryError;
pub use processor::Processor;
pub use store::Registry;
pub use types::{ActionOutcome, MintContext, ProcessResult, RegistryStats, Treasury};

// Re-export the fee constants at the crate root for ergonomics (same as before).
pub use constants::{FUNDING_MIN_ZAT, MINT_FEE_ZAT, MIN_CLAIM_FEE_ZAT, MIN_MUTATION_FEE_ZAT};

// ---------------------------------------------------------------------------
// Basic tests exercising the new modular surface (processor + store split)
// The old god-module tests have been migrated here.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::{
        keys::{FullViewingKey, Scope, SpendingKey},
        tree::Anchor,
    };
    use std::sync::Arc;

    fn make_context() -> MintContext {
        // Tests go through the signer crate boundary. The seed never
        // appears in this (host) crate.
        let registry_addr = test_registry_address();
        let policy = SpendPolicy {
            registry_addr,
            cold_addr: registry_addr,
            max_fee_zat: MINT_FEE_ZAT,
            target_float_zat: 0,
            high_watermark_zat: u64::MAX,
            low_watermark_zat: 0,
            max_mints_per_window: u32::MAX,
        };
        let signer = Arc::new(Signer::new_test(policy).unwrap());
        MintContext {
            signer,
            hot_balance_zat: 1_000_000,
            anchor: Anchor::empty_tree(),
            height: 2_000_000,
            expiry_height: 0,
            network: zcash_protocol::consensus::Network::MainNetwork,
            circuit_version: orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
            branch_id: zcash_protocol::consensus::BranchId::Nu6_2,
            treasury: None,
        }
    }

    #[tokio::test]
    async fn registry_authored_memos_are_skipped() {
        let store = Registry::open_in_memory().unwrap();
        let processor = Processor::new(store);
        let ctx = make_context();
        // We still need a GrpcClient for the signature, even if these paths
        // never broadcast (treasury None + early skips).
        let grpc = GrpcClient::new("http://127.0.0.1:0");

        let note = |s: &[u8]| IncomingNote {
            txid: [9u8; 32],
            height: 2_000_000,
            block_hash: [0u8; 32],
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: true,
            confirmed: true,
        };

        let name_note = format!("ZNS:claim:alice:u1xxx:{}", "a".repeat(64));
        let results = processor
            .process_notes(
                &[
                    note(name_note.as_bytes()),
                    note(b"ZNS:challenge:alice:beef"),
                ],
                &ctx,
                &grpc,
            )
            .await;
        assert!(
            results
                .iter()
                .all(|r| matches!(r, ProcessResult::Skipped(_))),
            "got: {results:?}"
        );

        let store = processor.registry();
        assert!(store.lookup("alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn claim_insufficient_fee() {
        let store = Registry::open_in_memory().unwrap();
        let processor = Processor::new(store);
        let ctx = make_context();
        let grpc = GrpcClient::new("http://127.0.0.1:0");

        let note = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            block_hash: [0u8; 32],
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: 1,
            is_received: true,
            confirmed: true,
        };

        let results = processor.process_notes(&[note], &ctx, &grpc).await;
        assert!(matches!(results[0], ProcessResult::Err(_, _)));
    }

    #[tokio::test]
    async fn sent_notes_skipped() {
        let store = Registry::open_in_memory().unwrap();
        let processor = Processor::new(store);
        let ctx = make_context();
        let grpc = GrpcClient::new("http://127.0.0.1:0");

        let note = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            block_hash: [0u8; 32],
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: false,
            confirmed: true,
        };

        let results = processor.process_notes(&[note], &ctx, &grpc).await;
        assert_eq!(results.len(), 0);
    }
}
