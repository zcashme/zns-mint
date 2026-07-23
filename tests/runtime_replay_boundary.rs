const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const SYNC_SOURCE: &str = include_str!("../src/sync.rs");
const WALLET_SOURCE: &str = include_str!("../src/wallet.rs");
const REGISTRY_SOURCE: &str = include_str!("../src/registry/state.rs");
const REGISTRY_TRANSACTION_SOURCE: &str = include_str!("../src/registry/transaction.rs");
const TREASURY_SOURCE: &str = include_str!("../src/treasury.rs");
const ZCASH_SOURCE: &str = include_str!("../src/zcash.rs");

#[test]
fn canonical_replay_invokes_no_operational_effects() {
    for forbidden in [
        "PendingOtps",
        "TreasuryKeys",
        "RegistryKeys",
        "authorize_claim",
        "authorize_update",
        "authorize_release",
        "build_transaction",
        "build_refund_transaction",
        "OsRng",
        "rpc.send(",
        "JsonRpc",
        "SubmissionState",
        "InFlightIntent",
        "inc_blocks_scanned",
        "inc_request",
        "inc_otp",
        "inc_submission",
    ] {
        assert!(
            !MAIN_SOURCE.contains(forbidden),
            "passive replay regained forbidden operation `{forbidden}`"
        );
    }

    assert!(
        MAIN_SOURCE.contains("CanonicalBlockSource"),
        "passive replay must use the read-only canonical block source"
    );
}

#[test]
fn canonical_applicator_returns_only_transition_status() {
    let signature_start = MAIN_SOURCE
        .find("fn apply_canonical_block(")
        .expect("canonical applicator must exist");
    let signature_end = MAIN_SOURCE[signature_start..]
        .find(") -> Result<(), RuntimeError>")
        .map(|offset| signature_start + offset)
        .expect("canonical applicator signature terminator must exist");
    let signature = &MAIN_SOURCE[signature_start..signature_end];

    for forbidden in [
        "height:",
        "Treasury",
        "Otp",
        "Intent",
        "Submission",
        "TreasuryKeys",
        "RegistryKeys",
        "SpendingKey",
        "JsonRpc",
        "metrics",
    ] {
        assert!(
            !signature.contains(forbidden),
            "canonical applicator accepts forbidden input `{forbidden}`"
        );
    }

    assert!(
        !MAIN_SOURCE.contains("Result<CommittedBlock, RuntimeError>"),
        "canonical folding must not become an event-delivery interface"
    );

    let catch_up_start = MAIN_SOURCE
        .find("async fn catch_up(")
        .expect("catch-up function must exist");
    let applicator_start = MAIN_SOURCE
        .find("fn apply_canonical_block(")
        .expect("canonical applicator must exist");
    let catch_up = &MAIN_SOURCE[catch_up_start..applicator_start];
    let apply_call = catch_up
        .find("apply_canonical_block(")
        .expect("catch-up must invoke the canonical applicator");
    let after_apply = &catch_up[apply_call..];

    assert!(
        after_apply.contains("publish_canonical_gauges(wallet, cursor.block_height())"),
        "post-fold consumers must read the promoted cursor"
    );
    assert!(
        !after_apply.contains("committed_height"),
        "catch-up must not retain a second accepted-height result"
    );
}

#[test]
fn scanned_block_has_one_accepted_height_source() {
    let struct_start = SYNC_SOURCE
        .find("pub struct BlockOutput {")
        .expect("BlockOutput must exist");
    let impl_start = SYNC_SOURCE[struct_start..]
        .find("impl BlockOutput {")
        .map(|offset| struct_start + offset)
        .expect("BlockOutput implementation must exist");
    let next_type = SYNC_SOURCE[impl_start..]
        .find("pub struct TxOutput {")
        .map(|offset| impl_start + offset)
        .expect("BlockOutput implementation terminator must exist");

    let fields = &SYNC_SOURCE[struct_start..impl_start];
    let implementation = &SYNC_SOURCE[impl_start..next_type];

    assert!(
        !fields.contains("\n    height: BlockHeight,"),
        "BlockOutput must not duplicate scanner metadata height"
    );
    assert!(
        !implementation.contains("pub fn height("),
        "accepted height must be read explicitly from BlockMetadata"
    );
    assert!(WALLET_SOURCE.contains("output.metadata().block_height()"));
    assert!(REGISTRY_SOURCE.contains("output.metadata().block_height()"));
    assert!(SYNC_SOURCE.contains("block_height: metadata.block_height()"));
}

#[test]
fn canonical_block_source_exposes_only_chain_reads() {
    let impl_start = ZCASH_SOURCE
        .find("impl CanonicalBlockSource {")
        .expect("canonical block source implementation must exist");
    let impl_end = ZCASH_SOURCE[impl_start..]
        .find("impl Default for CanonicalBlockSource")
        .map(|offset| impl_start + offset)
        .expect("canonical block source implementation terminator must exist");
    let implementation = &ZCASH_SOURCE[impl_start..impl_end];

    assert!(implementation.contains("pub async fn get_blockchain_info("));
    assert!(implementation.contains("pub async fn get_block("));
    assert!(!implementation.contains("send("));
    assert!(!implementation.contains("raw("));
    assert!(!implementation.contains("send_request"));
}

#[test]
fn canonical_state_owners_have_no_operational_locks() {
    for forbidden in [
        "reserved:",
        "reserve_note",
        "reserve_all",
        "reserved_notes",
        "is_note_reserved",
        "orchard_exclude_set",
        "sapling_exclude_set",
        "ironwood_exclude_set",
    ] {
        assert!(
            !WALLET_SOURCE.contains(forbidden),
            "Wallet regained operational reservation surface `{forbidden}`"
        );
    }

    for forbidden in [
        "locked:",
        "lock_name",
        "unlock_name",
        "locked_names",
        "is_name_locked",
    ] {
        assert!(
            !REGISTRY_SOURCE.contains(forbidden),
            "Registry regained operational lock surface `{forbidden}`"
        );
    }
}

#[test]
fn treasury_has_no_per_block_request_queue() {
    assert!(
        !TREASURY_SOURCE.contains("requests_in_block"),
        "Treasury must not expose a replay-oriented per-block request queue"
    );
}

#[test]
fn registry_fee_planning_requires_caller_owned_exclusions() {
    assert!(
        REGISTRY_TRANSACTION_SOURCE.contains("excluded: &BTreeSet<NoteLocator>"),
        "Registry fee planning must receive explicit Live-owned exclusions"
    );
    assert!(
        REGISTRY_TRANSACTION_SOURCE.contains("!excluded.contains(locator)"),
        "Registry fee planning must apply every caller-owned exclusion"
    );
    assert!(
        !REGISTRY_TRANSACTION_SOURCE.contains("wallet.is_note_reserved"),
        "Registry fee planning must not read operational state from Wallet"
    );
}

#[test]
fn malformed_chain_data_is_never_retryable() {
    use zns_mint::zcash::TransportError;

    assert!(TransportError::Timeout.is_retryable());
    assert!(TransportError::HttpStatus(503).is_retryable());
    assert!(!TransportError::HttpStatus(400).is_retryable());
    assert!(!TransportError::BadNodeData("test").is_retryable());
    assert!(!TransportError::BadCheckpoint("test".to_owned()).is_retryable());
}
