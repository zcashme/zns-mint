//! Spend-lane idle invariants (no network).

use zns_registry::{Registry, SpendLane};
use zns_state::{InFlightSpend, State};

#[tokio::test]
async fn spend_lane_idle_when_empty() {
    let state = State::open_in_memory().unwrap();
    let registry = Registry::new(state);
    let lane = SpendLane::new();

    assert!(lane.is_idle(&registry).await.unwrap());
}

#[tokio::test]
async fn spend_lane_not_idle_with_in_flight() {
    let state = State::open_in_memory().unwrap();
    state
        .set_in_flight(&InFlightSpend {
            txid: [1u8; 32],
            request_txid: [2u8; 32],
            request_index: 0,
            expiry_height: 100,
            relay: false,
            sweep: false,
            name: "alice".into(),
        })
        .unwrap();

    let registry = Registry::new(state);
    let lane = SpendLane::new();

    assert!(!lane.is_idle(&registry).await.unwrap());
}

#[test]
fn pending_count_includes_queued_and_active() {
    let lane = SpendLane::new();
    lane.push(zns_registry::QueuedSpend {
        txid: [1u8; 32],
        pool: 0,
        output_index: 0,
        block_height: 100,
        block_hash: [0u8; 32],
        verb: zns_registry::SpendVerb::Claim,
        name: "alice".into(),
        ua: "u1x".into(),
        nonce: String::new(),
        value_zat: 10_000,
    });
    assert_eq!(lane.pending_count(), 1);
}