//! Canon golden vector v1.
//!
//! Emits and verifies `tests/fixtures/canon-vectors-v1.json` — the
//! cross-repo acceptance-test artifact for `zns-canon` consumers.
//! Resolvers implement the same rules against the same event stream and
//! must produce byte-identical per-event snapshots after mapping to
//! their own state schema.
//!
//! Regeneration:
//!
//!   CANON_VECTORS_REGEN=1 cargo test --test canon_vectors
//!
//! Otherwise the test asserts the committed fixture matches the current
//! emitter output.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::Timestamp;
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_protocol::consensus::{BlockHeight, MainNetwork};

use zns_mint::mint::registry::{Registry, ANCHOR_POOL_SIZE};
use zns_mint::mint::{Action, Expiry, Name, NameNote};

// ---------------------------------------------------------------------------
// Fixture types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Vectors {
    version: String,
    anchor_pool_size: usize,
    scenarios: Vec<Scenario>,
}

#[derive(Serialize, Deserialize)]
struct Scenario {
    name: String,
    description: String,
    events: Vec<Event>,
    /// State snapshot after each event, in order.
    trace: Vec<Snapshot>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    /// Ceremony filling: a zero-value Registry output joins the pool
    /// below standing size, in canonical scan order.
    AdoptAnchor { height: u32, nullifier: Hex32 },
    /// A backed Claim: retires `spent_anchor`, adopts `successor_anchor`,
    /// binds the name. `expect` says whether the record transition lands;
    /// a rejected claim (a duplicate on a live name) still advances the
    /// pool.
    Claim {
        height: u32,
        mtp_secs: i64,
        name: String,
        ua: String,
        /// Unix seconds; `null` means `Expiry::Never`.
        expires_at_secs: Option<i64>,
        spent_anchor: Hex32,
        successor_anchor: Hex32,
        /// The NameNote's own nullifier.
        nullifier: Hex32,
        expect: Expectation,
    },
    /// Attacker-shaped Claim: no live anchor spent. Mint drops the
    /// candidate; every consumer must reject without state change.
    UnbackedClaim {
        height: u32,
        mtp_secs: i64,
        name: String,
        ua: String,
        expires_at_secs: Option<i64>,
        /// Optional non-anchor nullifier(s) the attacker spent. Empty
        /// means the tx spent nothing.
        spent: Vec<Hex32>,
    },
    /// An Update that spends the current record's nullifier.
    Update {
        height: u32,
        mtp_secs: i64,
        name: String,
        ua: String,
        expires_at_secs: Option<i64>,
        /// Executor asserts this matches `registry.record(name).nullifier`.
        prev_nullifier: Hex32,
        /// The successor NameNote's own nullifier.
        nullifier: Hex32,
    },
    /// A Release that spends the current record's nullifier.
    Release {
        height: u32,
        mtp_secs: i64,
        name: String,
        ua: String,
        prev_nullifier: Hex32,
        nullifier: Hex32,
    },
    /// Reorg: rewind Registry to `to_height`.
    Rewind { to_height: u32 },
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    after_event: usize,
    /// Live anchor-pool nullifiers, lowercase hex, sorted lexicographically.
    anchor_pool: Vec<Hex32>,
    /// Name → current record. `BTreeMap` for deterministic key order.
    records: BTreeMap<String, RecordSnapshot>,
}

#[derive(Serialize, Deserialize)]
struct RecordSnapshot {
    action: String,
    ua: String,
    /// Unix seconds; `null` means `Expiry::Never`.
    expires_at_secs: Option<i64>,
    commitment: Hex32,
    confirmed_height: u32,
    release_deadline_secs: i64,
    nullifier: Hex32,
}

/// Lowercase 32-byte hex string.
type Hex32 = String;

/// Whether the Mint admits the transition. A rejected claim can still
/// advance the anchor pool — rejection is about the record, not the chain.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Expectation {
    Accepted,
    Rejected,
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// Runs `events` against a fresh `Registry`, returning a snapshot after
/// each event. Panics on any scenario invariant violation (Mint API
/// contract), which is the correct signal that the scenario itself is
/// malformed rather than that the code under test is wrong.
fn run(events: &[Event]) -> Vec<Snapshot> {
    let mut registry = Registry::new();
    let mut trace = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        apply(&mut registry, event);
        trace.push(snapshot(&registry, index));
    }
    trace
}

fn apply(registry: &mut Registry, event: &Event) {
    match event {
        Event::AdoptAnchor { height, nullifier } => {
            registry.adopt_anchor(BlockHeight::from_u32(*height), nf(nullifier));
        }
        Event::Claim {
            height,
            mtp_secs,
            name,
            ua,
            expires_at_secs,
            spent_anchor,
            successor_anchor,
            nullifier,
            expect,
        } => {
            let note = NameNote::Claim {
                name: parse_name(name),
                ua: parse_ua(ua),
                expires_at: expiry(*expires_at_secs),
            };
            let ok = registry.accept_claim(
                &MainNetwork,
                &note,
                nf(nullifier),
                Some(nf(successor_anchor)),
                &[nf(spent_anchor)],
                BlockHeight::from_u32(*height),
                ts(*mtp_secs),
            );
            match *expect {
                Expectation::Accepted => assert!(ok, "backed claim was rejected: {name}"),
                Expectation::Rejected => {
                    assert!(!ok, "rejected claim overwrote the record: {name}")
                }
            }
        }
        Event::UnbackedClaim {
            height,
            mtp_secs,
            name,
            ua,
            expires_at_secs,
            spent,
        } => {
            let note = NameNote::Claim {
                name: parse_name(name),
                ua: parse_ua(ua),
                expires_at: expiry(*expires_at_secs),
            };
            let nfs: Vec<_> = spent.iter().map(|s| nf(s)).collect();
            let accepted = registry.accept_claim(
                &MainNetwork,
                &note,
                nf(&hex32_from_seed(0xFE)),
                // No successor: an unbacked claim never authored one, and
                // `accept_claim` must reject before the successor is read.
                None,
                &nfs,
                BlockHeight::from_u32(*height),
                ts(*mtp_secs),
            );
            assert!(!accepted, "unbacked claim was accepted: {name}");
        }
        Event::Update {
            height,
            mtp_secs,
            name,
            ua,
            expires_at_secs,
            prev_nullifier,
            nullifier,
        } => {
            let parsed_name = parse_name(name);
            let record = registry
                .record(&parsed_name)
                .expect("update predecessor exists");
            assert_eq!(
                record.nullifier.to_bytes(),
                nf(prev_nullifier).to_bytes(),
                "update prev_nullifier does not match current record for {name}",
            );
            let note = NameNote::Update {
                name: parsed_name.clone(),
                ua: parse_ua(ua),
                expires_at: expiry(*expires_at_secs),
                prev: record.commitment,
            };
            let ok = registry.accept_update(
                &MainNetwork,
                &note,
                nf(nullifier),
                &[nf(prev_nullifier)],
                BlockHeight::from_u32(*height),
                ts(*mtp_secs),
            );
            assert!(ok, "update was rejected: {name}");
        }
        Event::Release {
            height,
            mtp_secs,
            name,
            ua,
            prev_nullifier,
            nullifier,
        } => {
            let parsed_name = parse_name(name);
            let record = registry
                .record(&parsed_name)
                .expect("release predecessor exists");
            assert_eq!(
                record.nullifier.to_bytes(),
                nf(prev_nullifier).to_bytes(),
                "release prev_nullifier does not match current record for {name}",
            );
            let note = NameNote::Release {
                name: parsed_name.clone(),
                ua: parse_ua(ua),
                prev: record.commitment,
            };
            let ok = registry.accept_release(
                &MainNetwork,
                &note,
                nf(nullifier),
                &[nf(prev_nullifier)],
                BlockHeight::from_u32(*height),
                ts(*mtp_secs),
            );
            assert!(ok, "release was rejected: {name}");
        }
        Event::Rewind { to_height } => {
            registry.truncate_to_height(BlockHeight::from_u32(*to_height));
        }
    }
}

fn snapshot(registry: &Registry, after_event: usize) -> Snapshot {
    let mut anchor_pool: Vec<Hex32> = registry
        .anchor_pool()
        .iter()
        .map(|nf| hex::encode(nf.to_bytes()))
        .collect();
    anchor_pool.sort();
    let records: BTreeMap<String, RecordSnapshot> = registry
        .name_chain()
        .map(|(name, record)| (name.as_str().to_owned(), record_snapshot(record)))
        .collect();
    Snapshot {
        after_event,
        anchor_pool,
        records,
    }
}

fn record_snapshot(record: &zns_mint::mint::registry::NameRecord) -> RecordSnapshot {
    let ua_str = Address::Unified(record.ua.clone()).encode(&MainNetwork);
    let expires_at_secs = match record.expires_at {
        Expiry::Never => None,
        Expiry::At(t) => Some(t.as_seconds()),
    };
    RecordSnapshot {
        action: match record.action {
            Action::Claim => "claim".to_owned(),
            Action::Update => "update".to_owned(),
            Action::Release => "release".to_owned(),
        },
        ua: ua_str,
        expires_at_secs,
        commitment: hex::encode(record.commitment.to_bytes()),
        confirmed_height: u32::from(record.confirmed_height),
        release_deadline_secs: record.release_deadline.as_seconds(),
        nullifier: hex::encode(record.nullifier.to_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A real mainnet UA with every known receiver kind — Orchard, Sapling,
/// and P2PKH.
const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

fn parse_ua(s: &str) -> UnifiedAddress {
    match Address::decode(&MainNetwork, s) {
        Some(Address::Unified(ua)) => ua,
        _ => panic!("scenario UA is not a mainnet Unified Address: {s}"),
    }
}

fn parse_name(s: &str) -> Name {
    Name::parse(s).unwrap_or_else(|| panic!("scenario name is not a valid ZNS name: {s}"))
}

fn expiry(secs: Option<i64>) -> Expiry {
    match secs {
        None => Expiry::Never,
        Some(t) => Expiry::At(Timestamp::from_seconds(t).expect("expiry fits Timestamp")),
    }
}

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_seconds(secs).expect("MTP fits Timestamp")
}

/// Parses a lowercase 32-byte hex nullifier.
fn nf(hex_str: &str) -> orchard::note::Nullifier {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut bytes)
        .unwrap_or_else(|_| panic!("nullifier hex is not 32 bytes: {hex_str}"));
    orchard::note::Nullifier::from_bytes(&bytes)
        .into_option()
        .unwrap_or_else(|| panic!("nullifier hex is not a Pallas base element: {hex_str}"))
}

/// Builds a deterministic 32-byte nullifier hex from a single-byte seed.
///
/// Any `[u8; 32]` whose top two bits are zero is a valid Pallas base
/// element; placing the seed in the low byte keeps the number small.
fn hex32_from_seed(seed: u8) -> Hex32 {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Scenario builders
// ---------------------------------------------------------------------------

/// Scans a small ceremony of five zero-value Registry outputs. Verifies
/// that adoption is in canonical scan order and that the pool never
/// exceeds standing size (kept small here — the full `ANCHOR_POOL_SIZE`
/// case is exercised in the anchor pool's unit tests).
fn ceremony_fill() -> Scenario {
    let events: Vec<Event> = (1..=5)
        .map(|i| Event::AdoptAnchor {
            height: 100 + i,
            nullifier: hex32_from_seed(i as u8),
        })
        .collect();
    Scenario {
        name: "ceremony_fill".to_owned(),
        description: "Five zero-value Registry outputs enter the anchor pool in scan order."
            .to_owned(),
        trace: run(&events),
        events,
    }
}

/// A single backed Claim retires one anchor, adopts a successor, binds
/// the name.
fn backed_claim() -> Scenario {
    let a1 = hex32_from_seed(0x01);
    let s1 = hex32_from_seed(0xC1);
    let n1 = hex32_from_seed(0xA1);
    let events = vec![
        Event::AdoptAnchor {
            height: 100,
            nullifier: a1.clone(),
        },
        Event::Claim {
            height: 110,
            mtp_secs: 1_700_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            spent_anchor: a1,
            successor_anchor: s1,
            nullifier: n1,
            expect: Expectation::Accepted,
        },
    ];
    Scenario {
        name: "backed_claim".to_owned(),
        description: "First claim retires a live anchor and adopts its successor.".to_owned(),
        trace: run(&events),
        events,
    }
}

/// Attacker case: an unbacked "Claim" that spends no live anchor. Mint
/// drops it; any consumer must drop it.
fn unbacked_claim() -> Scenario {
    let a1 = hex32_from_seed(0x01);
    let events = vec![
        Event::AdoptAnchor {
            height: 100,
            nullifier: a1,
        },
        // Unrelated non-anchor nullifier — an ordinary payment input.
        Event::UnbackedClaim {
            height: 110,
            mtp_secs: 1_700_000_000,
            name: "mallory".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            spent: vec![hex32_from_seed(0xEE)],
        },
    ];
    Scenario {
        name: "unbacked_claim".to_owned(),
        description: "A commitment-valid Claim that spent no anchor must not enter Registry state."
            .to_owned(),
        trace: run(&events),
        events,
    }
}

/// Two backed Claims for the same name: the pool advances both times,
/// the first registration stands.
fn duplicate_claim() -> Scenario {
    let a1 = hex32_from_seed(0x01);
    let a2 = hex32_from_seed(0x02);
    let s1 = hex32_from_seed(0xC1);
    let s2 = hex32_from_seed(0xC2);
    let n1 = hex32_from_seed(0xA1);
    let n2 = hex32_from_seed(0xA2);
    let events = vec![
        Event::AdoptAnchor {
            height: 100,
            nullifier: a1.clone(),
        },
        Event::AdoptAnchor {
            height: 100,
            nullifier: a2.clone(),
        },
        Event::Claim {
            height: 110,
            mtp_secs: 1_700_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            spent_anchor: a1,
            successor_anchor: s1,
            nullifier: n1,
            expect: Expectation::Accepted,
        },
        // Second backed claim for the same live name: rejected for the
        // record, accepted for the pool — the anchor is still retired
        // and the successor adopted.
        Event::Claim {
            height: 120,
            mtp_secs: 1_700_100_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            spent_anchor: a2,
            successor_anchor: s2,
            nullifier: n2,
            expect: Expectation::Rejected,
        },
    ];
    Scenario {
        name: "duplicate_claim".to_owned(),
        description: "Second backed claim on a live name advances the anchor pool without \
             changing the registration."
            .to_owned(),
        trace: run(&events),
        events,
    }
}

/// Claim after Release: the second Claim succeeds because the current
/// record's action is Release.
fn claim_after_release() -> Scenario {
    let a1 = hex32_from_seed(0x01);
    let a2 = hex32_from_seed(0x02);
    let s1 = hex32_from_seed(0xC1);
    let s2 = hex32_from_seed(0xC2);
    let n1 = hex32_from_seed(0xA1);
    let n_release = hex32_from_seed(0xB1);
    let n2 = hex32_from_seed(0xA2);
    let events = vec![
        Event::AdoptAnchor {
            height: 100,
            nullifier: a1.clone(),
        },
        Event::AdoptAnchor {
            height: 100,
            nullifier: a2.clone(),
        },
        Event::Claim {
            height: 110,
            mtp_secs: 1_700_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            spent_anchor: a1,
            successor_anchor: s1,
            nullifier: n1.clone(),
            expect: Expectation::Accepted,
        },
        Event::Release {
            height: 200,
            mtp_secs: 1_710_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            prev_nullifier: n1,
            nullifier: n_release,
        },
        Event::Claim {
            height: 300,
            mtp_secs: 1_720_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            spent_anchor: a2,
            successor_anchor: s2,
            nullifier: n2,
            expect: Expectation::Accepted,
        },
    ];
    Scenario {
        name: "claim_after_release".to_owned(),
        description: "A new Claim after Release binds the name to the second claimant.".to_owned(),
        trace: run(&events),
        events,
    }
}

/// Update followed by voluntary Release, both spending the current
/// record's nullifier.
fn update_then_release() -> Scenario {
    let a1 = hex32_from_seed(0x01);
    let s1 = hex32_from_seed(0xC1);
    let n_claim = hex32_from_seed(0xA1);
    let n_update = hex32_from_seed(0xA2);
    let n_release = hex32_from_seed(0xA3);
    let events = vec![
        Event::AdoptAnchor {
            height: 100,
            nullifier: a1.clone(),
        },
        Event::Claim {
            height: 110,
            mtp_secs: 1_700_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: Some(2_000_000_000),
            spent_anchor: a1,
            successor_anchor: s1,
            nullifier: n_claim.clone(),
            expect: Expectation::Accepted,
        },
        Event::Update {
            height: 200,
            mtp_secs: 1_710_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: Some(2_100_000_000),
            prev_nullifier: n_claim,
            nullifier: n_update.clone(),
        },
        Event::Release {
            height: 300,
            mtp_secs: 1_720_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            prev_nullifier: n_update,
            nullifier: n_release,
        },
    ];
    Scenario {
        name: "update_then_release".to_owned(),
        description: "Cross-block Update, then voluntary Release, both spending the \
                      exact current record."
            .to_owned(),
        trace: run(&events),
        events,
    }
}

/// Reorg: apply a claim and an update, then rewind past both.
fn reorg() -> Scenario {
    let a1 = hex32_from_seed(0x01);
    let s1 = hex32_from_seed(0xC1);
    let n_claim = hex32_from_seed(0xA1);
    let n_update = hex32_from_seed(0xA2);
    let events = vec![
        Event::AdoptAnchor {
            height: 100,
            nullifier: a1.clone(),
        },
        Event::Claim {
            height: 110,
            mtp_secs: 1_700_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            spent_anchor: a1,
            successor_anchor: s1,
            nullifier: n_claim.clone(),
            expect: Expectation::Accepted,
        },
        Event::Update {
            height: 200,
            mtp_secs: 1_710_000_000,
            name: "alice".to_owned(),
            ua: TEST_UA.to_owned(),
            expires_at_secs: None,
            prev_nullifier: n_claim,
            nullifier: n_update,
        },
        // Rewind past both the update and the claim — pool and records
        // return to their post-ceremony state.
        Event::Rewind { to_height: 100 },
    ];
    Scenario {
        name: "reorg".to_owned(),
        description: "Rewind after Claim + Update returns Registry to its pre-Claim state."
            .to_owned(),
        trace: run(&events),
        events,
    }
}

// ---------------------------------------------------------------------------
// Fixture drift test
// ---------------------------------------------------------------------------

fn build_vectors() -> Vectors {
    Vectors {
        version: "canon-vectors-v1".to_owned(),
        anchor_pool_size: ANCHOR_POOL_SIZE,
        scenarios: vec![
            ceremony_fill(),
            backed_claim(),
            unbacked_claim(),
            duplicate_claim(),
            claim_after_release(),
            update_then_release(),
            reorg(),
        ],
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("canon-vectors-v1.json")
}

/// Emits and drift-checks the fixture in one test. Run with
/// `CANON_VECTORS_REGEN=1` to overwrite; without the env var, the test
/// fails on any drift from the committed file.
#[test]
fn canon_vectors_v1_matches_fixture() {
    let vectors = build_vectors();
    let generated = serde_json::to_string_pretty(&vectors).expect("serialize vectors");
    let path = fixture_path();

    if std::env::var("CANON_VECTORS_REGEN").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).expect("create fixtures dir");
        std::fs::write(&path, format!("{generated}\n")).expect("write fixture");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "canon-vectors-v1 fixture missing at {}: {e}.\n\
             Generate it with:\n\
             \n\
             \tCANON_VECTORS_REGEN=1 cargo test --test canon_vectors\n",
            path.display(),
        )
    });
    if committed.trim() != generated.trim() {
        panic!(
            "canon-vectors-v1 drift.\n\
             Regenerate with:\n\
             \n\
             \tCANON_VECTORS_REGEN=1 cargo test --test canon_vectors\n\
             \n\
             …then review the diff before committing.",
        );
    }
}
