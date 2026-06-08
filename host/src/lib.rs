//! `zns-registry` — ZcashName (ZNS) minting and registry logic.
//!
//! # Overview
//!
//! The [`Registry`] struct is the top-level entry point.  It:
//!
//! 1. Scans incoming Orchard notes addressed to `addr_reg` over lightwalletd's
//!    compact-block proto (standard ZIP-212; see [`scanner`]).
//! 2. Parses ZNS memos from those notes (see [`memo`]).
//! 3. For **CLAIM**: verifies that the fee ≥ minimum and mints immediately.
//! 4. For **UPDATE/RELEASE**: initiates OTP auth ([`zns_auth::AuthModule`]),
//!    waits for a confirm note, then mints.
//! 5. Mints Name Notes: computes `(rcm, psi)` via [`zns_verify::zns_psi_rcm`],
//!    builds the Orchard action via the `zns-orchard` fork (see [`mint`]).
//! 6. Persists per-name `rcm` tips in SQLite (see [`db`]).
//! 7. Broadcasts transactions via zebrad gRPC (see [`grpc`]).

// Host-owned modules (orchestration + chain I/O).
pub mod grpc;
pub mod scanner;

// Flat API surface — re-export the shared `core` and crypto `signer` crates so
// `zns_host::{parse_memo, build_name_note, NameRecord, ...}` keep resolving.
pub use zns_core::{db, memo, parse_memo, NameRecord, ParsedMemo, RegistryError};
pub use zns_signer::{build_name_note, expected_cmx, verify_cmx, MintParams, MintResult};
pub use grpc::GrpcClient;
pub use scanner::{scan_incoming, IncomingNote, ScannerConfig};

use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::Mutex;
use zns_auth::AuthModule;
use zns_verify::ZERO_PREV_RCM;

/// Minimum fee in zatoshis required for a CLAIM operation.
pub const MIN_CLAIM_FEE_ZAT: u64 = 10_000; // 0.0001 ZEC

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// The ZNS registry.
///
/// Cheaply cloneable — the inner state is behind `Arc`s.
#[derive(Clone)]
pub struct Registry {
    /// SQLite connection shared across the tokio runtime.
    db: Arc<Mutex<Connection>>,
    /// OTP challenge-response state for UPDATE / RELEASE.
    auth: Arc<AuthModule>,
    /// lightwalletd gRPC endpoint (e.g. `"http://127.0.0.1:9067"`) used to
    /// broadcast minted Name Notes via `SendTransaction`.
    grpc_addr: String,
}

impl Registry {
    /// Open (or create) the registry database at `db_path` and return a new
    /// [`Registry`] pointing at `grpc_addr` for transaction broadcast.
    pub fn new(
        db_path: &str,
        grpc_addr: impl Into<String>,
    ) -> Result<Self, RegistryError> {
        let conn = Connection::open(db_path)?;
        db::init_schema(&conn)?;
        Ok(Registry {
            db: Arc::new(Mutex::new(conn)),
            auth: Arc::new(AuthModule::new()),
            grpc_addr: grpc_addr.into(),
        })
    }

    /// Open an in-memory registry (for testing / ephemeral use).
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        let conn = Connection::open_in_memory()?;
        db::init_schema(&conn)?;
        Ok(Registry {
            db: Arc::new(Mutex::new(conn)),
            auth: Arc::new(AuthModule::new()),
            grpc_addr: "http://127.0.0.1:9067".into(),
        })
    }

    // -----------------------------------------------------------------------
    // Query API
    // -----------------------------------------------------------------------

    /// Look up a registered name.  Returns `None` if the name is unknown.
    pub async fn lookup(&self, name: &str) -> Result<Option<NameRecord>, RegistryError> {
        let conn = self.db.lock().await;
        db::get_record(&conn, name)
    }

    // -----------------------------------------------------------------------
    // Processing incoming notes
    // -----------------------------------------------------------------------

    /// Process a batch of [`IncomingNote`]s that arrived at `addr_reg`.
    ///
    /// Each note's memo is parsed; the appropriate action is dispatched.
    /// Errors for individual notes are logged and skipped (best-effort).
    pub async fn process_notes(
        &self,
        notes: &[IncomingNote],
        mint_ctx: &MintContext,
    ) -> Vec<ProcessResult> {
        let mut results = Vec::new();
        for note in notes {
            if !note.is_received {
                continue; // skip OVK-recovered sent notes
            }
            let res = self.process_note(note, mint_ctx).await;
            results.push(res);
        }
        results
    }

    async fn process_note(
        &self,
        note: &IncomingNote,
        mint_ctx: &MintContext,
    ) -> ProcessResult {
        let parsed = match parse_memo(&note.memo) {
            Ok(m) => m,
            Err(e) => {
                return ProcessResult::Skipped(format!("memo parse error: {e}"));
            }
        };

        match &parsed {
            ParsedMemo::Action {
                action,
                name,
                ua,
            } => {
                match self
                    .handle_action(*action, name, ua, note.value_zat, mint_ctx)
                    .await
                {
                    Ok(outcome) => ProcessResult::Ok(outcome),
                    Err(e) => ProcessResult::Err(name.clone(), e.to_string()),
                }
            }
            ParsedMemo::Confirm { name, nonce } => {
                match self.handle_confirm(name, nonce, mint_ctx).await {
                    Ok(outcome) => ProcessResult::Ok(outcome),
                    Err(e) => ProcessResult::Err(name.clone(), e.to_string()),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal action handlers
    // -----------------------------------------------------------------------

    async fn handle_action(
        &self,
        action: zns_verify::Action,
        name: &str,
        ua: &str,
        value_zat: u64,
        mint_ctx: &MintContext,
    ) -> Result<ActionOutcome, RegistryError> {
        match action {
            zns_verify::Action::Claim => {
                // 1. Verify fee.
                if value_zat < MIN_CLAIM_FEE_ZAT {
                    return Err(RegistryError::InsufficientFee {
                        got: value_zat,
                        need: MIN_CLAIM_FEE_ZAT,
                    });
                }

                // 2. Ensure name is not already taken.
                {
                    let conn = self.db.lock().await;
                    if db::get_record(&conn, name)?.is_some() {
                        return Err(RegistryError::AlreadyClaimed(name.into()));
                    }
                }

                // 3. Mint the Name Note.
                let result = self
                    .do_mint(action, name, ua, &ZERO_PREV_RCM, mint_ctx)
                    .await?;

                // 4. Persist the new record.
                {
                    let conn = self.db.lock().await;
                    db::upsert_record(&conn, name, &result.new_rcm, ua, mint_ctx.height)?;
                }

                Ok(ActionOutcome::Minted {
                    name: name.into(),
                    action,
                })
            }

            zns_verify::Action::Update | zns_verify::Action::Release => {
                // Name must exist.
                let record = {
                    let conn = self.db.lock().await;
                    db::get_record(&conn, name)?.ok_or_else(|| {
                        RegistryError::NotFound(name.into())
                    })?
                };

                // Convert action for auth module.
                let auth_action = match action {
                    zns_verify::Action::Update => zns_auth::Action::Update,
                    zns_verify::Action::Release => zns_auth::Action::Release,
                    _ => unreachable!(),
                };

                // Initiate OTP challenge — nonce will be sent to current owner.
                let (_nonce, send_to) = self
                    .auth
                    .new_challenge(name, auth_action, ua, &record.ua)
                    .await?;

                Ok(ActionOutcome::ChallengeIssued {
                    name: name.into(),
                    send_to,
                })
            }
        }
    }

    async fn handle_confirm(
        &self,
        name: &str,
        nonce: &str,
        mint_ctx: &MintContext,
    ) -> Result<ActionOutcome, RegistryError> {
        // Verify the OTP.
        let challenge = self.auth.verify_confirm(name, nonce).await?;

        // Look up the current record (for prev_rcm).
        let prev_rcm = {
            let conn = self.db.lock().await;
            match db::get_record(&conn, name)? {
                Some(rec) => rec.tip_rcm,
                None => return Err(RegistryError::NotFound(name.into())),
            }
        };

        // Convert auth action back to zns_verify action.
        let action = match challenge.action {
            zns_auth::Action::Update => zns_verify::Action::Update,
            zns_auth::Action::Release => zns_verify::Action::Release,
            zns_auth::Action::Claim => return Err(RegistryError::InvalidMemo(
                "confirm for Claim is not valid".into(),
            )),
        };

        let ua = &challenge.ua_new;

        // Mint the Name Note.
        let result = self
            .do_mint(action, name, ua, &prev_rcm, mint_ctx)
            .await?;

        // Update or delete the DB record.
        {
            let conn = self.db.lock().await;
            if action == zns_verify::Action::Release {
                db::delete_record(&conn, name)?;
            } else {
                db::upsert_record(&conn, name, &result.new_rcm, ua, mint_ctx.height)?;
            }
        }

        Ok(ActionOutcome::Minted { name: name.into(), action })
    }

    /// Build the Name Note (computing `(rcm, psi)` and the Orchard action) and
    /// broadcast it via `grpc_addr` before the caller records the name.
    async fn do_mint(
        &self,
        action: zns_verify::Action,
        name: &str,
        ua: &str,
        prev_rcm: &[u8; 32],
        ctx: &MintContext,
    ) -> Result<MintResult, RegistryError> {
        let result = build_name_note(MintParams {
            action,
            name,
            ua,
            prev_rcm: *prev_rcm,
            recipient: ctx.recipient,
            registry_fvk: ctx.registry_fvk.clone(),
            anchor: ctx.anchor,
            branch_id: zcash_protocol::consensus::BranchId::Nu6,
            expiry_height: 0,
        })?;

        // Broadcast the serialized V5 transaction before the caller records the
        // name, so a failed broadcast never leaves a phantom DB record.
        GrpcClient::new(&self.grpc_addr)
            .broadcast(result.tx_bytes.clone())
            .await?;

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Contextual data the caller supplies to [`Registry::process_notes`] /
/// [`Registry::do_mint`] — the Orchard key material and current block height.
///
/// These are intentionally not stored inside [`Registry`] so that the registry
/// can be used with different key configurations at runtime (e.g. hot-swap,
/// testing).
#[derive(Clone)]
pub struct MintContext {
    /// Full Viewing Key of the registry Orchard address.
    pub registry_fvk: orchard::keys::FullViewingKey,
    /// The registry's Orchard recipient address (self-send for Name Notes).
    pub recipient: orchard::Address,
    /// Orchard commitment-tree anchor.  A value-0 Name Note only requires the
    /// empty-tree anchor (`Anchor::empty_tree()`).
    pub anchor: orchard::tree::Anchor,
    /// The current Zcash block height (used for DB records).
    pub height: u32,
}

/// The outcome of processing a single incoming note.
#[derive(Debug)]
pub enum ProcessResult {
    /// The note was not a ZNS memo (or was a sent / OVK note); skipped.
    Skipped(String),
    /// Action processed successfully.
    Ok(ActionOutcome),
    /// An error occurred while processing this note.
    Err(String, String),
}

/// What happened when an action was dispatched.
#[derive(Debug)]
pub enum ActionOutcome {
    /// A Name Note was minted (CLAIM or confirmed UPDATE/RELEASE).
    Minted {
        name: String,
        action: zns_verify::Action,
    },
    /// An OTP challenge was issued; waiting for the confirm note.
    ChallengeIssued { name: String, send_to: String },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::{
        keys::{FullViewingKey, Scope, SpendingKey},
        tree::Anchor,
    };

    fn make_context() -> MintContext {
        let seed = [0x42u8; 32];
        let sk = SpendingKey::from_zip32_seed(&seed, 133, zip32::AccountId::ZERO).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        MintContext {
            registry_fvk: fvk,
            recipient,
            anchor: Anchor::empty_tree(),
            height: 2_000_000,
        }
    }

    #[tokio::test]
    async fn claim_and_lookup() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

        let note = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: true,
        };

        let results = reg.process_notes(&[note], &ctx).await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], ProcessResult::Ok(ActionOutcome::Minted { .. })));

        let rec = reg.lookup("alice").await.unwrap().unwrap();
        assert_eq!(rec.ua, "u1xxx");
    }

    #[tokio::test]
    async fn claim_insufficient_fee() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

        let note = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: 1, // too low
            is_received: true,
        };

        let results = reg.process_notes(&[note], &ctx).await;
        assert!(matches!(results[0], ProcessResult::Err(_, _)));
    }

    #[tokio::test]
    async fn duplicate_claim_rejected() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

        let make_claim = || IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: true,
        };

        reg.process_notes(&[make_claim()], &ctx).await;
        let results = reg.process_notes(&[make_claim()], &ctx).await;
        assert!(matches!(results[0], ProcessResult::Err(_, _)));
    }

    #[tokio::test]
    async fn update_issues_challenge() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

        // First, claim the name.
        let claim = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1old";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: true,
        };
        reg.process_notes(&[claim], &ctx).await;

        // Then request an update.
        let update = IncomingNote {
            txid: [1u8; 32],
            height: 2_000_001,
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:update:alice:u1new";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: 0,
            is_received: true,
        };
        let results = reg.process_notes(&[update], &ctx).await;
        assert!(matches!(
            results[0],
            ProcessResult::Ok(ActionOutcome::ChallengeIssued { .. })
        ));
    }

    #[tokio::test]
    async fn non_zns_memo_skipped() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

        let note = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"Hello, Zcash!";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: 100_000,
            is_received: true,
        };

        let results = reg.process_notes(&[note], &ctx).await;
        assert!(matches!(results[0], ProcessResult::Skipped(_)));
    }

    #[tokio::test]
    async fn sent_notes_skipped() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

        let note = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: false, // OVK-recovered sent note
        };

        let results = reg.process_notes(&[note], &ctx).await;
        assert_eq!(results.len(), 0); // sent notes filtered before push
    }
}
