//! `zns-registry` — the ZNS registry daemon: orchestration.
//!
//! # Overview
//!
//! The [`Registry`] struct wires the other crates together, the way `zebrad`
//! composes Zebra's services. It:
//!
//! 1. Reads incoming Orchard notes addressed to the registry over lightwalletd
//!    (`zns_chain::scanner`).
//! 2. Parses ZNS memos from those notes (`zns_core::memo`).
//! 3. For **CLAIM**: verifies that the fee ≥ minimum and mints immediately.
//! 4. For **UPDATE/RELEASE**: initiates OTP auth ([`zns_auth::AuthModule`]),
//!    waits for a confirm note, then mints.
//! 5. Mints Name Notes: `zns_mint` derives `(rcm, psi)` and builds the Orchard
//!    action via the `zns-orchard` fork.
//! 6. Persists per-name `rcm` tips in SQLite (`zns_state`).
//! 7. Broadcasts transactions via zebrad gRPC (`zns_chain::grpc`).

// Flat API surface — re-export the domain, state, chain, and mint crates so
// `zns_registry::{parse_memo, build_name_note, NameRecord, ...}` resolve in one place.
pub use zns_chain::{
    scan_incoming, scan_incoming_all, scan_mempool, GrpcClient, GrpcError, IncomingNote,
    ScannerConfig,
};
pub use zns_core::{memo, parse_memo, Action, MemoError, ParsedMemo, ZERO_PREV_RCM};
pub use zns_mint::{
    build_name_note, FundingInput, MintParams, MintResult, RequestId, Signer, SpendPolicy,
};
pub use zns_state::{
    db, FundingSelection, MintedAction, NameRecord, NoteState, SpendableNote, TreasuryConfig,
};

pub mod rpc;

// ---------------------------------------------------------------------------
// Registry error type (lives here — it spans all layers)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("insufficient fee: got {got} zat, need {need} zat")]
    InsufficientFee { got: u64, need: u64 },
    #[error("name already claimed: {0}")]
    AlreadyClaimed(String),
    #[error("name not found: {0}")]
    NotFound(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("broadcast: {0}")]
    Broadcast(String),
    #[error("policy: {reason}")]
    Policy { reason: String, permanent: bool },
    #[error("invalid memo: {0}")]
    InvalidMemo(String),
    #[error(transparent)]
    Db(#[from] zns_state::StateError),
    #[error(transparent)]
    Memo(#[from] zns_core::MemoError),
    #[error(transparent)]
    Grpc(#[from] GrpcError),
    #[error(transparent)]
    Sign(#[from] zns_mint::SignError),
    #[error(transparent)]
    Build(#[from] zns_mint::BuildError),
    #[error("config: {0}")]
    Config(String),
    #[error("rpc: {0}")]
    Rpc(String),
}

impl From<rusqlite::Error> for RegistryError {
    fn from(e: rusqlite::Error) -> Self {
        RegistryError::Db(zns_state::StateError::Db(e))
    }
}

impl RegistryError {
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::InsufficientFee { .. }
            | Self::AlreadyClaimed(_)
            | Self::NotFound(_)
            | Self::Auth(_)
            | Self::InvalidMemo(_)
            | Self::Config(_)
            | Self::Rpc(_) => true,
            Self::Policy { permanent, .. } => *permanent,
            Self::Broadcast(_)
            | Self::Db(_)
            | Self::Memo(_)
            | Self::Grpc(_)
            | Self::Sign(_)
            | Self::Build(_) => false,
        }
    }
}

use std::sync::Arc;

use tokio::sync::Mutex;

/// Minimum fee in zatoshis required for a CLAIM operation.
pub const MIN_CLAIM_FEE_ZAT: u64 = 10_000; // 0.0001 ZEC

/// ZIP-317 fee for a funded mint / relay (1 spend + ≤2 outputs ⇒ 2 logical
/// actions ⇒ 5000 × 2). Also the conventional dust value carried to a recipient.
pub const MINT_FEE_ZAT: u64 = 10_000;

/// Minimum value a treasury funding note must hold: the costliest single
/// spend is the OTP challenge relay (fee + dust to the owner = 2 × fee). A
/// floor of one fee would let the selector pick a user's own dust note and
/// then fail the relay with `InsufficientFee`.
pub const FUNDING_MIN_ZAT: u64 = 2 * MINT_FEE_ZAT;

/// Minimum fee for an UPDATE / RELEASE request — covers the funded OTP relay
/// it triggers (fee + dust), so mutations can't drain the treasury.
pub const MIN_MUTATION_FEE_ZAT: u64 = 2 * MINT_FEE_ZAT;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// The ZNS registry.
///
/// Cheaply cloneable — the inner state is behind `Arc`s.
#[derive(Clone)]
pub struct Registry {
    state: Arc<Mutex<zns_state::State>>,
    grpc_addr: String,
}

impl Registry {
    /// Open (or create) the registry database at `db_path` and return a new
    /// [`Registry`] pointing at `grpc_addr` for transaction broadcast.
    pub fn new(db_path: &str, grpc_addr: impl Into<String>) -> Result<Self, RegistryError> {
        let state = zns_state::State::open(db_path)?;
        Ok(Registry {
            state: Arc::new(Mutex::new(state)),
            grpc_addr: grpc_addr.into(),
        })
    }

    /// Open an in-memory registry (for testing / ephemeral use).
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        let state = zns_state::State::open_in_memory()?;
        Ok(Registry {
            state: Arc::new(Mutex::new(state)),
            grpc_addr: "https://zec.rocks:443".into(),
        })
    }

    // -----------------------------------------------------------------------
    // Query API
    // -----------------------------------------------------------------------

    /// Look up a registered name.  Returns `None` if the name is unknown.
    pub async fn lookup(&self, name: &str) -> Result<Option<NameRecord>, RegistryError> {
        let st = self.state.lock().await;
        db::get_record(st.conn(), name).map_err(Into::into)
    }

    /// Registry table counts for the control plane's `status` method.
    pub async fn stats(&self) -> Result<RegistryStats, RegistryError> {
        let st = self.state.lock().await;
        let (names, pending_challenges, mint_intents) = db::table_counts(st.conn())?;
        Ok(RegistryStats {
            names,
            pending_challenges,
            mint_intents,
        })
    }

    /// Drop notes the intake ledger has already settled. Lets the daemon skip
    /// the O(chain) funding rescan on quiet polls — once any historical note
    /// exists, the raw scan is never empty, but the *unsettled* set usually is.
    pub async fn unsettled(&self, notes: Vec<IncomingNote>) -> Vec<IncomingNote> {
        let st = self.state.lock().await;
        notes
            .into_iter()
            .filter(|n| !db::is_processed(st.conn(), &n.txid, n.output_index).unwrap_or(false))
            .collect()
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
        // The poll's treasury note funds exactly one spend (a mint or a
        // challenge relay) — it is consumed by `take()` at the spend site.
        // Later spend-needing actions in the same batch are deferred: the
        // intake rescan re-surfaces them next poll, when a fresh funding
        // note (typically this spend's confirmed change) is selectable.
        let mut treasury = mint_ctx.treasury.clone();
        let mut results = Vec::new();
        for note in notes {
            if !note.is_received {
                continue; // skip OVK-recovered sent notes
            }
            let res = self.process_note(note, mint_ctx, &mut treasury).await;
            results.push(res);
        }
        results
    }

    async fn process_note(
        &self,
        note: &IncomingNote,
        mint_ctx: &MintContext,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> ProcessResult {
        {
            let st = self.state.lock().await;
            if db::is_processed(st.conn(), &note.txid, note.output_index).unwrap_or(false) {
                return ProcessResult::Skipped("already settled".into());
            }
        }

        // Dispatch, deciding whether this outcome *settles* the note: yes for
        // success and for permanent rejections (nothing about the note can
        // change); no for transient failures and treasury deferral, which the
        // next rescan retries.
        let (result, settled) = match &parse_memo(&note.memo) {
            // Not a ZNS memo, or one that breaks the grammar — permanent.
            Err(e) => (
                ProcessResult::Skipped(format!("memo parse error: {e}")),
                true,
            ),

            // A memo carrying the prev_rcm witness is the registry's own Name
            // Note canonical form (DESIGN.md §6) — our past mint seen again on
            // rescan, never a user request. Likewise a challenge is our own
            // outbound OTP. Both settle without action.
            Ok(ParsedMemo::Action {
                prev_rcm: Some(_),
                name,
                ..
            }) => (
                ProcessResult::Skipped(format!("registry-authored Name Note memo for {name:?}")),
                true,
            ),
            Ok(ParsedMemo::Challenge { name, .. }) => (
                ProcessResult::Skipped(format!("registry-authored challenge memo for {name:?}")),
                true,
            ),

            // Every dispatch below ends in a spend (mint or challenge relay);
            // once the poll's treasury note is consumed, defer the rest. (No
            // treasury *configured* is different — that mode still validates
            // and falls through to the unfunded paths.)
            Ok(ParsedMemo::Action {
                name,
                prev_rcm: None,
                ..
            })
            | Ok(ParsedMemo::Confirm { name, .. })
                if treasury.is_none() && mint_ctx.treasury.is_some() =>
            {
                (
                    ProcessResult::Skipped(format!(
                        "treasury consumed this poll — {name:?} deferred to the next rescan"
                    )),
                    false,
                )
            }

            Ok(ParsedMemo::Action {
                action,
                name,
                ua,
                prev_rcm: None,
            }) => {
                let request = RequestId {
                    txid: note.txid,
                    action_index: note.output_index,
                };
                match self
                    .handle_action(
                        *action,
                        name,
                        ua,
                        note.value_zat,
                        request,
                        mint_ctx,
                        treasury,
                    )
                    .await
                {
                    Ok(outcome) => (ProcessResult::Ok(outcome), true),
                    Err(e) => {
                        let settled = e.is_permanent();
                        (ProcessResult::Err(name.clone(), e.to_string()), settled)
                    }
                }
            }
            Ok(ParsedMemo::Confirm { name, nonce }) => {
                let request = RequestId {
                    txid: note.txid,
                    action_index: note.output_index,
                };
                match self
                    .handle_confirm(name, nonce, request, mint_ctx, treasury)
                    .await
                {
                    Ok(outcome) => (ProcessResult::Ok(outcome), true),
                    Err(e) => {
                        let settled = e.is_permanent();
                        (ProcessResult::Err(name.clone(), e.to_string()), settled)
                    }
                }
            }
        };

        if settled {
            let st = self.state.lock().await;
            if let Err(e) = db::mark_processed(
                st.conn(),
                &note.txid,
                note.output_index,
                note.height,
                &note.block_hash,
            ) {
                tracing::warn!("intake ledger write failed: {e}");
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Internal action handlers
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn handle_action(
        &self,
        action: zns_core::Action,
        name: &str,
        ua: &str,
        value_zat: u64,
        request: RequestId,
        mint_ctx: &MintContext,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<ActionOutcome, RegistryError> {
        match action {
            zns_core::Action::Claim => {
                // 1. Verify fee.
                if value_zat < MIN_CLAIM_FEE_ZAT {
                    return Err(RegistryError::InsufficientFee {
                        got: value_zat,
                        need: MIN_CLAIM_FEE_ZAT,
                    });
                }

                // 2. Ensure name is not already taken.
                {
                    let st = self.state.lock().await;
                    if db::get_record(st.conn(), name)?.is_some() {
                        return Err(RegistryError::AlreadyClaimed(name.into()));
                    }
                }

                // 3. Mint the Name Note, then commit its persistence atomically.
                let result = self
                    .do_mint(
                        action,
                        name,
                        ua,
                        &ZERO_PREV_RCM,
                        request,
                        mint_ctx,
                        treasury,
                    )
                    .await?;
                self.persist_mint(&minted_action(
                    name,
                    action,
                    ua,
                    &result,
                    mint_ctx.height,
                    ZERO_PREV_RCM,
                ))
                    .await?;

                Ok(ActionOutcome::Minted {
                    name: name.into(),
                    action,
                })
            }

            zns_core::Action::Update | zns_core::Action::Release => {
                // 1. Verify fee. A mutation costs the treasury a funded relay
                //    (fee + dust, and the dust lands at the *owner's* UA) —
                //    free mutations would let an attacker updating their own
                //    name drain the treasury at one relay per poll while
                //    recouping the dust.
                if value_zat < MIN_MUTATION_FEE_ZAT {
                    return Err(RegistryError::InsufficientFee {
                        got: value_zat,
                        need: MIN_MUTATION_FEE_ZAT,
                    });
                }

                // Name must exist.
                let record = {
                    let st = self.state.lock().await;
                    db::get_record(st.conn(), name)?
                        .ok_or_else(|| RegistryError::NotFound(name.into()))?
                };

                // Initiate the OTP challenge: persist it durably *first* (a
                // failed relay retries with a fresh challenge next poll; a
                // relayed nonce that was never persisted would be
                // unconfirmable), then relay the nonce to the current owner.
                let challenge = zns_auth::new_challenge(name, action, ua, mint_ctx.height)
                    .map_err(|e| RegistryError::Auth(e.to_string()))?;
                {
                    let st = self.state.lock().await;
                    db::purge_expired_challenges(st.conn(), mint_ctx.height)?;
                    db::put_challenge(st.conn(), &challenge)?;
                }

                self.relay_challenge(
                    name,
                    &record.ua,
                    &challenge.nonce,
                    request,
                    mint_ctx,
                    treasury,
                )
                .await?;

                Ok(ActionOutcome::ChallengeIssued {
                    name: name.into(),
                    send_to: record.ua,
                })
            }
        }
    }

    async fn handle_confirm(
        &self,
        name: &str,
        nonce: &str,
        request: RequestId,
        mint_ctx: &MintContext,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<ActionOutcome, RegistryError> {
        let challenge = {
            let st = self.state.lock().await;
            db::get_challenge(st.conn(), name)?
        }
        .ok_or_else(|| RegistryError::Auth(format!("no pending challenge for name '{name}'")))?;
        zns_auth::verify(&challenge, nonce, mint_ctx.height)
            .map_err(|e| RegistryError::Auth(e.to_string()))?;

        let prev_rcm = {
            let st = self.state.lock().await;
            match db::get_record(st.conn(), name)? {
                Some(rec) => rec.tip_rcm,
                None => return Err(RegistryError::NotFound(name.into())),
            }
        };

        let action = challenge.action;
        let ua = &challenge.ua_new;

        // Mint the Name Note, then commit record + challenge consumption +
        // intent clearance in one transaction — a duplicate confirm after
        // this point finds no challenge and cannot re-mint.
        let result = self
            .do_mint(action, name, ua, &prev_rcm, request, mint_ctx, treasury)
            .await?;
        self.persist_mint(&minted_action(
            name,
            action,
            ua,
            &result,
            mint_ctx.height,
            prev_rcm,
        ))
            .await?;

        Ok(ActionOutcome::Minted {
            name: name.into(),
            action,
        })
    }

    /// Build the Name Note (computing `(rcm, psi)` and the Orchard action) and
    /// broadcast it via `grpc_addr` before the caller records the name.
    #[allow(clippy::too_many_arguments)]
    async fn do_mint(
        &self,
        action: zns_core::Action,
        name: &str,
        ua: &str,
        prev_rcm: &[u8; 32],
        request: RequestId,
        ctx: &MintContext,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<MintResult, RegistryError> {
        {
            let st = self.state.lock().await;
            if db::get_intent(st.conn(), name)?.is_some() {
                return Err(RegistryError::Broadcast(format!(
                    "mint intent for {name:?} pending reconciliation"
                )));
            }
        }

        // Self-funded mint when a treasury note is available: the host
        // proposes pure *intent* and the policy-gated signer authors,
        // validates, and signs the spend (fee cap, low-watermark pause,
        // replay set, velocity cap — zns_mint::policy). The note is
        // consumed here (`take`) so a later action in the same poll cannot
        // double-spend it. Without treasury, fall back to the unfunded
        // value-0 note (won't pass stock consensus; testing).
        let result = match treasury.take() {
            Some(treasury) => {
                let intent = zns_mint::MintIntent {
                    action,
                    name: name.to_owned(),
                    ua: ua.to_owned(),
                    prev_rcm: *prev_rcm,
                    fee_zat: MINT_FEE_ZAT,
                    request_id: request,
                };
                ctx.signer
                    .sign_mint(
                        zns_mint::MintProposal {
                            intent,
                            funding: treasury.funding_input(),
                        },
                        ctx.hot_balance_zat,
                        ctx.branch_id,
                        ctx.expiry_height,
                        ctx.circuit_version,
                    )
                    .map_err(registry_err)?
            }
            None => build_name_note(MintParams {
                action,
                name,
                ua,
                prev_rcm: *prev_rcm,
                recipient: ctx.signer.registry_address(),
                registry_fvk: ctx.signer.fvk().clone(),
                anchor: ctx.anchor,
                branch_id: ctx.branch_id,
                expiry_height: ctx.expiry_height,
                circuit_version: ctx.circuit_version,
            })?,
        };

        {
            let st = self.state.lock().await;
            db::put_intent(
                st.conn(),
                &db::PendingMint {
                    minted: minted_action(name, action, ua, &result, ctx.height, *prev_rcm),
                    expiry_height: ctx.expiry_height,
                    request: (request.txid, request.action_index),
                },
            )?;
        }
        if let Err(e) = GrpcClient::new(&self.grpc_addr)
            .broadcast(result.tx_bytes.clone())
            .await
        {
            // A definitive node rejection means the tx was never admitted:
            // clear the intent and release the request now (a retry can
            // re-sign immediately, e.g. after funding contention clears).
            // Ambiguous failures — timeouts, transport errors — leave the
            // intent for reconciliation: the tx may still be in flight.
            if matches!(e, GrpcError::Rejected { .. }) {
                let st = self.state.lock().await;
                let _ = db::delete_intent(st.conn(), name);
                ctx.signer.release_request(request);
            }
            return Err(e.into());
        }

        Ok(result)
    }

    /// Commit a broadcast mint in one transaction: append to the canonical
    /// action log (the source of truth for the `(ψ, rcm)` chain), fold the
    /// Append the action to the canonical `name_events` history, then update
    /// (or delete) the live `names` row, consume the challenge, and clear the
    /// intent. One atomic step shared by CLAIM, confirmed mutations, and
    /// crash reconciliation — partial persistence cannot exist.
    async fn persist_mint(&self, minted: &MintedAction) -> Result<(), RegistryError> {
        let st = self.state.lock().await;
        st.apply_mint(minted)?;
        Ok(())
    }

    /// Resolve any mint intents that survived a crash: an intent whose txid
    /// the chain knows is replayed into [`Self::persist_mint`]; one whose tx
    /// expired unmined is dropped (the triggering request note was never
    /// settled, so it retries naturally). In-flight intents are left alone.
    pub async fn reconcile_intents(
        &self,
        grpc: &GrpcClient,
        signer: &Signer,
        tip_height: u32,
    ) -> Result<(), RegistryError> {
        let intents = {
            let st = self.state.lock().await;
            db::list_intents(st.conn())?
        };
        for intent in intents {
            let name = &intent.minted.name;
            if grpc.transaction_exists(&intent.minted.txid).await? {
                tracing::warn!(
                    name,
                    txid = hex::encode(intent.minted.txid),
                    "reconciling: broadcast tx found on chain, replaying persistence"
                );
                self.persist_mint(&intent.minted).await?;
            } else if intent.expiry_height > 0 && tip_height > intent.expiry_height {
                tracing::warn!(name, "dropping mint intent — tx expired unmined");
                signer.release_request(RequestId {
                    txid: intent.request.0,
                    action_index: intent.request.1,
                });
                let st = self.state.lock().await;
                st.delete_intent(name)?;
            }
        }
        Ok(())
    }

    /// Detect a chain reorg and roll back any registry state that was based on
    /// the orphaned branch.
    ///
    /// Returns `Ok(Some(reorg_height))` if a reorg was handled, `Ok(None)` if
    /// the chain and our ledger still agree. The caller should skip minting for
    /// this poll if a reorg was detected, to give the rolled-back notes a
    /// chance to reappear on the canonical chain.
    pub async fn handle_reorg(
        &self,
        grpc: &GrpcClient,
        signer: &Signer,
        tip_height: u32,
    ) -> Result<Option<u32>, RegistryError> {
        let st = self.state.lock().await;

        let Some(last_height) = db::last_processed_height(st.conn())? else {
            return Ok(None);
        };

        // If our last settled height is above the tip, the chain has definitely
        // reorganized away from our view.
        let reorg_height = if last_height > tip_height {
            tip_height.saturating_add(1)
        } else {
            let Some(stored_hash) = db::processed_hash_at_height(st.conn(), last_height)? else {
                return Ok(None);
            };
            let current_hash = grpc.block_hash(last_height).await?;
            if stored_hash == current_hash {
                return Ok(None);
            }

            let mut h = last_height;
            loop {
                let Some(stored) = db::processed_hash_at_height(st.conn(), h)? else {
                    break 0;
                };
                let current = grpc.block_hash(h).await?;
                if stored == current {
                    break h.saturating_add(1);
                }
                if h == 0 {
                    break 0;
                }
                h -= 1;
            }
        };

        let affected = st.apply_reorg(reorg_height, |(txid, idx)| {
            signer.release_request(RequestId {
                txid,
                action_index: idx,
            });
        })?;

        tracing::warn!(
            reorg_height,
            affected_names = affected,
            "chain reorg detected: rolled back registry state"
        );
        Ok(Some(reorg_height))
    }

    /// Relay an OTP nonce to a name's current owner by sending them a
    /// `ZNS:challenge:<name>:<nonce>` memo. Without this the owner never learns
    /// the nonce and UPDATE / RELEASE can never be confirmed.
    ///
    /// The relay goes through the signer's bounded exception
    /// ([`zns_mint::Signer::sign_relay`]): dust + fee are policy-capped, the
    /// triggering request is replay-protected, and a velocity slot is
    /// consumed. It requires treasury spend material; without it the
    /// challenge cannot be delivered.
    #[allow(clippy::too_many_arguments)]
    async fn relay_challenge(
        &self,
        name: &str,
        owner_ua: &str,
        nonce: &str,
        request: RequestId,
        ctx: &MintContext,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<(), RegistryError> {
        let memo_text = memo::encode_challenge(name, nonce);
        let memo_bytes = memo::encode_memo_bytes(&memo_text)?;
        let recipient = parse_orchard_recipient(owner_ua, ctx.network)?;

        // Consume the poll's funding note (`take`) — see `do_mint`.
        let treasury = treasury.take().ok_or_else(|| {
            RegistryError::Broadcast(
                "cannot relay OTP challenge: no treasury funding configured".into(),
            )
        })?;

        let tx_bytes = ctx
            .signer
            .sign_relay(
                recipient,
                memo_bytes,
                treasury.funding_input(),
                request,
                ctx.hot_balance_zat,
                ctx.branch_id,
                ctx.expiry_height,
                ctx.circuit_version,
            )
            .map_err(registry_err)?;

        GrpcClient::new(&self.grpc_addr).broadcast(tx_bytes).await?;
        Ok(())
    }
}

/// The action-log row for a freshly built mint.
/// `prev_rcm` is the input rcm used for this note's `(ψ, rcm)` derivation
/// (ZERO for claim; prior tip's rcm for update/release). It is stored both
/// in the history event and (for the live tip) in the `names` row.
fn minted_action(
    name: &str,
    action: zns_core::Action,
    ua: &str,
    result: &MintResult,
    height: u32,
    prev_rcm: [u8; 32],
) -> MintedAction {
    MintedAction {
        name: name.to_owned(),
        action,
        ua: ua.to_owned(),
        txid: result.txid,
        cmx: result.cmx,
        rcm: result.new_rcm,
        psi: result.new_psi,
        prev_rcm,
        height,
    }
}

/// Carry a [`zns_mint::SignError`] across the crate boundary, preserving
/// the permanence class the intake ledger settles on.
fn registry_err(e: zns_mint::SignError) -> RegistryError {
    use zns_mint::{PolicyError, SignError};
    match e {
        SignError::Build(e) => RegistryError::Build(e),
        SignError::InvalidSeed(s) => RegistryError::Config(format!("invalid signer seed: {s}")),
        SignError::Policy(p) => {
            let permanent = matches!(
                p,
                PolicyError::NameInvalid(_)
                    | PolicyError::EmptyUa
                    | PolicyError::FeeTooHigh { .. }
                    | PolicyError::Replay(_)
            );
            RegistryError::Policy {
                reason: format!("{p:?}"),
                permanent,
            }
        }
    }
}

/// Parse a name owner's Unified Address string into its Orchard receiver, which
/// the registry needs to address the OTP relay note.
fn parse_orchard_recipient(
    ua: &str,
    network: zcash_protocol::consensus::Network,
) -> Result<orchard::Address, RegistryError> {
    use zcash_keys::address::Address;
    match Address::decode(&network, ua) {
        Some(Address::Unified(addr)) => addr
            .orchard()
            .copied()
            .ok_or_else(|| RegistryError::InvalidMemo(format!("UA has no Orchard receiver: {ua}"))),
        _ => Err(RegistryError::InvalidMemo(format!(
            "owner address is not a valid Unified Address: {ua}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Contextual data the caller supplies to [`Registry::process_notes`] /
/// [`Registry::do_mint`] — the signing authority and current block height.
///
/// These are intentionally not stored inside [`Registry`] so that the registry
/// can be used with different key configurations at runtime (e.g. hot-swap,
/// testing).
#[derive(Clone)]
pub struct MintContext {
    /// The policy-gated signing authority. The only path to a signature; the
    /// registry proposes intent, never touches key material.
    pub signer: Arc<zns_mint::Signer>,
    /// Current spendable treasury balance, for the signer's low-watermark
    /// pause. The daemon refreshes it each poll from funding selection.
    pub hot_balance_zat: u64,
    /// Orchard commitment-tree anchor.  A value-0 Name Note only requires the
    /// empty-tree anchor (`Anchor::empty_tree()`).
    pub anchor: orchard::tree::Anchor,
    /// The current Zcash block height (used for DB records).
    pub height: u32,
    /// Block height at which built transactions expire (0 = no expiry).
    pub expiry_height: u32,
    /// The network the registry operates on — needed to decode owner UAs.
    pub network: zcash_protocol::consensus::Network,
    /// Orchard circuit version to prove against — must match the target chain's
    /// active upgrade (NU6 → `InsecurePreNu6_2`; NU6.2+ → `FixedPostNu6_2`).
    pub circuit_version: orchard::circuit::OrchardCircuitVersion,
    /// Consensus branch id for the target chain's active upgrade (e.g. `Nu6` for
    /// a NU6 chain, `Nu6_2` post-NU6.2). Embedded in the tx + the sighash.
    pub branch_id: zcash_protocol::consensus::BranchId,
    /// Treasury spend material for funded sends. `None` means unfunded mode
    /// (testing); relays then fail with a clear "no treasury funding
    /// configured" error rather than silently no-op'ing. Behind an `Arc`
    /// because [`zns_mint::FundingInput`] is not `Clone`.
    pub treasury: Option<Arc<Treasury>>,
}

/// Treasury spend material: a registry note with its witness and anchor,
/// selected by the daemon from note-state. **No key material** — signing
/// authority lives exclusively in the [`zns_mint::Signer`]. Change always
/// returns to the registry self-address (a policy constant).
pub struct Treasury {
    /// The treasury note being spent, with its Merkle witness and anchor.
    pub funding: zns_mint::FundingInput,
}

impl Treasury {
    /// An owned [`zns_mint::FundingInput`] for a proposal (the note and
    /// anchor are `Copy`; only the witness clones).
    pub fn funding_input(&self) -> zns_mint::FundingInput {
        zns_mint::FundingInput {
            note: self.funding.note,
            merkle_path: self.funding.merkle_path.clone(),
            anchor: self.funding.anchor,
        }
    }
}

/// Registry table counts, served by the control plane's `status` method.
#[derive(Debug, Clone, Copy)]
pub struct RegistryStats {
    /// Currently registered names.
    pub names: u64,
    /// Pending (unconfirmed, unexpired-or-not-yet-purged) OTP challenges.
    pub pending_challenges: u64,
    /// In-flight mint intents awaiting persistence or reconciliation.
    pub mint_intents: u64,
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
        action: zns_core::Action,
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
        let registry_addr = fvk.address_at(0u32, Scope::External);
        // A permissive policy: these tests exercise registry orchestration,
        // not the gate (the gate has its own tests in zns-signer).
        let policy = SpendPolicy {
            registry_addr,
            cold_addr: registry_addr,
            max_fee_zat: MINT_FEE_ZAT,
            target_float_zat: 0,
            high_watermark_zat: u64::MAX,
            low_watermark_zat: 0,
            max_mints_per_window: u32::MAX,
            max_swept_per_window_zat: 0,
        };
        let signer = Arc::new(Signer::new(seed, 133, zip32::AccountId::ZERO, policy).unwrap());
        MintContext {
            signer,
            hot_balance_zat: 1_000_000,
            anchor: Anchor::empty_tree(),
            height: 2_000_000,
            expiry_height: 0,
            network: zcash_protocol::consensus::Network::MainNetwork,
            circuit_version: orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
            // Must match the regtest chain these tests broadcast to — it runs
            // at NU6.2 (the circuit version above already says so).
            branch_id: zcash_protocol::consensus::BranchId::Nu6_2,
            treasury: None,
        }
    }

    /// Registry-authored memos (the Name Note canonical form with its
    /// prev_rcm witness, and outbound challenges) must be skipped on rescan,
    /// not re-processed as user requests. Fails *before* any mint/broadcast,
    /// so no node is needed.
    #[tokio::test]
    async fn registry_authored_memos_are_skipped() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

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

        // Our own Name Note seen again on rescan: 5-field canonical form.
        let name_note = format!("ZNS:claim:alice:u1xxx:{}", "a".repeat(64));
        let results = reg
            .process_notes(
                &[
                    note(name_note.as_bytes()),
                    note(b"ZNS:challenge:alice:beef"),
                ],
                &ctx,
            )
            .await;
        assert!(
            results
                .iter()
                .all(|r| matches!(r, ProcessResult::Skipped(_))),
            "got: {results:?}"
        );
        // And nothing was registered.
        assert!(reg.lookup("alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn claim_insufficient_fee() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

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
            value_zat: 1, // too low
            is_received: true,
            confirmed: true,
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
            block_hash: [0u8; 32],
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: true,
            confirmed: true,
        };

        reg.process_notes(&[make_claim()], &ctx).await;
        let results = reg.process_notes(&[make_claim()], &ctx).await;
        assert!(matches!(results[0], ProcessResult::Err(_, _)));
    }

    #[tokio::test]
    async fn non_zns_memo_skipped() {
        let reg = Registry::open_in_memory().unwrap();
        let ctx = make_context();

        let note = IncomingNote {
            txid: [0u8; 32],
            height: 2_000_000,
            block_hash: [0u8; 32],
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"Hello, Zcash!";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: 100_000,
            is_received: true,
            confirmed: true,
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
            block_hash: [0u8; 32],
            output_index: 0,
            memo: {
                let mut m = vec![0u8; 512];
                let s = b"ZNS:claim:alice:u1xxx";
                m[..s.len()].copy_from_slice(s);
                m
            },
            value_zat: MIN_CLAIM_FEE_ZAT,
            is_received: false, // OVK-recovered sent note
            confirmed: true,
        };

        let results = reg.process_notes(&[note], &ctx).await;
        assert_eq!(results.len(), 0); // sent notes filtered before push
    }
}
