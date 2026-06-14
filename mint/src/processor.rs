//! Action processing and mint coordination.
//!
//! The `Processor` is the orchestration layer. It drives the ZNS protocol rules
//! (fee checks, already-claimed, OTP challenge for UPDATE/RELEASE, etc.) on top of
//! a [`crate::store::Registry`] (the local persisted name bindings + history +
//! intake ledger).
//!
//! It coordinates with the policy-gated `Signer` (via `MintContext`), ensures
//! atomic "build + broadcast + persist intent" for crash safety, and handles
//! reorg + reconciliation recovery.
//!
//! All chain I/O (scanning is done by the caller; broadcasting is done here)
//! is supplied explicitly via `&GrpcClient` parameters. The processor never
//! owns a lightwalletd / node endpoint string.

use std::sync::Arc;

use crate::constants::{MINT_FEE_ZAT, MIN_CLAIM_FEE_ZAT, MIN_MUTATION_FEE_ZAT};
use crate::error::RegistryError;
use crate::store::Registry;
use crate::types::{ActionOutcome, MintContext, ProcessResult, Treasury};

use zns_chain::{GrpcClient, GrpcError, IncomingNote};
use zns_core::{memo, parse_memo, Action, ParsedMemo, ZERO_PREV_RCM};
use zns_mint::{MintResult, RequestId, Signer};
use zns_state::{MintedAction, PendingMint};

/// Orchestrates intake, OTP challenges for mutations, Name Note minting,
/// and recovery. Holds a cloneable handle to the persisted registry state.
#[derive(Clone)]
pub struct Processor {
    registry: Registry,
}

impl Processor {
    pub fn new(registry: Registry) -> Self {
        Processor { registry }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // -----------------------------------------------------------------------
    // Main entry point for a batch of incoming notes
    // -----------------------------------------------------------------------

    /// Process a batch of [`IncomingNote`]s that arrived at addr_reg.
    ///
    /// The caller supplies the current `MintContext` (signer, treasury note
    /// for this poll, heights, etc.) and a `GrpcClient` for any broadcasts
    /// required by this batch.
    pub async fn process_notes(
        &self,
        notes: &[IncomingNote],
        mint_ctx: &MintContext,
        grpc: &GrpcClient,
    ) -> Vec<ProcessResult> {
        let mut treasury = mint_ctx.treasury.clone();
        let mut results = Vec::new();
        for note in notes {
            if !note.is_received {
                continue;
            }
            let res = self.process_note(note, mint_ctx, grpc, &mut treasury).await;
            results.push(res);
        }
        results
    }

    async fn process_note(
        &self,
        note: &IncomingNote,
        mint_ctx: &MintContext,
        grpc: &GrpcClient,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> ProcessResult {
        let pool_byte: u8 = match note.pool {
            zcash_protocol::ShieldedProtocol::Orchard => 0,
            zcash_protocol::ShieldedProtocol::Sapling => 1,
        };
        {
            if self
                .registry
                .is_processed(&note.txid, pool_byte, note.output_index)
                .await
                .unwrap_or(false)
            {
                return ProcessResult::Skipped("already settled".into());
            }
        }

        let (result, settled) = match &parse_memo(&note.memo) {
            Err(e) => (
                ProcessResult::Skipped(format!("memo parse error: {e}")),
                true,
            ),

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
                        grpc,
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
                    .handle_confirm(name, nonce, request, mint_ctx, grpc, treasury)
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
            if let Err(e) = self
                .registry
                .mark_processed(&note.txid, pool_byte, note.output_index, note.height, &note.block_hash)
                .await
            {
                tracing::warn!("intake ledger write failed: {e}");
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Action handlers (claim vs mutation)
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn handle_action(
        &self,
        action: Action,
        name: &str,
        ua: &str,
        value_zat: u64,
        request: RequestId,
        mint_ctx: &MintContext,
        grpc: &GrpcClient,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<ActionOutcome, RegistryError> {
        match action {
            Action::Claim => {
                if value_zat < MIN_CLAIM_FEE_ZAT {
                    return Err(RegistryError::InsufficientFee {
                        got: value_zat,
                        need: MIN_CLAIM_FEE_ZAT,
                    });
                }

                {
                    if self.registry.get_record(name).await?.is_some() {
                        return Err(RegistryError::AlreadyClaimed(name.into()));
                    }
                }

                let result = self
                    .do_mint(
                        action,
                        name,
                        ua,
                        &ZERO_PREV_RCM,
                        request,
                        mint_ctx,
                        grpc,
                        treasury,
                    )
                    .await?;

                self.registry
                    .persist_mint(&minted_action(
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

            Action::Update | Action::Release => {
                if value_zat < MIN_MUTATION_FEE_ZAT {
                    return Err(RegistryError::InsufficientFee {
                        got: value_zat,
                        need: MIN_MUTATION_FEE_ZAT,
                    });
                }

                let record = self
                    .registry
                    .get_record(name)
                    .await?
                    .ok_or_else(|| RegistryError::NotFound(name.into()))?;

                let challenge = zns_auth::new_challenge(name, action, ua, mint_ctx.height)
                    .map_err(|e| RegistryError::Auth(e.to_string()))?;

                {
                    self.registry
                        .purge_expired_challenges(mint_ctx.height)
                        .await?;
                    self.registry.put_challenge(&challenge).await?;
                }

                self.relay_challenge(
                    name,
                    &record.ua,
                    &challenge.nonce,
                    request,
                    mint_ctx,
                    grpc,
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
        grpc: &GrpcClient,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<ActionOutcome, RegistryError> {
        let challenge = self.registry.get_challenge(name).await?.ok_or_else(|| {
            RegistryError::Auth(format!("no pending challenge for name '{name}'"))
        })?;

        zns_auth::verify(&challenge, nonce, mint_ctx.height)
            .map_err(|e| RegistryError::Auth(e.to_string()))?;

        let prev_rcm = self
            .registry
            .get_current_rcm(name)
            .await?
            .ok_or_else(|| RegistryError::NotFound(name.into()))?;

        let action = challenge.action;
        let ua = &challenge.ua_new;

        let result = self
            .do_mint(
                action, name, ua, &prev_rcm, request, mint_ctx, grpc, treasury,
            )
            .await?;

        self.registry
            .persist_mint(&minted_action(
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

    // -----------------------------------------------------------------------
    // Core mint + broadcast + intent coordination
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn do_mint(
        &self,
        action: Action,
        name: &str,
        ua: &str,
        prev_rcm: &[u8; 32],
        request: RequestId,
        ctx: &MintContext,
        grpc: &GrpcClient,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<MintResult, RegistryError> {
        if self.registry.get_intent(name).await?.is_some() {
            return Err(RegistryError::Broadcast(format!(
                "mint intent for {name:?} pending reconciliation"
            )));
        }

        let result = match treasury.take() {
            Some(treasury_funding) => {
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
                            funding: treasury_funding.funding_input(),
                        },
                        ctx.hot_balance_zat,
                        ctx.branch_id,
                        ctx.expiry_height,
                        ctx.circuit_version,
                    )
                    .map_err(registry_err)?
            }
            None => zns_mint::build_name_note(zns_mint::MintParams {
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

        self.registry
            .put_intent(&PendingMint {
                minted: minted_action(name, action, ua, &result, ctx.height, *prev_rcm),
                expiry_height: ctx.expiry_height,
                request: (request.txid, request.action_index),
            })
            .await?;

        if let Err(e) = grpc.broadcast(result.tx_bytes.clone()).await {
            if matches!(e, GrpcError::Rejected { .. }) {
                let _ = self.registry.delete_intent(name).await;
                ctx.signer.release_request(request);
            }
            return Err(e.into());
        }

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // OTP relay (also a funded spend)
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn relay_challenge(
        &self,
        name: &str,
        owner_ua: &str,
        nonce: &str,
        request: RequestId,
        ctx: &MintContext,
        grpc: &GrpcClient,
        treasury: &mut Option<Arc<Treasury>>,
    ) -> Result<(), RegistryError> {
        let memo_text = memo::encode_challenge(name, nonce);
        let memo_bytes = memo::encode_memo_bytes(&memo_text)?;
        let recipient = parse_orchard_recipient(owner_ua, ctx.network)?;

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

        grpc.broadcast(tx_bytes).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Recovery (reorg + crash reconciliation)
    // These were on the old Registry; they now live on Processor and take
    // the broadcaster explicitly (as they always did for the grpc client).
    // -----------------------------------------------------------------------

    pub async fn reconcile_intents(
        &self,
        grpc: &GrpcClient,
        signer: &Signer,
        tip_height: u32,
    ) -> Result<(), RegistryError> {
        let intents = self.registry.list_intents().await?;
        for intent in intents {
            let name = &intent.minted.name;
            if grpc.transaction_exists(&intent.minted.txid).await? {
                tracing::warn!(
                    name,
                    txid = hex::encode(intent.minted.txid),
                    "reconciling: broadcast tx found on chain, replaying persistence"
                );
                self.registry.persist_mint(&intent.minted).await?;
            } else if intent.expiry_height > 0 && tip_height > intent.expiry_height {
                tracing::warn!(name, "dropping mint intent — tx expired unmined");
                signer.release_request(RequestId {
                    txid: intent.request.0,
                    action_index: intent.request.1,
                });
                self.registry.delete_intent(name).await?;
            }
        }
        Ok(())
    }

    pub async fn handle_reorg(
        &self,
        grpc: &GrpcClient,
        signer: &Signer,
        tip_height: u32,
    ) -> Result<Option<u32>, RegistryError> {
        let Some(last_height) = self.registry.last_processed_height().await? else {
            return Ok(None);
        };

        let reorg_height = if last_height > tip_height {
            tip_height.saturating_add(1)
        } else {
            let Some(stored_hash) = self.registry.processed_hash_at_height(last_height).await?
            else {
                return Ok(None);
            };
            let current_hash = grpc.block_hash(last_height).await?;
            if stored_hash == current_hash {
                return Ok(None);
            }

            let mut h = last_height;
            loop {
                let Some(stored) = self.registry.processed_hash_at_height(h).await? else {
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

        let affected = self
            .registry
            .apply_reorg(reorg_height, |(txid, idx)| {
                signer.release_request(RequestId {
                    txid,
                    action_index: idx,
                });
            })
            .await?;

        tracing::warn!(
            reorg_height,
            affected_names = affected,
            "chain reorg detected: rolled back registry state"
        );
        Ok(Some(reorg_height))
    }
}

// ---------------------------------------------------------------------------
// Helpers (kept close to the coordination logic)
// ---------------------------------------------------------------------------

fn minted_action(
    name: &str,
    action: Action,
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
