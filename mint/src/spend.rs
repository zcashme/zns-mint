use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use orchard::circuit::OrchardCircuitVersion;
use tokio::sync::Mutex as AsyncMutex;
use zcash_address::unified::{self, Container, Encoding, Receiver};
use zcash_protocol::consensus::BranchId;
use zns_auth::{new_challenge, verify, AuthError};
use zns_chain::{GrpcClient, GrpcError};
use zns_core::{memo, Action, ZERO_PREV_RCM};
use zns_signer::{
    FundingInput, MintIntent, MintProposal, RelayResult, RequestId, SignError, Signer,
};
use zns_state::{InFlightSpend, SpendableNote, StateError, Treasury, TreasuryError};

use crate::config::{ANCHOR_CONFIRMATIONS, MIN_MUTATION_FEE_ZAT, MINT_FEE_ZAT, TX_EXPIRY_BLOCKS};
use crate::Registry;

/// A request note waiting for the single-lane spend path (in-memory only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSpend {
    pub txid: [u8; 32],
    pub pool: u8,
    pub output_index: u32,
    pub block_height: u32,
    pub block_hash: [u8; 32],
    pub verb: SpendVerb,
    pub name: String,
    pub ua: String,
    pub nonce: String,
    pub value_zat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendVerb {
    Claim,
    Update,
    Release,
    Confirm,
}

/// In-memory spend lane + persisted in-flight tx.
pub struct SpendLane {
    queue: Mutex<VecDeque<QueuedSpend>>,
    active: Mutex<Option<QueuedSpend>>,
}

impl SpendLane {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            active: Mutex::new(None),
        }
    }

    pub fn push(&self, job: QueuedSpend) {
        self.queue.lock().expect("spend queue").push_back(job);
    }

    pub fn pending_count(&self) -> usize {
        let queued = self.queue.lock().expect("spend queue").len();
        let active = usize::from(self.active.lock().expect("spend active").is_some());
        queued + active
    }

    pub fn has_pending_claim(&self, name: &str) -> bool {
        let q = self.queue.lock().expect("spend queue");
        q.iter()
            .any(|j| j.name == name && j.verb == SpendVerb::Claim)
    }

    pub fn clear_active(&self) {
        *self.active.lock().expect("spend active") = None;
    }

    /// Drop queued and active jobs after a reorg rewind.
    pub fn reset(&self) {
        self.queue.lock().expect("spend queue").clear();
        self.clear_active();
    }

    pub fn active_job(&self) -> Option<QueuedSpend> {
        self.active.lock().expect("spend active").clone()
    }

    fn requeue_active(&self) {
        if let Some(job) = self.active.lock().expect("spend active").take() {
            self.queue.lock().expect("spend queue").push_front(job);
        }
    }

    pub async fn tick(
        &self,
        registry: &Registry,
        treasury: Option<&AsyncMutex<Treasury>>,
        signer: &Arc<Signer>,
        grpc: &GrpcClient,
        network: zcash_protocol::consensus::Network,
        _chain_tip: u32,
    ) -> Result<(), SpendError> {
        let chain_tip = grpc.tip_height().await?;

        if let Some(outcome) =
            reconcile_in_flight(registry, grpc, signer, self, chain_tip).await?
        {
            tracing::info!(?outcome, "in-flight spend resolved");
        }

        if {
            let st = registry.lock().await;
            st.get_in_flight()?.is_some()
        } {
            tracing::debug!("spend lane blocked: tx in flight");
            return Ok(());
        }

        let job = {
            let active = self.active.lock().expect("spend active").clone();
            active.or_else(|| self.queue.lock().expect("spend queue").pop_front())
        };
        let Some(job) = job else {
            return Ok(());
        };

        let Some(treasury) = treasury else {
            tracing::debug!("spend deferred: treasury not available");
            self.queue.lock().expect("spend queue").push_front(job);
            return Ok(());
        };

        let min_funding = match job.verb {
            SpendVerb::Update | SpendVerb::Release => MIN_MUTATION_FEE_ZAT,
            _ => MINT_FEE_ZAT,
        };

        let (funding_note, hot_balance) = {
            let mut t = treasury.lock().await;
            let funding = t.select_funding(min_funding, ANCHOR_CONFIRMATIONS)?;
            (funding.note, funding.spendable_total_zat)
        };
        let Some(funding_note) = funding_note else {
            tracing::warn!(name = %job.name, "spend deferred: treasury not spendable");
            self.queue.lock().expect("spend queue").push_front(job);
            return Ok(());
        };

        let sign_tip = grpc.tip_height().await?;
        let ctx = SpendCtx {
            signer: Arc::clone(signer),
            height: sign_tip,
            expiry_height: sign_tip.saturating_add(TX_EXPIRY_BLOCKS),
            network,
            branch_id: BranchId::for_height(&network, sign_tip.into()),
            hot_balance_zat: hot_balance,
            circuit_version: OrchardCircuitVersion::InsecurePreNu6_2,
        };

        let request_id = RequestId {
            txid: job.txid,
            action_index: job.output_index,
        };

        match dispatch(&ctx, registry, &job, funding_note, request_id).await {
            Ok(flight) => {
                let verb = job.verb;
                match grpc.broadcast(flight.tx_bytes).await {
                    Ok(()) => {
                        {
                            let st = registry.lock().await;
                            st.set_in_flight(&flight.in_flight)?;
                        }
                        *self.active.lock().expect("spend active") = Some(job);
                        tracing::info!(
                            verb = verb_label(verb),
                            name = %flight.in_flight.name,
                            txid = %hex::encode(flight.in_flight.txid),
                            relay = flight.in_flight.relay,
                            "broadcast spend"
                        );
                    }
                    Err(e) => {
                        signer.release_request(request_id);
                        self.queue.lock().expect("spend queue").push_front(job);
                        tracing::warn!(
                            verb = verb_label(verb),
                            name = %flight.in_flight.name,
                            error = %e,
                            "broadcast rejected; spend requeued"
                        );
                    }
                }
            }
            Err(SpendDispatchError::Permanent(reason)) => {
                tracing::warn!(
                    verb = verb_label(job.verb),
                    name = %job.name,
                    reason,
                    "spend permanently rejected"
                );
                mark_request_settled(registry, &job).await?;
            }
            Err(SpendDispatchError::Transient(e)) => {
                tracing::warn!(
                    verb = verb_label(job.verb),
                    name = %job.name,
                    error = %e,
                    "spend deferred (transient)"
                );
                self.queue.lock().expect("spend queue").push_front(job);
            }
        }

        Ok(())
    }
}

struct SpendCtx {
    signer: Arc<Signer>,
    height: u32,
    expiry_height: u32,
    network: zcash_protocol::consensus::Network,
    branch_id: BranchId,
    hot_balance_zat: u64,
    circuit_version: OrchardCircuitVersion,
}

struct BroadcastFlight {
    tx_bytes: Vec<u8>,
    in_flight: InFlightSpend,
}

enum SpendDispatchError {
    Permanent(&'static str),
    Transient(SpendError),
}

impl From<SignError> for SpendDispatchError {
    fn from(e: SignError) -> Self {
        match &e {
            SignError::Policy(_) => SpendDispatchError::Permanent("signer policy refused"),
            _ => SpendDispatchError::Transient(e.into()),
        }
    }
}

impl From<AuthError> for SpendDispatchError {
    fn from(e: AuthError) -> Self {
        SpendDispatchError::Permanent(match e {
            AuthError::NotRequired => "challenge not required",
            AuthError::WrongNonce(_) => "wrong OTP nonce",
            AuthError::Expired(_) => "OTP challenge expired",
            AuthError::NoPendingChallenge(_) => "no pending challenge",
        })
    }
}

impl From<StateError> for SpendDispatchError {
    fn from(e: StateError) -> Self {
        SpendDispatchError::Transient(SpendError::State(e))
    }
}

impl From<SpendError> for SpendDispatchError {
    fn from(e: SpendError) -> Self {
        match e {
            SpendError::UaParse(_) => SpendDispatchError::Permanent("invalid owner UA"),
            other => SpendDispatchError::Transient(other),
        }
    }
}

async fn dispatch(
    ctx: &SpendCtx,
    registry: &Registry,
    job: &QueuedSpend,
    funding_note: SpendableNote,
    request_id: RequestId,
) -> Result<BroadcastFlight, SpendDispatchError> {
    let funding = FundingInput {
        note: funding_note.note,
        merkle_path: funding_note.merkle_path,
        anchor: funding_note.anchor,
    };

    match job.verb {
        SpendVerb::Claim => dispatch_mint(
            ctx,
            Action::Claim,
            &job.name,
            &job.ua,
            ZERO_PREV_RCM,
            funding,
            request_id,
            false,
        ),
        SpendVerb::Update => dispatch_challenge(ctx, registry, job, Action::Update, funding, request_id)
            .await,
        SpendVerb::Release => {
            dispatch_challenge(ctx, registry, job, Action::Release, funding, request_id).await
        }
        SpendVerb::Confirm => dispatch_confirm(ctx, registry, job, funding, request_id).await,
    }
}

fn dispatch_mint(
    ctx: &SpendCtx,
    action: Action,
    name: &str,
    ua: &str,
    prev_rcm: [u8; 32],
    funding: FundingInput,
    request_id: RequestId,
    relay: bool,
) -> Result<BroadcastFlight, SpendDispatchError> {
    let intent = MintIntent {
        action,
        name: name.to_owned(),
        ua: ua.to_owned(),
        prev_rcm,
        fee_zat: MINT_FEE_ZAT,
        request_id,
    };
    let proposal = MintProposal {
        intent,
        funding,
    };
    let result = ctx.signer.sign_mint(
        proposal,
        ctx.hot_balance_zat,
        ctx.branch_id,
        ctx.expiry_height,
        ctx.circuit_version,
    )?;
    Ok(BroadcastFlight {
        tx_bytes: result.tx_bytes,
        in_flight: InFlightSpend {
            txid: result.txid,
            request_txid: request_id.txid,
            request_index: request_id.action_index,
            expiry_height: ctx.expiry_height,
            relay,
            name: name.to_owned(),
        },
    })
}

async fn dispatch_challenge(
    ctx: &SpendCtx,
    registry: &Registry,
    job: &QueuedSpend,
    action: Action,
    funding: FundingInput,
    request_id: RequestId,
) -> Result<BroadcastFlight, SpendDispatchError> {
    let owner_ua = {
        let st = registry.lock().await;
        st.get_record(&job.name)?
            .map(|n| n.ua)
            .ok_or(SpendDispatchError::Permanent("name not registered"))?
    };

    let challenge = new_challenge(&job.name, action, &job.ua, ctx.height)?;
    {
        let st = registry.lock().await;
        st.put_challenge(&challenge)?;
    }

    let memo_text = memo::encode_challenge(&challenge.name, &challenge.nonce);
    let memo = pad_memo(&memo_text);
    let recipient = orchard_from_ua(&owner_ua, ctx.network)?;

    let RelayResult { tx_bytes, txid } = ctx.signer.sign_relay(
        recipient,
        memo,
        funding,
        request_id,
        ctx.hot_balance_zat,
        ctx.branch_id,
        ctx.expiry_height,
        ctx.circuit_version,
    )?;

    Ok(BroadcastFlight {
        tx_bytes,
        in_flight: InFlightSpend {
            txid,
            request_txid: request_id.txid,
            request_index: request_id.action_index,
            expiry_height: ctx.expiry_height,
            relay: true,
            name: job.name.clone(),
        },
    })
}

async fn dispatch_confirm(
    ctx: &SpendCtx,
    registry: &Registry,
    job: &QueuedSpend,
    funding: FundingInput,
    request_id: RequestId,
) -> Result<BroadcastFlight, SpendDispatchError> {
    let (challenge, prev_rcm) = {
        let st = registry.lock().await;
        let challenge = st
            .get_challenge(&job.name)?
            .ok_or(SpendDispatchError::Permanent("no pending challenge"))?;
        verify(&challenge, &job.nonce, ctx.height)?;
        let prev_rcm = st
            .get_current_rcm(&job.name)?
            .ok_or(SpendDispatchError::Permanent("name not registered"))?;
        (challenge, prev_rcm)
    };

    dispatch_mint(
        ctx,
        challenge.action,
        &job.name,
        &challenge.ua_new,
        prev_rcm,
        funding,
        request_id,
        false,
    )
}

fn pad_memo(text: &str) -> [u8; 512] {
    let mut memo = [0u8; 512];
    let bytes = text.as_bytes();
    let len = bytes.len().min(512);
    memo[..len].copy_from_slice(&bytes[..len]);
    memo
}

fn orchard_from_ua(
    ua: &str,
    network: zcash_protocol::consensus::Network,
) -> Result<orchard::Address, SpendError> {
    let (net, addr) = unified::Address::decode(ua).map_err(|e| SpendError::UaParse(e.to_string()))?;
    let expected = match network {
        zcash_protocol::consensus::Network::MainNetwork => zcash_protocol::consensus::NetworkType::Main,
        zcash_protocol::consensus::Network::TestNetwork => {
            zcash_protocol::consensus::NetworkType::Test
        }
    };
    if net != expected {
        return Err(SpendError::UaParse("UA network mismatch".into()));
    }
    let orchard_raw = addr
        .items_as_parsed()
        .iter()
        .find_map(|r| match r {
            Receiver::Orchard(bytes) => Some(*bytes),
            _ => None,
        })
        .ok_or_else(|| SpendError::UaParse("UA has no Orchard receiver".into()))?;
    orchard::Address::from_raw_address_bytes(&orchard_raw)
        .into_option()
        .ok_or_else(|| SpendError::UaParse("invalid Orchard receiver".into()))
}

async fn mark_request_settled(registry: &Registry, job: &QueuedSpend) -> Result<(), SpendError> {
    let st = registry.lock().await;
    st.mark_processed(
        &job.txid,
        job.pool,
        job.output_index,
        job.block_height,
        &job.block_hash,
    )?;
    Ok(())
}

#[derive(Debug)]
enum InFlightOutcome {
    RelayConfirmed,
    Expired,
}

async fn reconcile_in_flight(
    registry: &Registry,
    grpc: &GrpcClient,
    signer: &Signer,
    spend: &SpendLane,
    chain_tip: u32,
) -> Result<Option<InFlightOutcome>, SpendError> {
    let flight = {
        let st = registry.lock().await;
        st.get_in_flight()?
    };
    let Some(flight) = flight else {
        return Ok(None);
    };

    if grpc.transaction_exists(&flight.txid).await? {
        if flight.relay {
            if let Some(job) = spend.active_job() {
                mark_request_settled(registry, &job).await?;
            }
            let st = registry.lock().await;
            st.clear_in_flight()?;
            spend.clear_active();
            tracing::info!(name = %flight.name, "OTP relay confirmed on chain");
            return Ok(Some(InFlightOutcome::RelayConfirmed));
        }
        tracing::debug!(
            name = %flight.name,
            "mint tx on chain; awaiting name note in scan"
        );
        return Ok(None);
    }

    if chain_tip > flight.expiry_height {
        signer.release_request(RequestId {
            txid: flight.request_txid,
            action_index: flight.request_index,
        });
        spend.requeue_active();
        let st = registry.lock().await;
        st.clear_in_flight()?;
        return Ok(Some(InFlightOutcome::Expired));
    }

    Ok(None)
}

pub(crate) fn verb_label(verb: SpendVerb) -> &'static str {
    match verb {
        SpendVerb::Claim => "claim",
        SpendVerb::Update => "update",
        SpendVerb::Release => "release",
        SpendVerb::Confirm => "confirm",
    }
}

#[cfg(test)]
mod lane_tests {
    use super::*;

    #[test]
    fn pending_count_includes_queued_and_active() {
        let lane = SpendLane::new();
        lane.push(QueuedSpend {
            txid: [1u8; 32],
            pool: 0,
            output_index: 0,
            block_height: 100,
            block_hash: [0u8; 32],
            verb: SpendVerb::Claim,
            name: "alice".into(),
            ua: "u1x".into(),
            nonce: String::new(),
            value_zat: 10_000,
        });
        assert_eq!(lane.pending_count(), 1);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Grpc(#[from] GrpcError),
    #[error(transparent)]
    Treasury(#[from] TreasuryError),
    #[error(transparent)]
    Sign(#[from] SignError),
    #[error("unified address: {0}")]
    UaParse(String),
}