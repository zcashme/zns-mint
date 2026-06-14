//! The policy-gated signing authority — the heart of the (future in-enclave)
//! signer.
//!
//! [`Signer`] holds the registry spend seed **in memory only** ([`Zeroizing`],
//! zeroized on drop; in production generated in-enclave and sealed to the
//! attestation measurement). Nothing can extract the key: the only operation is
//! [`Signer::sign_mint`], which runs every request through the [`SpendPolicy`]
//! gate and the [`SpendGuard`] (replay + velocity) before it will author and
//! sign a transaction. A fully-compromised host can therefore never redirect
//! funds — only request mints the policy already permits.

use std::sync::Mutex;

use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    Address,
};
use zcash_protocol::consensus::BranchId;
use zeroize::Zeroizing;

use orchard::circuit::OrchardCircuitVersion;

use crate::error::SignError;
use crate::mint::{build_funded_mint, build_memo_send, build_sweep, MintResult};
use crate::policy::{FundingInput, MintProposal, PolicyError, RequestId, SpendGuard, SpendPolicy};

/// The registry signing authority. Cheap to share behind an `Arc`; the inner
/// guard is mutex-protected.
pub struct Signer {
    /// Registry spend seed — memory-only, zeroized on drop.
    seed: Zeroizing<[u8; 32]>,
    coin_type: u32,
    account: zip32::AccountId,
    /// Cached public full viewing key (not secret).
    fvk: FullViewingKey,
    policy: SpendPolicy,
    guard: Mutex<SpendGuard>,
}

impl Signer {
    /// Construct a signer from the registry spend seed and its derivation path.
    ///
    /// `coin_type` follows SLIP-44 (133 = mainnet ZEC, 1 = test/regtest).
    pub fn new(
        seed: [u8; 32],
        coin_type: u32,
        account: zip32::AccountId,
        policy: SpendPolicy,
    ) -> Result<Self, SignError> {
        let sk = SpendingKey::from_zip32_seed(&seed, coin_type, account)
            .map_err(|e| SignError::InvalidSeed(format!("{e:?}")))?;
        let fvk = FullViewingKey::from(&sk);

        Ok(Self {
            seed: Zeroizing::new(seed),
            coin_type,
            account,
            fvk,
            policy,
            guard: Mutex::new(SpendGuard::default()),
        })
    }

    /// The registry self-address — receives every Name Note and all change.
    pub fn registry_address(&self) -> Address {
        self.fvk.address_at(0u32, Scope::External)
    }

    /// The registry full viewing key (public — for the host's scanner/WalletDb).
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// The active spend policy — the daemon consults this to decide whether a
    /// sweep is due ([`SpendPolicy::evaluate_sweep`]); the signer is what
    /// enforces it.
    pub fn policy(&self) -> &SpendPolicy {
        &self.policy
    }

    /// Advance the velocity window (call once per block/epoch).
    pub fn roll_window(&self) {
        self.guard.lock().expect("guard poisoned").roll_window();
    }

    /// Release a request from the replay set because its signed transaction
    /// is **provably dead** (expired unmined — decided by intent
    /// reconciliation, the only place that can know). Without this, a
    /// broadcast that never lands permanently burns the request: the replay
    /// set records at sign time, but the mint isn't *done* until it persists.
    ///
    /// Trust note: a lying host calling this only re-enables a mint the
    /// policy already permits, with the same deterministic `(ψ, rcm)` — the
    /// replay set is defense-in-depth against accidental double-signing, not
    /// the chain's integrity boundary (a forked name chain is publicly
    /// visible to every scanner).
    pub fn release_request(&self, id: RequestId) {
        self.guard.lock().expect("guard poisoned").rollback_mint(id);
    }

    /// Re-derive the spending key transiently for one signature. It lives only
    /// on the stack for the duration of the call; the seed is the sole resident
    /// secret.
    fn spending_key(&self) -> SpendingKey {
        SpendingKey::from_zip32_seed(&self.seed[..], self.coin_type, self.account)
            .expect("seed validated in Signer::new")
    }

    /// Gate a proposal through policy + guard, then author and sign the funded
    /// mint. `hot_balance_zat` is the current spendable treasury balance (from
    /// the host's WalletDb); the signer recomputes change and enforces the
    /// low-watermark pause against it.
    pub fn sign_mint(
        &self,
        proposal: MintProposal,
        hot_balance_zat: u64,
        branch_id: BranchId,
        expiry_height: u32,
        circuit_version: OrchardCircuitVersion,
    ) -> Result<MintResult, SignError> {
        // Pure policy gate first — cheap rejects without mutating state.
        let funding_value = proposal.funding.note.value().inner();
        let plan = self
            .policy
            .evaluate_mint(&proposal.intent, funding_value, hot_balance_zat)?;

        // Record (replay + velocity). Rolled back if the build fails so a
        // transient error neither burns the request nor a velocity slot.
        let id = proposal.intent.request_id;
        self.guard
            .lock()
            .expect("guard poisoned")
            .admit_mint(&self.policy, id)?;

        let sk = self.spending_key();
        match build_funded_mint(
            &self.fvk,
            &sk,
            self.registry_address(),
            &proposal.funding,
            &plan,
            branch_id,
            expiry_height,
            circuit_version,
        ) {
            Ok(result) => Ok(result),
            Err(e) => {
                self.guard.lock().expect("guard poisoned").rollback_mint(id);
                Err(SignError::Build(e))
            }
        }
    }

    /// Author and sign an OTP challenge relay: a dust note carrying the
    /// challenge memo to the name owner's UA, change back to the registry.
    ///
    /// This is the **one bounded exception** to "value only ever lands at the
    /// registry or cold": the recipient is host-supplied (the owner UA from
    /// the name record). The bound: dust and fee are each capped at
    /// `max_fee_zat`, the relay consumes a mint velocity slot, and the
    /// triggering request note is replay-protected — so a fully compromised
    /// host can leak at most `2 × max_fee × max_mints_per_window` per window,
    /// griefing the float, never draining it.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_relay(
        &self,
        recipient: Address,
        memo: [u8; 512],
        funding: FundingInput,
        request_id: RequestId,
        hot_balance_zat: u64,
        branch_id: BranchId,
        expiry_height: u32,
        circuit_version: OrchardCircuitVersion,
    ) -> Result<Vec<u8>, SignError> {
        // The dust mirrors the fee (one policy knob bounds both).
        let fee = self.policy.max_fee_zat.min(crate::policy::RELAY_UNIT_ZAT);
        let dust = fee;
        if hot_balance_zat < self.policy.low_watermark_zat {
            return Err(SignError::Policy(PolicyError::BelowLowWatermark {
                balance: hot_balance_zat,
                low: self.policy.low_watermark_zat,
            }));
        }
        let funding_value = funding.note.value().inner();
        let change = funding_value
            .checked_sub(fee + dust)
            .ok_or(SignError::Policy(PolicyError::InsufficientFunding {
                have: funding_value,
                need: fee + dust,
            }))?;

        self.guard
            .lock()
            .expect("guard poisoned")
            .admit_mint(&self.policy, request_id)?;

        let sk = self.spending_key();
        match build_memo_send(
            &self.fvk,
            &sk,
            recipient,
            self.registry_address(),
            &funding,
            dust,
            change,
            memo,
            branch_id,
            expiry_height,
            circuit_version,
        ) {
            Ok(tx_bytes) => Ok(tx_bytes),
            Err(e) => {
                self.guard
                    .lock()
                    .expect("guard poisoned")
                    .rollback_mint(request_id);
                Err(SignError::Build(e))
            }
        }
    }

    /// Author and sign an auto-sweep of one treasury note to the **cold address**.
    /// Destination is always the policy's cold_addr. The host decides when and
    /// how much.
    pub fn sign_sweep(
        &self,
        funding: FundingInput,
        fee_zat: u64,
        branch_id: BranchId,
        expiry_height: u32,
        circuit_version: OrchardCircuitVersion,
    ) -> Result<SweepResult, SignError> {
        if fee_zat > self.policy.max_fee_zat {
            return Err(SignError::Policy(PolicyError::FeeTooHigh {
                fee: fee_zat,
                max: self.policy.max_fee_zat,
            }));
        }
        let funding_value = funding.note.value().inner();
        let amount = funding_value.checked_sub(fee_zat).ok_or(SignError::Policy(
            PolicyError::InsufficientFunding {
                have: funding_value,
                need: fee_zat,
            },
        ))?;

        // Sweep velocity cap removed. We still call through the guard API for
        // now; the implementation is a no-op for sweeps.
        self.guard
            .lock()
            .expect("guard poisoned")
            .admit_sweep(&self.policy, amount)?;

        let sk = self.spending_key();
        match build_sweep(
            &self.fvk,
            &sk,
            self.policy.cold_addr,
            &funding,
            amount,
            branch_id,
            expiry_height,
            circuit_version,
        ) {
            Ok(tx_bytes) => Ok(SweepResult {
                tx_bytes,
                amount_zat: amount,
            }),
            Err(e) => {
                self.guard
                    .lock()
                    .expect("guard poisoned")
                    .rollback_sweep(amount);
                Err(SignError::Build(e))
            }
        }
    }
}

/// The result of a sweep: the signed transaction and how much went to cold.
#[derive(Debug)]
pub struct SweepResult {
    pub tx_bytes: Vec<u8>,
    pub amount_zat: u64,
}

/// === Test harness boundary helpers (the *only* place the test zero seed appears) ===
/// 
/// The orchestrator (zns-registry binary / host) must never see or hold the raw
/// spend seed. All derivation and secret material stays inside this crate.
/// These functions exist so the host can get the public view material it needs
/// (for CLI and scanner/treasury setup) and construct a Signer for signing
/// without ever receiving seed bytes.
///
/// In the current test harness the seed is the well-known zero value.
/// In production the equivalent construction inside this crate will derive
/// the seed from the TEE (sealed data + measurement). The host API stays the same.

impl Signer {
    /// Test-harness constructor.
    /// The spend seed is derived *inside* this crate from the known test value.
    /// The caller only supplies the (public) policy parameters.
    /// In production the equivalent happens inside the TEE.
    pub fn new_test(policy: SpendPolicy) -> Result<Self, SignError> {
        let seed = [0u8; 32];
        let coin_type = 133;
        let account = zip32::AccountId::ZERO;

        let sk = SpendingKey::from_zip32_seed(&seed, coin_type, account)
            .map_err(|e| SignError::InvalidSeed(format!("{e:?}")))?;
        let fvk = FullViewingKey::from(&sk);
        let registry_addr = fvk.address_at(0u32, Scope::External);

        // The host may pass a policy with a placeholder registry_addr.
        // We force the correct one derived from the (internal) seed so it always matches.
        let actual_policy = SpendPolicy {
            registry_addr,
            cold_addr: policy.cold_addr,
            max_fee_zat: policy.max_fee_zat,
            target_float_zat: policy.target_float_zat,
            high_watermark_zat: policy.high_watermark_zat,
            low_watermark_zat: policy.low_watermark_zat,
            max_mints_per_window: policy.max_mints_per_window,
        };

        Ok(Self {
            seed: Zeroizing::new(seed),
            coin_type,
            account,
            fvk,
            policy: actual_policy,
            guard: Mutex::new(SpendGuard::default()),
        })
    }
}

/// Pure view material for the test harness key. The host can call these for
/// "zns-mint address", "viewkey", and scanner/treasury setup.
pub fn test_registry_address() -> Address {
    let seed = [0u8; 32];
    let sk = SpendingKey::from_zip32_seed(&seed, 133, zip32::AccountId::ZERO)
        .expect("test seed is always valid");
    let fvk = FullViewingKey::from(&sk);
    fvk.address_at(0u32, Scope::External)
}

pub fn test_orchard_ivk() -> orchard::keys::IncomingViewingKey {
    let seed = [0u8; 32];
    let sk = SpendingKey::from_zip32_seed(&seed, 133, zip32::AccountId::ZERO)
        .expect("test seed is always valid");
    let fvk = FullViewingKey::from(&sk);
    fvk.to_ivk(Scope::External)
}


