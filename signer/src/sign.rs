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

use zns_core::RegistryError;

use crate::mint::{build_funded_mint, MintResult};
use crate::policy::{MintProposal, PolicyError, SpendGuard, SpendPolicy};

/// Why the signer refused (policy) or failed (build).
#[derive(Debug)]
pub enum SignError {
    /// The proposal violated policy — the signer refused before building.
    Policy(PolicyError),
    /// Policy passed but bundle construction / proving failed.
    Build(RegistryError),
}

impl From<PolicyError> for SignError {
    fn from(e: PolicyError) -> Self {
        SignError::Policy(e)
    }
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::Policy(e) => write!(f, "policy refused: {e:?}"),
            SignError::Build(e) => write!(f, "build failed: {e}"),
        }
    }
}

impl std::error::Error for SignError {}

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
    ) -> Result<Self, RegistryError> {
        let sk = SpendingKey::from_zip32_seed(&seed, coin_type, account)
            .map_err(|e| RegistryError::Build(format!("invalid registry seed: {e:?}")))?;
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

    /// Advance the velocity window (call once per block/epoch).
    pub fn roll_window(&self) {
        self.guard.lock().expect("guard poisoned").roll_window();
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
    ) -> Result<MintResult, SignError> {
        // Pure policy gate first — cheap rejects without mutating state.
        let funding_value = proposal.funding.note.value().inner();
        let plan = self.policy.evaluate_mint(&proposal.intent, funding_value, hot_balance_zat)?;

        // Record (replay + velocity). Rolled back if the build fails so a
        // transient error neither burns the request nor a velocity slot.
        let id = proposal.intent.request_id;
        self.guard.lock().expect("guard poisoned").admit_mint(&self.policy, id)?;

        let sk = self.spending_key();
        match build_funded_mint(
            &self.fvk,
            &sk,
            self.registry_address(),
            &proposal.funding,
            &plan,
            branch_id,
            expiry_height,
        ) {
            Ok(result) => Ok(result),
            Err(e) => {
                self.guard.lock().expect("guard poisoned").rollback_mint(id);
                Err(SignError::Build(e))
            }
        }
    }
}
