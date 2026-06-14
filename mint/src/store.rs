//! Local persisted registry + intake ledger.
//!
//! This is the honest "ZNS registry" from a persistence point of view: the
//! current name bindings, the append-only action history (source of truth for
//! the (ψ, rcm) chain), the intake settlement ledger, pending OTP challenges,
//! and crash-recovery mint intents.
//!
//! It deliberately knows *nothing* about how to talk to lightwalletd or the
//! full node for new data or for broadcasting. Those concerns live in the
//! processor and are supplied by the caller at the operation sites.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::error::RegistryError;
use crate::types::RegistryStats;

use zns_state::{MintedAction, Name, PendingMint};

/// Local handle to the persisted ZNS registry state.
///
/// Cheaply cloneable. All mutable operations that must be atomic (mint
/// persistence, reorg rollback) go through here so the invariants are in one
/// place.
#[derive(Clone)]
pub struct Registry {
    state: Arc<Mutex<zns_state::State>>,
}

impl Registry {
    /// Open (or create) the registry database at `db_path`.
    pub fn new(db_path: &str) -> Result<Self, RegistryError> {
        let state = zns_state::State::open(db_path)?;
        Ok(Registry {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Open an in-memory registry (for testing / ephemeral use).
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        let state = zns_state::State::open_in_memory()?;
        Ok(Registry {
            state: Arc::new(Mutex::new(state)),
        })
    }

    // ---------------- Query API (public, used by RPC and processors) -------

    /// Look up a registered name.
    pub async fn lookup(&self, name: &str) -> Result<Option<Name>, RegistryError> {
        let st = self.state.lock().await;
        st.get_record(name).map_err(Into::into)
    }

    /// Table counts for the control plane.
    pub async fn stats(&self) -> Result<RegistryStats, RegistryError> {
        let st = self.state.lock().await;
        let (names, pending_challenges, mint_intents) = st.table_counts()?;
        Ok(RegistryStats {
            names,
            pending_challenges,
            mint_intents,
        })
    }

    /// Filter out notes that the intake ledger has already settled.
    pub async fn unsettled(
        &self,
        notes: Vec<zns_chain::IncomingNote>,
    ) -> Vec<zns_chain::IncomingNote> {
        let st = self.state.lock().await;
        notes
            .into_iter()
            .filter(|n| !st.is_processed(&n.txid, n.output_index).unwrap_or(false))
            .collect()
    }

    // ---------------- Internal API for Processor / recovery ----------------

    pub(crate) async fn is_processed(
        &self,
        txid: &[u8; 32],
        output_index: u32,
    ) -> Result<bool, RegistryError> {
        let st = self.state.lock().await;
        st.is_processed(txid, output_index).map_err(Into::into)
    }

    pub(crate) async fn mark_processed(
        &self,
        txid: &[u8; 32],
        output_index: u32,
        block_height: u32,
        block_hash: &[u8; 32],
    ) -> Result<(), RegistryError> {
        let st = self.state.lock().await;
        st.mark_processed(txid, output_index, block_height, block_hash)
            .map_err(Into::into)
    }

    pub(crate) async fn get_intent(
        &self,
        name: &str,
    ) -> Result<Option<PendingMint>, RegistryError> {
        let st = self.state.lock().await;
        st.get_intent(name).map_err(Into::into)
    }

    pub(crate) async fn put_intent(&self, intent: &PendingMint) -> Result<(), RegistryError> {
        let st = self.state.lock().await;
        st.put_intent(intent).map_err(Into::into)
    }

    pub(crate) async fn delete_intent(&self, name: &str) -> Result<(), RegistryError> {
        let st = self.state.lock().await;
        st.delete_intent(name).map_err(Into::into)
    }

    pub(crate) async fn list_intents(&self) -> Result<Vec<PendingMint>, RegistryError> {
        let st = self.state.lock().await;
        st.list_intents().map_err(Into::into)
    }

    pub(crate) async fn last_processed_height(&self) -> Result<Option<u32>, RegistryError> {
        let st = self.state.lock().await;
        st.last_processed_height().map_err(Into::into)
    }

    pub(crate) async fn processed_hash_at_height(
        &self,
        height: u32,
    ) -> Result<Option<[u8; 32]>, RegistryError> {
        let st = self.state.lock().await;
        st.processed_hash_at_height(height).map_err(Into::into)
    }

    /// Atomically persist a successful mint (name_events + names tip + challenge
    /// consumption + intent clearance).
    pub(crate) async fn persist_mint(&self, minted: &MintedAction) -> Result<(), RegistryError> {
        let st = self.state.lock().await;
        st.apply_mint(minted).map_err(Into::into)
    }

    /// Roll back registry state above `height`. The supplied `releaser` is
    /// called (inside the DB transaction) for every intent whose request must
    /// be released back to the signer's replay/velocity guard.
    pub(crate) async fn apply_reorg<F>(
        &self,
        height: u32,
        releaser: F,
    ) -> Result<usize, RegistryError>
    where
        F: FnMut(([u8; 32], u32)),
    {
        let st = self.state.lock().await;
        st.apply_reorg(height, releaser).map_err(Into::into)
    }

    // Pieces needed by the mutation / confirm / reorg paths (challenge + record)

    pub(crate) async fn get_record(&self, name: &str) -> Result<Option<Name>, RegistryError> {
        let st = self.state.lock().await;
        st.get_record(name).map_err(Into::into)
    }

    pub(crate) async fn get_current_rcm(
        &self,
        name: &str,
    ) -> Result<Option<[u8; 32]>, RegistryError> {
        let st = self.state.lock().await;
        st.get_current_rcm(name).map_err(Into::into)
    }

    pub(crate) async fn get_challenge(
        &self,
        name: &str,
    ) -> Result<Option<zns_auth::PendingChallenge>, RegistryError> {
        let st = self.state.lock().await;
        st.get_challenge(name).map_err(Into::into)
    }

    pub(crate) async fn put_challenge(
        &self,
        c: &zns_auth::PendingChallenge,
    ) -> Result<(), RegistryError> {
        let st = self.state.lock().await;
        st.put_challenge(c).map_err(Into::into)
    }

    pub(crate) async fn purge_expired_challenges(
        &self,
        current_height: u32,
    ) -> Result<(), RegistryError> {
        let st = self.state.lock().await;
        st.purge_expired_challenges(current_height)
            .map_err(Into::into)
    }
}
