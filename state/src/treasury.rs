//! Treasury wallet using the proper zcash_client_sqlite / librustzcash light client shape.
//! Owns the WalletDb (notes + Orchard shardtree witnesses). The orchestrator drives
//! sync using the passive `wallet_db_mut()` seam and an ephemeral block cache.

use std::num::NonZeroU32;
use std::path::Path;

use orchard::tree::{Anchor, MerklePath};
use rand::rngs::OsRng;
use thiserror::Error;
use zcash_address::unified::{Encoding as _, Fvk, Ufvk};
use zcash_client_backend::{
    data_api::{
        wallet::ConfirmationsPolicy,
        Account as _, AccountBirthday, AccountPurpose, InputSource as _,
        TargetValue, WalletCommitmentTrees as _, WalletRead as _, WalletWrite as _,
    },
};
use zcash_client_sqlite::{
    util::SystemClock,
    wallet::init::init_wallet_db,
    AccountUuid, WalletDb,
};

use tonic::{
    body::Body as TonicBody,
    codegen::{Body, Bytes, StdError},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{
    consensus::{BlockHeight, Network},
    value::Zatoshis,
    ShieldedProtocol,
};

/// Configuration for the registry's treasury note-state.
///
/// This is *purely* the parameters needed to open (or create) the view-only
/// WalletDb for the registry's own funds. Transport / syncing is the
/// orchestrator's responsibility — do not put lwd URLs or clients here.
pub struct TreasuryConfig {
    /// The registry's Orchard Full Viewing Key (`addr_reg`), including the
    /// nullifier-deriving key — needed to track which of the wallet's notes
    /// have been spent. The registry is Orchard-only, so we hold the FVK
    /// directly rather than round-tripping a Unified FVK string.
    pub registry_fvk: orchard::keys::FullViewingKey,
    /// The Zcash network the wallet tracks.
    pub network: Network,
    /// Block height to import the account at (the key's "birthday").
    pub birthday: u32,
}

/// Errors operating the registry's treasury note-state (the `WalletDb` over
/// `addr_reg`'s view-only account).
#[derive(Debug, Error)]
pub enum TreasuryError {
    #[error("opening wallet database: {0}")]
    Open(#[from] rusqlite::Error),

    #[error("initializing wallet database: {0}")]
    Init(String),

    #[error("wallet database: {0}")]
    WalletDb(#[from] zcash_client_sqlite::error::SqliteClientError),

    #[error("orchard commitment tree: {0}")]
    ShardTree(
        #[from]
        shardtree::error::ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>,
    ),

    /// The WalletDb exists but has no imported account for the registry FVK.
    /// The orchestrator must perform one-time bootstrap (fetch tree state for
    /// the birthday using chain helpers, then call `NoteState::initialize`).
    #[error("treasury wallet uninitialized: {0}")]
    Uninitialized(String),

    #[error("invalid funding floor: {0}")]
    Balance(#[from] zcash_protocol::value::BalanceError),

    #[error("parsing registry UFVK container: {0}")]
    UfvkContainer(#[from] zcash_address::unified::ParseError),

    #[error("decoding registry UFVK: {0}")]
    Ufvk(#[from] zcash_keys::keys::DecodingError),

    #[error("no orchard checkpoint at anchor height {0:?}")]
    MissingCheckpoint(BlockHeight),

    #[error("no witness for note at position {0:?}")]
    MissingWitness(incrementalmerkletree::Position),
}

/// A registry-owned Orchard note that can fund a mint, with its spend witness.
pub struct SpendableNote {
    /// The note to spend.
    pub note: orchard::Note,
    /// Its value in zatoshis.
    pub value_zat: u64,
    /// Merkle path authenticating the note to [`Self::anchor`].
    pub merkle_path: MerklePath,
    /// The tree root the path authenticates to (the bundle's spend anchor).
    pub anchor: Anchor,
}

/// Result of note selection: one note (if any >= floor) + total spendable
/// hot treasury balance. The host uses the total for drain decisions;
/// the signer uses it for the low watermark.
pub struct FundingSelection {
    /// A spendable note worth at least the floor, with its witness.
    pub note: Option<SpendableNote>,
    /// Total spendable registry balance in zatoshis (floor or not).
    pub spendable_total_zat: u64,
}

/// The registry's treasury wallet, using the proper zcash_client_sqlite light
/// client shape.
///
/// Owns the data `WalletDb` (notes, Orchard witnesses via shardtree, scan state
/// for the view-only account). Provides `select_funding` and an explicit passive
/// seam (`wallet_db_mut`) so the orchestrator can drive `sync::run` (or
/// `scan_cached_blocks`) with its own ephemeral `BlockCache`.
///
/// All durable treasury state lives in the WalletDb. Block caching for sync is
/// ephemeral and owned by the caller (recommended when the WalletDb holds scan
/// progress).
pub struct Treasury {
    data: WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    network: Network,
    account: AccountUuid,
}

impl Treasury {
    /// Open the treasury WalletDb.
    ///
    /// If the registry account does not exist yet, this will fail with
    /// `TreasuryError::Uninitialized`. The orchestrator is responsible for
    /// the one-time bootstrap (fetching the tree state for the birthday and
    /// calling `NoteState::initialize`).
    ///
    /// Normal operation (account already imported) is synchronous and performs
    /// no network I/O.
    pub fn open(
        wallet_db_path: impl AsRef<Path>,
        config: &TreasuryConfig,
    ) -> Result<Self, TreasuryError> {
        // Data DB (notes, trees, scan progress, witnesses)
        let mut data = WalletDb::for_path(wallet_db_path, config.network, SystemClock, OsRng)?;
        init_wallet_db(&mut data, None).map_err(|e| TreasuryError::Init(e.to_string()))?;

        let account = match data.get_account_ids()?.first() {
            Some(id) => *id,
            None => {
                // First run / uninitialized treasury wallet.
                // The orchestrator must have supplied a pre-fetched AccountBirthday
                // (via chain helper that talks to lightwalletd get_tree_state).
                return Err(TreasuryError::Uninitialized(
                    "treasury wallet has no account — caller must supply AccountBirthday for initial import (see orchestrator bootstrap)".into(),
                ));
            }
        };

        Ok(Treasury {
            data,
            network: config.network,
            account,
        })
    }

    /// One-time initialization: create the view-only account in the WalletDb
    /// using a pre-fetched `AccountBirthday`.
    ///
    /// The caller (orchestrator) is responsible for obtaining the `AccountBirthday`
    /// by talking to lightwalletd (typically one `get_tree_state` call at the
    /// height just before `config.birthday`). This method performs no I/O.
    ///
    /// After calling this, subsequent `open` calls on the same path will succeed.
    pub fn initialize(
        wallet_db_path: impl AsRef<Path>,
        config: &TreasuryConfig,
        birthday: AccountBirthday,
    ) -> Result<Self, TreasuryError> {
        // Data DB (notes, trees, scan progress, witnesses)
        let mut data = WalletDb::for_path(wallet_db_path, config.network, SystemClock, OsRng)?;
        init_wallet_db(&mut data, None).map_err(|e| TreasuryError::Init(e.to_string()))?;

        let account = if let Some(&id) = data.get_account_ids()?.first() {
            // Already present — treat as success (idempotent bootstrap).
            id
        } else {
            // The only stable public UFVK constructor is the ZIP 316 container parse.
            let ufvk =
                Ufvk::try_from_items(vec![Fvk::Orchard(config.registry_fvk.to_bytes())])?;
            let ufvk = UnifiedFullViewingKey::parse(&ufvk)?;

            data.import_account_ufvk(
                "zns-registry",
                &ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )?
            .id()
        };

        Ok(Treasury {
            data,
            network: config.network,
            account,
        })
    }

    /// Drive synchronization using the library's sync helper (convenience).
    ///
    /// The caller supplies a connected Lwd client and an (ephemeral) BlockCache
    /// for the duration of the run. All durable state (notes, witnesses, scan
    /// progress) lives in the owned WalletDb.
    ///
    /// Most callers will prefer the passive seam:
    /// `zcash_client_backend::sync::run(..., note_state.wallet_db_mut(), ...)`
    /// so that the orchestrator fully owns transport, caching policy, and the
    /// sync loop.
    pub async fn sync<ChT, CaT>(
        &mut self,
        client: &mut zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<ChT>,
        cache: &mut CaT,
    ) -> Result<(), TreasuryError>
    where
        ChT: tonic::client::GrpcService<TonicBody> + Send + Sync + 'static,
        ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
        ChT::Error: Into<StdError>,
        CaT: zcash_client_backend::data_api::chain::BlockCache,
        CaT::Error: std::error::Error + Send + Sync + 'static,
    {
        // Convenience wrapper. The orchestrator owns the cache (ephemeral is fine
        // and recommended — see chain::wallet_sync::EphemeralCompactBlockCache).
        zcash_client_backend::sync::run(
            client,
            &self.network,
            cache,
            &mut self.data,
            1_000,
        )
        .await
        .map_err(|e| TreasuryError::Init(format!("treasury sync: {e:#}")))?;
        Ok(())
    }

    /// Explicit passive seam for the orchestrator to drive sync (or note selection)
    /// without the Treasury object owning clients, caching policy, or the sync loop.
    ///
    /// Typical use:
    /// ```ignore
    /// zcash_client_backend::sync::run(
    ///     &mut client,
    ///     &network,
    ///     &mut ephemeral_cache,
    ///     note_state.wallet_db_mut(),
    ///     1000,
    /// ).await?;
    /// ```
    pub fn wallet_db_mut(
        &mut self,
    ) -> &mut WalletDb<rusqlite::Connection, Network, SystemClock, OsRng> {
        &mut self.data
    }

    /// Find a spendable registry note worth at least `min_value_zat` and build
    /// its witness against the anchor `min_confirmations` blocks deep.
    ///
    /// Returns `note: None` (with the hot balance still reported) if the
    /// wallet has no sufficiently confirmed note worth the floor.
    pub fn select_funding(
        &mut self,
        min_value_zat: u64,
        min_confirmations: u32,
    ) -> Result<FundingSelection, TreasuryError> {
        let min_confirmations =
            NonZeroU32::new(min_confirmations.max(1)).expect("max(1) is nonzero");
        let policy = ConfirmationsPolicy::new_symmetrical(min_confirmations);

        let spendable_total_zat = self
            .data
            .get_wallet_summary(policy)?
            .as_ref()
            .and_then(|s| s.account_balances().get(&self.account))
            .map(|b| u64::from(b.orchard_balance().spendable_value()))
            .unwrap_or(0);

        // No blocks scanned yet → nothing spendable.
        let Some((target_height, anchor_height)) =
            self.data.get_target_and_anchor_heights(min_confirmations)?
        else {
            return Ok(FundingSelection {
                note: None,
                spendable_total_zat,
            });
        };

        // Selection targets a *sum*; the mint spends a single input, so the
        // note itself must meet the floor.
        let notes = self.data.select_spendable_notes(
            self.account,
            TargetValue::AtLeast(Zatoshis::from_u64(min_value_zat)?),
            &[ShieldedProtocol::Orchard],
            target_height,
            policy,
            &[],
        )?;
        let Some(received) = notes
            .orchard()
            .iter()
            .find(|n| n.note().value().inner() >= min_value_zat)
        else {
            return Ok(FundingSelection {
                note: None,
                spendable_total_zat,
            });
        };

        let position = received.note_commitment_tree_position();
        let (path, root) = self
            .data
            .with_orchard_tree_mut::<_, _, TreasuryError>(|tree| {
                let root = tree
                    .root_at_checkpoint_id(&anchor_height)?
                    .ok_or(TreasuryError::MissingCheckpoint(anchor_height))?;
                let path = tree
                    .witness_at_checkpoint_id_caching(position, &anchor_height)?
                    .ok_or(TreasuryError::MissingWitness(position))?;
                Ok((path, root))
            })?;

        Ok(FundingSelection {
            note: Some(SpendableNote {
                note: *received.note(),
                value_zat: received.note().value().inner(),
                merkle_path: MerklePath::from(path),
                anchor: Anchor::from(root),
            }),
            spendable_total_zat,
        })
    }
}
