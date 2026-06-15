//! Treasury: owns the registry's self-funding light client state (data WalletDb
//! + BlockDb cache).
//!
//! Follows the shape used by zallet and other "proper" zcash_client_sqlite
//! integrations:
//! - One owning struct holds the WalletDb (notes, witnesses, scan progress) and
//!   the BlockDb (persistent compact blocks).
//! - Provides `async fn sync(&mut self, lwd_url: &str)` so the caller just asks
//!   it to stay up to date.
//! - `select_funding(...)` is the only thing the mint loop needs for the two
//!   spend types (name note mints + sweeps).
//!
//! This removes the old passive `wallet_db_mut` + "orchestrator does everything"
//! model. The Treasury object is responsible for its own DBs and for driving
//! the library scan (modeled on zallet's owning DB wrapper + custom MemoryCache
//! + manual/ high-level scan drive).

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

use crate::block_cache::PersistedBlockCache;

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

/// Owns a `zcash_client_sqlite::WalletDb` (plus Orchard shardtree) holding the
/// registry's view-only account and its spendable notes ("treasury float").
///
/// This type is intentionally passive:
/// - `open` / `initialize` set up the WalletDb (and run migrations).
/// - `select_funding` extracts a spendable note + witness.
/// - `wallet_db_mut` exposes the underlying WalletDb so an external driver
///   can perform scanning.
///
/// The type does *not* own lightwalletd clients, block caches, or a sync loop.
/// Whether a particular binary actually drives sync through `wallet_db_mut`
/// or just calls `select_funding` on a stub is up to the caller.
pub struct Treasury {
    data: WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    block_cache: PersistedBlockCache,
    network: Network,
    account: AccountUuid,
}

impl Treasury {
    /// Open (or create) the treasury WalletDb and run migrations.
    ///
    /// If no account has been imported yet this returns `Uninitialized`.
    /// The caller is then expected to do the one-time birthday bootstrap
    /// (via lightwalletd get_tree_state) and call `initialize`.
    ///
    /// This function itself does no network I/O.
    pub fn open(
        wallet_db_path: impl AsRef<Path>,
        block_db_path: impl AsRef<Path>,
        config: &TreasuryConfig,
    ) -> Result<Self, TreasuryError> {
        // Data DB (notes, trees, scan progress, witnesses)
        let mut data = WalletDb::for_path(wallet_db_path, config.network, SystemClock, OsRng)?;
        init_wallet_db(&mut data, None).map_err(|e| TreasuryError::Init(e.to_string()))?;

        let block_cache = PersistedBlockCache::open(block_db_path)?;

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
            block_cache,
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
        block_db_path: impl AsRef<Path>,
        config: &TreasuryConfig,
        birthday: AccountBirthday,
    ) -> Result<Self, TreasuryError> {
        // Data DB (notes, trees, scan progress, witnesses)
        let mut data = WalletDb::for_path(wallet_db_path, config.network, SystemClock, OsRng)?;
        init_wallet_db(&mut data, None).map_err(|e| TreasuryError::Init(e.to_string()))?;

        let block_cache = PersistedBlockCache::open(block_db_path)?;

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
            block_cache,
            network: config.network,
            account,
        })
    }

    /// Convenience method that owns a sync run for this Treasury's WalletDb.
    ///
    /// Sync the wallet against lightwalletd using the on-disk compact-block cache.
    pub async fn sync<ChT>(
        &mut self,
        client: &mut zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<ChT>,
    ) -> Result<(), TreasuryError>
    where
        ChT: tonic::client::GrpcService<TonicBody> + Send + Sync + 'static,
        ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
        ChT::Error: Into<StdError>,
    {
        zcash_client_backend::sync::run(
            client,
            &self.network,
            &self.block_cache,
            &mut self.data,
            1_000,
        )
        .await
        .map_err(|e| TreasuryError::Init(format!("treasury sync: {e:#}")))?;
        Ok(())
    }

    /// Gives the caller direct mutable access to the underlying WalletDb.
    ///
    /// This exists so an external piece of code can perform scanning, rewinds,
    /// or anything else the WalletDb supports. In the current mint binary this
    /// method is not actually called on a real instance (the NoteState is a
    /// dummy and treasury sync is disabled).
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
