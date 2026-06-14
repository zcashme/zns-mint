//! Treasury note-state: the registry's wallet.

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
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
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

/// The outcome of funding selection: the chosen unspent note (if any meets
/// the floor) plus the total spendable registry balance — the *hot balance*
/// the signer's low-watermark gate runs against.
pub struct FundingSelection {
    /// A spendable note worth at least the floor, with its witness.
    pub note: Option<SpendableNote>,
    /// Total spendable registry balance in zatoshis (floor or not).
    pub spendable_total_zat: u64,
}

/// The registry's note-state: a view-only `WalletDb` over the registry FVK.
///
/// This object owns the persisted treasury (spendable notes + orchard witnesses).
/// It does **not** perform chain sync. The orchestrator (main loop / sync
/// coordinator) is responsible for driving `zcash_client_backend::sync::run`
/// against `wallet_db_mut()` and keeping the view up to date before calling
/// `select_funding`.
pub struct NoteState {
    db: WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    network: Network,
    account: AccountUuid,
}

impl NoteState {
    /// Open the wallet database at `wallet_db`.
    ///
    /// If the registry account does not exist yet, this will fail with
    /// `TreasuryError::Uninitialized`. The orchestrator is responsible for
    /// the one-time bootstrap (fetching the tree state for the birthday and
    /// calling a separate import helper, or constructing with a birthday).
    ///
    /// Normal operation (account already imported) is synchronous and performs
    /// no network I/O.
    pub fn open(
        wallet_db: impl AsRef<Path>,
        config: &TreasuryConfig,
    ) -> Result<Self, TreasuryError> {
        let mut db = WalletDb::for_path(wallet_db, config.network, SystemClock, OsRng)?;
        init_wallet_db(&mut db, None).map_err(|e| TreasuryError::Init(e.to_string()))?;

        let account = match db.get_account_ids()?.first() {
            Some(id) => *id,
            None => {
                // First run / uninitialized treasury wallet.
                // The orchestrator must have supplied a pre-fetched AccountBirthday
                // (via chain helper that talks to lightwalletd get_tree_state).
                // We no longer do network I/O inside the "state" object.
                return Err(TreasuryError::Uninitialized(
                    "treasury wallet has no account — caller must supply AccountBirthday for initial import (see orchestrator bootstrap)".into(),
                ));
            }
        };

        Ok(NoteState {
            db,
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
        wallet_db: impl AsRef<Path>,
        config: &TreasuryConfig,
        birthday: AccountBirthday,
    ) -> Result<Self, TreasuryError> {
        let mut db = WalletDb::for_path(wallet_db, config.network, SystemClock, OsRng)?;
        init_wallet_db(&mut db, None).map_err(|e| TreasuryError::Init(e.to_string()))?;

        let account = if let Some(&id) = db.get_account_ids()?.first() {
            // Already present — treat as success (idempotent bootstrap).
            id
        } else {
            // The only stable public UFVK constructor is the ZIP 316 container parse.
            let ufvk =
                Ufvk::try_from_items(vec![Fvk::Orchard(config.registry_fvk.to_bytes())])?;
            let ufvk = UnifiedFullViewingKey::parse(&ufvk)?;

            db.import_account_ufvk(
                "zns-registry",
                &ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )?
            .id()
        };

        Ok(NoteState {
            db,
            network: config.network,
            account,
        })
    }

    /// Escape hatch for the orchestrator to drive synchronization.
    ///
    /// Returns a mutable handle to the underlying `WalletDb` so that an
    /// external sync driver (e.g. `zcash_client_backend::sync::run` called
    /// from the main poll loop or a dedicated coordinator) can feed it
    /// compact blocks and advance the scan state + witnesses.
    ///
    /// `state` does **not** own clients, caches, or the sync loop. This is
    /// the explicit seam.
    pub fn wallet_db_mut(
        &mut self,
    ) -> &mut WalletDb<rusqlite::Connection, Network, SystemClock, OsRng> {
        &mut self.db
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
            .db
            .get_wallet_summary(policy)?
            .as_ref()
            .and_then(|s| s.account_balances().get(&self.account))
            .map(|b| u64::from(b.orchard_balance().spendable_value()))
            .unwrap_or(0);

        // No blocks scanned yet → nothing spendable.
        let Some((target_height, anchor_height)) =
            self.db.get_target_and_anchor_heights(min_confirmations)?
        else {
            return Ok(FundingSelection {
                note: None,
                spendable_total_zat,
            });
        };

        // Selection targets a *sum*; the mint spends a single input, so the
        // note itself must meet the floor.
        let notes = self.db.select_spendable_notes(
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
            .db
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
