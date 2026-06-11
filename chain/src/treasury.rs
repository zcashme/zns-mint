//! Treasury note-state: the registry's wallet.
//!
//! [`NoteState`] wraps `zcash_client_sqlite`'s `WalletDb`, which owns scanning,
//! shardtree witnesses, reorg rewind, and note selection — the spend side of
//! the mint borrows a real wallet instead of hand-rolling one. The registry
//! account is imported view-only (the spend key never leaves `zns-signer`);
//! `sync::run` keeps the wallet at the chain tip incrementally, and
//! [`NoteState::select_funding`] turns a spendable note into the
//! `(note, path, anchor)` triple `zns_signer::build_funded_mint` needs.
//!
//! The wallet sees only ordinary notes (the treasury float and change). The
//! Name Notes the registry mints override the ZIP-212 `rseed → (rcm, ψ)`
//! derivation, so standard trial-decryption rejects them — by design: the
//! registry confirms its own Name Notes by recomputing their `cmx`, not by
//! decrypting them.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::ops::Range;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use orchard::tree::{Anchor, MerklePath};
use rand::rngs::OsRng;
use zcash_address::unified::{Encoding as _, Fvk, Ufvk};
use zcash_client_backend::{
    data_api::{
        chain::{error as chain_error, BlockCache, BlockSource},
        scanning::ScanRange,
        wallet::ConfirmationsPolicy,
        Account as _, AccountBirthday, AccountPurpose, BirthdayError, InputSource as _,
        TargetValue, WalletCommitmentTrees as _, WalletRead as _, WalletWrite as _,
    },
    proto::{compact_formats::CompactBlock, service::BlockId},
    sync,
};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{consensus::Network, value::Zatoshis, ShieldedProtocol};

use crate::{grpc, ScannerConfig};

/// Compact blocks per `sync::run` download/scan batch.
const SYNC_BATCH_SIZE: u32 = 1_000;

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
pub struct NoteState {
    db: WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    cache: MemBlockCache,
    network: Network,
    lwd_url: String,
    account: AccountUuid,
}

impl NoteState {
    /// Open (or create) the wallet database at `wallet_db` and ensure the
    /// registry account exists, imported view-only at the configured birthday.
    pub async fn open(wallet_db: impl AsRef<Path>, config: &ScannerConfig) -> anyhow::Result<Self> {
        let mut db = WalletDb::for_path(wallet_db, config.network, SystemClock, OsRng)
            .context("open wallet db")?;
        init_wallet_db(&mut db, None).map_err(|e| anyhow!("init wallet db: {e}"))?;

        let account = match db.get_account_ids().context("list wallet accounts")?.first() {
            Some(id) => *id,
            None => {
                let birthday = birthday(config).await?;
                // The only stable public UFVK constructor is the ZIP 316
                // container parse; the from-parts constructors are test- or
                // frost-gated.
                let ufvk =
                    Ufvk::try_from_items(vec![Fvk::Orchard(config.registry_fvk.to_bytes())])
                        .map_err(|e| anyhow!("ufvk container: {e:?}"))?;
                let ufvk = UnifiedFullViewingKey::parse(&ufvk)
                    .map_err(|e| anyhow!("ufvk parse: {e:?}"))?;
                db.import_account_ufvk(
                    "zns-registry",
                    &ufvk,
                    &birthday,
                    AccountPurpose::ViewOnly,
                    None,
                )
                .context("import registry account")?
                .id()
            }
        };

        Ok(NoteState {
            db,
            cache: MemBlockCache::default(),
            network: config.network,
            lwd_url: config.lwd_url.clone(),
            account,
        })
    }

    /// Bring the wallet to the chain tip: download new compact blocks from
    /// lightwalletd and scan them. Incremental — a quiet poll is one round
    /// trip — and it is also where reorg rewind happens.
    pub async fn sync(&mut self) -> anyhow::Result<()> {
        let mut client = grpc::connect(&self.lwd_url)
            .await
            .map_err(|e| anyhow!("connect to {}: {e:?}", self.lwd_url))?;
        sync::run(&mut client, &self.network, &self.cache, &mut self.db, SYNC_BATCH_SIZE)
            .await
            .map_err(|e| anyhow!("wallet sync: {e}"))
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
    ) -> anyhow::Result<FundingSelection> {
        let min_confirmations =
            NonZeroU32::new(min_confirmations.max(1)).expect("max(1) is nonzero");
        let policy = ConfirmationsPolicy::new_symmetrical(min_confirmations);

        let spendable_total_zat = self
            .db
            .get_wallet_summary(policy)
            .context("wallet summary")?
            .as_ref()
            .and_then(|s| s.account_balances().get(&self.account))
            .map(|b| u64::from(b.orchard_balance().spendable_value()))
            .unwrap_or(0);

        // No blocks scanned yet → nothing spendable.
        let Some((target_height, anchor_height)) = self
            .db
            .get_target_and_anchor_heights(min_confirmations)
            .context("target/anchor heights")?
        else {
            return Ok(FundingSelection { note: None, spendable_total_zat });
        };

        // Selection targets a *sum*; the mint spends a single input, so the
        // note itself must meet the floor.
        let notes = self
            .db
            .select_spendable_notes(
                self.account,
                TargetValue::AtLeast(
                    Zatoshis::from_u64(min_value_zat).map_err(|e| anyhow!("floor: {e:?}"))?,
                ),
                &[ShieldedProtocol::Orchard],
                target_height,
                policy,
                &[],
            )
            .context("select spendable notes")?;
        let Some(received) =
            notes.orchard().iter().find(|n| n.note().value().inner() >= min_value_zat)
        else {
            return Ok(FundingSelection { note: None, spendable_total_zat });
        };

        let position = received.note_commitment_tree_position();
        let (path, root) = self.db.with_orchard_tree_mut::<_, _, anyhow::Error>(|tree| {
            let root = tree
                .root_at_checkpoint_id(&anchor_height)?
                .ok_or_else(|| anyhow!("no orchard checkpoint at anchor height {anchor_height}"))?;
            let path = tree
                .witness_at_checkpoint_id_caching(position, &anchor_height)?
                .ok_or_else(|| anyhow!("no witness for note at {position:?}"))?;
            Ok::<_, anyhow::Error>((path, root))
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

/// Fetch the tree state just below the configured birthday and turn it into
/// the wallet's [`AccountBirthday`]. The birthday is the height *after* the
/// anchoring tree state, so it floors at 2 — fund the registry above that.
async fn birthday(config: &ScannerConfig) -> anyhow::Result<AccountBirthday> {
    let prior = config.birthday.max(2) - 1;
    let mut client = grpc::connect(&config.lwd_url)
        .await
        .map_err(|e| anyhow!("connect to {}: {e:?}", config.lwd_url))?;
    let treestate = client
        .get_tree_state(BlockId { height: prior as u64, hash: vec![] })
        .await
        .context("get_tree_state for birthday")?
        .into_inner();
    AccountBirthday::from_treestate(treestate, None).map_err(|e| match e {
        BirthdayError::HeightInvalid(e) => anyhow!("account birthday height: {e}"),
        BirthdayError::Decode(e) => anyhow!("account birthday tree state: {e}"),
    })
}

/// In-memory compact-block cache for [`sync::run`]. Blocks live only between
/// download and scan — the wallet db records scan progress, so nothing here
/// needs to survive a restart.
#[derive(Default)]
struct MemBlockCache(Mutex<BTreeMap<u64, CompactBlock>>);

fn range_bounds(range: &ScanRange) -> Range<u64> {
    u64::from(u32::from(range.block_range().start))..u64::from(u32::from(range.block_range().end))
}

impl BlockSource for MemBlockCache {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<zcash_protocol::consensus::BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>,
    {
        let blocks = self.0.lock().expect("block cache lock");
        let from = from_height.map(|h| u64::from(u32::from(h))).unwrap_or(0);
        for block in blocks.range(from..).map(|(_, b)| b.clone()).take(limit.unwrap_or(usize::MAX))
        {
            with_block(block)?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for MemBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<zcash_protocol::consensus::BlockHeight>, Self::Error> {
        let blocks = self.0.lock().expect("block cache lock");
        let tip = match range {
            Some(range) => blocks.range(range_bounds(range)).next_back().map(|(h, _)| *h),
            None => blocks.keys().next_back().copied(),
        };
        Ok(tip.map(|h| zcash_protocol::consensus::BlockHeight::from_u32(h as u32)))
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let blocks = self.0.lock().expect("block cache lock");
        Ok(blocks.range(range_bounds(range)).map(|(_, b)| b.clone()).collect())
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut blocks = self.0.lock().expect("block cache lock");
        for block in compact_blocks {
            blocks.insert(block.height, block);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let mut blocks = self.0.lock().expect("block cache lock");
        let keys: Vec<u64> = blocks.range(range_bounds(&range)).map(|(h, _)| *h).collect();
        for key in keys {
            blocks.remove(&key);
        }
        Ok(())
    }
}
