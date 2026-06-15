//! Chain intake — scans `addr_reg` for incoming ZNS request notes.
//!
//! Host owns this directly now (no `seer-sync`): it streams compact blocks from
//! lightwalletd via [`crate::grpc`], trial-decrypts each Orchard action with the
//! registry IVK (standard ZIP-212 — the *inbound* request notes are ordinary
//! notes; only the Name Notes the registry *mints* are non-standard), then
//! fetches the full transaction to recover the memo (compact blocks omit it).
//!
//! Scope: receive-side intake only. Spends of the registry's own notes are
//! tracked by the [`crate::treasury`] note-state (`WalletDb`).

use orchard::{
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{CompactAction, OrchardDomain},
    Action,
};
use sapling::note_encryption::{
    CompactOutputDescription, Zip212Enforcement,
};
use thiserror::Error;
use zcash_client_backend::proto::compact_formats::CompactOrchardAction;
use zcash_note_encryption::{batch, try_note_decryption, EphemeralKeyBytes};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::ShieldedProtocol;

use crate::grpc::{GrpcClient, GrpcError};

/// Errors scanning `addr_reg` for incoming Name Note requests.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error(transparent)]
    Grpc(#[from] GrpcError),

    #[error("unparseable compact Orchard action in tx {txid}")]
    UnparseableAction { txid: String },

    #[error("parsing tx {txid} under {branch:?}: {source}")]
    ParseTransaction {
        txid: String,
        branch: BranchId,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Callback(Box<dyn std::error::Error + Send + Sync>),
}

/// Configuration for the scanner.
pub struct ScannerConfig {
    /// The registry's external-scope Orchard Incoming Viewing Key (`addr_reg`).
    /// IVK-only: the scanner trial-decrypts incoming request notes, which never
    /// requires a nullifier key.
    pub registry_ivk: orchard::keys::IncomingViewingKey,
    /// The registry's Sapling incoming viewing key (derived from the same ZIP-32
    /// seed as the Orchard IVK). Used only internally for trial-decrypting ZNS
    /// memos that arrive as Sapling notes. Never published in the public UIVK/UA.
    pub sapling_ivk: Option<sapling::SaplingIvk>,
    /// The Zcash network to scan (drives branch resolution for tx parsing).
    pub network: Network,
    /// Block height to start scanning from (the key's "birthday").
    pub birthday: u32,
    /// Lightwalletd URL, e.g. `"http://127.0.0.1:9067"` or `"https://zec.rocks:443"`.
    pub lwd_url: String,
}

/// A note received at the registry address.
#[derive(Debug, Clone)]
pub struct IncomingNote {
    /// Transaction ID (internal byte order, as the chain returns it).
    pub txid: [u8; 32],
    /// Block height the containing transaction was mined in.
    /// For mempool notes this is the height at which the tx was observed
    /// (typically the current chain tip) and may be zero if unknown.
    pub height: u32,
    /// Block hash of the containing block. All zeros for mempool notes.
    pub block_hash: [u8; 32],
    /// Index of the output/action within its shielded pool's list in the tx
    /// (Orchard actions or Sapling shielded outputs). Combined with txid and
    /// pool this uniquely identifies the note for settlement/replay.
    pub output_index: u32,
    /// Which shielded pool the note arrived in.
    pub pool: ShieldedProtocol,
    /// Note value in zatoshis.
    pub value_zat: u64,
    /// Raw memo bytes (512, zero-padded per ZIP 302).
    pub memo: Vec<u8>,
    /// Always `true`: only IVK-decrypted (received) notes are surfaced.
    pub is_received: bool,
    /// `true` if this note was observed in a mined block.
    /// Mempool notes are `false` and must not be settled until confirmed.
    pub confirmed: bool,
}

/// Scan `[start, end]` block-linear, invoking `callback` once per block.
///
/// `callback` runs even when a block has no registry notes (`notes` is empty).
pub async fn scan_blocks<F, Fut, E>(
    config: &ScannerConfig,
    start: u32,
    end: u32,
    mut callback: F,
) -> Result<(), ScanError>
where
    F: FnMut(u32, [u8; 32], Vec<IncomingNote>) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    if start > end {
        return Ok(());
    }

    let client = GrpcClient::new(&config.lwd_url);
    let ivk = orchard_ivk(&config.registry_ivk);

    let mut stream = client.block_range(start, end).await?;

    // Prepare Sapling IVK once per scan (if provided). We use the raw IVK here
    // and prepare on demand; this mirrors how the Orchard IVK is handled.
    let sapling_prepared: Option<sapling::keys::PreparedIncomingViewingKey> =
        config.sapling_ivk.as_ref().map(sapling::keys::PreparedIncomingViewingKey::new);

    while let Some(block) = stream.message().await.map_err(|source| GrpcError::Rpc {
        call: "block stream",
        source,
    })? {
        let height = block.height as u32;
        let block_hash: [u8; 32] = block.hash[..].try_into().unwrap_or([0u8; 32]);

        // (txid, output_index, value_zat, pool) for every shielded output/action
        // that IVK-decrypts. We process *both* pools; a tx may have only Sapling,
        // only Orchard, or (rarely) both. Never early-continue on one pool being
        // empty.
        let mut hits: Vec<([u8; 32], usize, u64, ShieldedProtocol)> = Vec::new();
        for ctx in &block.vtx {
            let Ok(txid) = <[u8; 32]>::try_from(&ctx.txid[..]) else {
                continue;
            };

            // Sapling outputs (if we have a Sapling IVK configured).
            if let Some(ref spivk) = sapling_prepared {
                for (i, so) in ctx.outputs.iter().enumerate() {
                    if let Ok(compact) = CompactOutputDescription::try_from(so) {
                        if let Some((note, _addr)) = sapling::note_encryption::try_sapling_compact_note_decryption(
                            spivk,
                            &compact,
                            Zip212Enforcement::GracePeriod,
                        ) {
                            hits.push((txid, i, note.value().inner(), ShieldedProtocol::Sapling));
                        }
                    }
                }
            }

            // Orchard actions (existing path, kept for compatibility).
            // Parse failures are errors, not skips: a dropped action would
            // shift every later enumerate() index, mis-attributing memos to
            // the wrong note. Consensus-valid data always parses.
            let actions: Vec<CompactAction> = ctx
                .actions
                .iter()
                .map(|a| {
                    parse_orchard(a).ok_or_else(|| ScanError::UnparseableAction {
                        txid: hex::encode(txid),
                    })
                })
                .collect::<Result<_, ScanError>>()?;
            for (i, hit) in try_compact_orchard(&ivk, actions).into_iter().enumerate() {
                if let Some(value) = hit {
                    hits.push((txid, i, value, ShieldedProtocol::Orchard));
                }
            }
        }
        if hits.is_empty() {
            callback(height, block_hash, Vec::new())
                .await
                .map_err(|e| ScanError::Callback(Box::new(e)))?;
            continue;
        }

        // Enrich each hit with its memo by fetching the full transaction once.
        let branch = BranchId::for_height(&config.network, BlockHeight::from_u32(height));
        let mut batch_out: Vec<IncomingNote> = Vec::with_capacity(hits.len());
        let mut last_txid: Option<[u8; 32]> = None;
        let mut tx: Option<Transaction> = None;
        for (txid, idx, value, pool) in hits {
            if last_txid != Some(txid) {
                tx = fetch_transaction(&client, &txid, branch).await?;
                last_txid = Some(txid);
            }

            let memo = match pool {
                ShieldedProtocol::Orchard => tx
                    .as_ref()
                    .and_then(|t| t.orchard_bundle())
                    .and_then(|b| b.actions().get(idx))
                    .and_then(|action| decrypt_memo(action, &ivk))
                    .unwrap_or_default(),
                ShieldedProtocol::Sapling => {
                    // Memo recovery for Sapling requires the full tx (compact
                    // only carries the 52-byte prefix). Use the same full-tx
                    // fetch we already do for Orchard.
                    let prepared = config
                        .sapling_ivk
                        .as_ref()
                        .map(sapling::keys::PreparedIncomingViewingKey::new);
                    if let (Some(p), Some(output)) = (
                        prepared.as_ref(),
                        tx.as_ref().and_then(|t| t.sapling_bundle()).and_then(|b| b.shielded_outputs().get(idx)),
                    ) {
                        if let Some((_note, _addr, memo)) = sapling::note_encryption::try_sapling_note_decryption(
                            p,
                            output,
                            Zip212Enforcement::GracePeriod,
                        ) {
                            memo.to_vec()
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    }
                }
            };

            batch_out.push(IncomingNote {
                txid,
                height,
                block_hash,
                output_index: idx as u32,
                pool,
                value_zat: value,
                memo,
                is_received: true,
                confirmed: true,
            });
        }
        callback(height, block_hash, batch_out)
            .await
            .map_err(|e| ScanError::Callback(Box::new(e)))?;
    }

    Ok(())
}

/// Scan from `config.birthday` to the current chain tip, invoking `callback`
/// once per block that contains notes addressed to the registry UFVK.
///
/// Receive-side, single pass (no reorg rewind — the daemon re-runs to advance).
pub async fn scan_incoming<F, Fut, E>(config: &ScannerConfig, mut callback: F) -> Result<(), ScanError>
where
    F: FnMut(Vec<IncomingNote>) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let client = GrpcClient::new(&config.lwd_url);
    let tip = client.tip_height().await?;
    if config.birthday > tip {
        return Ok(());
    }
    scan_blocks(config, config.birthday, tip, |_, _, notes| callback(notes)).await
}

/// Collect **all** notes from `birthday` to chain tip into a `Vec`.
///
/// Convenience wrapper around [`scan_incoming`]; for large ranges prefer the
/// callback form to bound memory.
pub async fn scan_incoming_all(config: &ScannerConfig) -> Result<Vec<IncomingNote>, ScanError> {
    let mut all = Vec::new();
    scan_incoming(config, |batch| {
        all.extend(batch);
        async { Ok::<(), std::convert::Infallible>(()) }
    })
    .await?;
    Ok(all)
}

/// Scan the current mempool for ZNS notes addressed to `addr_reg`.
///
/// Mempool notes are **unconfirmed**. They are returned with `confirmed: false`
/// so the caller can monitor them without settling them. `current_height` is
/// used only for branch-id resolution and bookkeeping; mempool txs have no
/// stable block height yet.
pub async fn scan_mempool(
    config: &ScannerConfig,
    current_height: u32,
) -> Result<Vec<IncomingNote>, ScanError> {
    let client = GrpcClient::new(&config.lwd_url);
    let ivk = orchard_ivk(&config.registry_ivk);

    let sapling_prepared: Option<sapling::keys::PreparedIncomingViewingKey> =
        config.sapling_ivk.as_ref().map(sapling::keys::PreparedIncomingViewingKey::new);

    let compact_txs = client.mempool_compact_txs().await?;
    if compact_txs.is_empty() {
        return Ok(Vec::new());
    }

    // Mempool txs are intended for the next block, so resolve the branch for
    // the current tip. This is an approximation; a future branch activation
    // between tip and next block is handled by the next poll's re-parse.
    let branch = BranchId::for_height(&config.network, BlockHeight::from_u32(current_height));

    let mut hits: Vec<([u8; 32], usize, u64, ShieldedProtocol)> = Vec::new();
    for ctx in &compact_txs {
        let Ok(txid) = <[u8; 32]>::try_from(&ctx.txid[..]) else {
            continue;
        };

        // Sapling
        if let Some(ref spivk) = sapling_prepared {
            for (i, so) in ctx.outputs.iter().enumerate() {
                if let Ok(compact) = CompactOutputDescription::try_from(so) {
                    if let Some((note, _addr)) = sapling::note_encryption::try_sapling_compact_note_decryption(
                        spivk,
                        &compact,
                        Zip212Enforcement::GracePeriod,
                    ) {
                        hits.push((txid, i, note.value().inner(), ShieldedProtocol::Sapling));
                    }
                }
            }
        }

        // Orchard
        let actions: Vec<CompactAction> = ctx
            .actions
            .iter()
            .map(|a| {
                parse_orchard(a).ok_or_else(|| ScanError::UnparseableAction {
                    txid: hex::encode(txid),
                })
            })
            .collect::<Result<_, ScanError>>()?;
        for (i, hit) in try_compact_orchard(&ivk, actions).into_iter().enumerate() {
            if let Some(value) = hit {
                hits.push((txid, i, value, ShieldedProtocol::Orchard));
            }
        }
    }
    if hits.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(hits.len());
    let mut last_txid: Option<[u8; 32]> = None;
    let mut tx: Option<Transaction> = None;
    for (txid, idx, value, pool) in hits {
        if last_txid != Some(txid) {
            tx = fetch_transaction(&client, &txid, branch).await?;
            last_txid = Some(txid);
        }

        let memo = match pool {
            ShieldedProtocol::Orchard => tx
                .as_ref()
                .and_then(|t| t.orchard_bundle())
                .and_then(|b| b.actions().get(idx))
                .and_then(|action| decrypt_memo(action, &ivk))
                .unwrap_or_default(),
            ShieldedProtocol::Sapling => {
                let prepared = config
                    .sapling_ivk
                    .as_ref()
                    .map(sapling::keys::PreparedIncomingViewingKey::new);
                if let (Some(p), Some(output)) = (
                    prepared.as_ref(),
                    tx.as_ref().and_then(|t| t.sapling_bundle()).and_then(|b| b.shielded_outputs().get(idx)),
                ) {
                    if let Some((_note, _addr, memo)) = sapling::note_encryption::try_sapling_note_decryption(
                        p,
                        output,
                        Zip212Enforcement::GracePeriod,
                    ) {
                        memo.to_vec()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            }
        };

        out.push(IncomingNote {
            txid,
            height: current_height,
            block_hash: [0u8; 32],
            output_index: idx as u32,
            pool,
            value_zat: value,
            memo,
            is_received: true,
            confirmed: false,
        });
    }

    Ok(out)
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Prepare the registry's incoming viewing key for trial decryption.
fn orchard_ivk(ivk: &orchard::keys::IncomingViewingKey) -> PreparedIncomingViewingKey {
    PreparedIncomingViewingKey::new(ivk)
}

/// Convert a proto [`CompactOrchardAction`] into an orchard [`CompactAction`].
pub(crate) fn parse_orchard(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}

/// Trial-decrypt a batch of compact actions; returns the note value (zatoshis)
/// for each that decrypts under `ivk`, else `None` at that index.
fn try_compact_orchard(
    ivk: &PreparedIncomingViewingKey,
    actions: Vec<CompactAction>,
) -> Vec<Option<u64>> {
    let inputs: Vec<(OrchardDomain, CompactAction)> = actions
        .into_iter()
        .map(|a| (OrchardDomain::for_compact_action(&a), a))
        .collect();
    batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
        .into_iter()
        .map(|hit| hit.map(|((note, _recipient), _ivk_idx)| note.value().inner()))
        .collect()
}

/// Full-decrypt a single Orchard action to recover its 512-byte memo.
fn decrypt_memo<A>(action: &Action<A>, ivk: &PreparedIncomingViewingKey) -> Option<Vec<u8>> {
    let (_note, _recipient, memo) =
        try_note_decryption(&OrchardDomain::for_action(action), ivk, action)?;
    Some(memo.to_vec())
}

/// Fetch and parse a full transaction by txid.
async fn fetch_transaction(
    client: &GrpcClient,
    txid: &[u8; 32],
    branch: BranchId,
) -> Result<Option<Transaction>, ScanError> {
    let raw = client.fetch_transaction(txid).await?;
    // A parse failure must propagate (transient — the poll retries), never
    // degrade to "no memo": that would settle real requests permanently as
    // memo-parse errors if a branch-id mismatch or parser bug ever slipped in.
    let tx = Transaction::read(&raw[..], branch).map_err(|source| ScanError::ParseTransaction {
        txid: hex::encode(txid),
        branch,
        source,
    })?;
    Ok(Some(tx))
}


