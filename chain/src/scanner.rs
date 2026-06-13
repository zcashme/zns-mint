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

use std::convert::Infallible;

use orchard::{
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{CompactAction, OrchardDomain},
    Action,
};
use thiserror::Error;
use zcash_client_backend::proto::compact_formats::CompactOrchardAction;
use zcash_note_encryption::{batch, try_note_decryption, EphemeralKeyBytes};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

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
    pub height: u32,
    /// Action index within the transaction's Orchard bundle.
    pub output_index: u32,
    /// Note value in zatoshis.
    pub value_zat: u64,
    /// Raw memo bytes (512, zero-padded per ZIP 302).
    pub memo: Vec<u8>,
    /// Always `true`: only IVK-decrypted (received) notes are surfaced.
    pub is_received: bool,
}

/// Scan from `config.birthday` to the current chain tip, invoking `callback`
/// once per block that contains notes addressed to the registry UFVK.
///
/// Receive-side, single pass (no reorg rewind — the daemon re-runs to advance).
pub async fn scan_incoming<F, E>(config: &ScannerConfig, mut callback: F) -> Result<(), ScanError>
where
    F: FnMut(Vec<IncomingNote>) -> Result<(), E>,
    E: std::error::Error + Send + Sync + 'static,
{
    let client = GrpcClient::new(&config.lwd_url);
    let ivk = orchard_ivk(&config.registry_ivk);

    let tip = client.tip_height().await?;
    if config.birthday > tip {
        return Ok(());
    }

    let mut stream = client.block_range(config.birthday, tip).await?;

    while let Some(block) = stream
        .message()
        .await
        .map_err(|source| GrpcError::Rpc { call: "block stream", source })?
    {
        let height = block.height as u32;

        // (txid, action_index, value_zat) for every action that IVK-decrypts.
        let mut hits: Vec<([u8; 32], usize, u64)> = Vec::new();
        for ctx in &block.vtx {
            let Ok(txid) = <[u8; 32]>::try_from(&ctx.txid[..]) else {
                continue;
            };
            // Parse failures are errors, not skips: a dropped action would
            // shift every later enumerate() index, mis-attributing memos to
            // the wrong note. Consensus-valid data always parses.
            let actions: Vec<CompactAction> = ctx
                .actions
                .iter()
                .map(|a| {
                    parse_orchard(a)
                        .ok_or_else(|| ScanError::UnparseableAction { txid: hex::encode(txid) })
                })
                .collect::<Result<_, ScanError>>()?;
            if actions.is_empty() {
                continue;
            }
            for (i, hit) in try_compact_orchard(&ivk, actions).into_iter().enumerate() {
                if let Some(value) = hit {
                    hits.push((txid, i, value));
                }
            }
        }
        if hits.is_empty() {
            continue;
        }

        // Enrich each hit with its memo by fetching the full transaction once.
        let branch = BranchId::for_height(&config.network, BlockHeight::from_u32(height));
        let mut batch_out: Vec<IncomingNote> = Vec::with_capacity(hits.len());
        let mut last_txid: Option<[u8; 32]> = None;
        let mut tx: Option<Transaction> = None;
        for (txid, idx, value) in hits {
            if last_txid != Some(txid) {
                tx = fetch_transaction(&client, &txid, branch).await?;
                last_txid = Some(txid);
            }
            let memo = tx
                .as_ref()
                .and_then(|t| t.orchard_bundle())
                .and_then(|b| b.actions().get(idx))
                .and_then(|action| decrypt_memo(action, &ivk))
                .unwrap_or_default();

            batch_out.push(IncomingNote {
                txid,
                height,
                output_index: idx as u32,
                value_zat: value,
                memo,
                is_received: true,
            });
        }
        callback(batch_out).map_err(|e| ScanError::Callback(Box::new(e)))?;
    }

    Ok(())
}

/// Collect **all** notes from `birthday` to chain tip into a `Vec`.
///
/// Convenience wrapper around [`scan_incoming`]; for large ranges prefer the
/// callback form to bound memory.
pub async fn scan_incoming_all(config: &ScannerConfig) -> Result<Vec<IncomingNote>, ScanError> {
    let mut all = Vec::new();
    scan_incoming(config, |batch| -> Result<(), Infallible> {
        all.extend(batch);
        Ok(())
    })
    .await?;
    Ok(all)
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
    let tx = Transaction::read(&raw[..], branch)
        .map_err(|source| ScanError::ParseTransaction { txid: hex::encode(txid), branch, source })?;
    Ok(Some(tx))
}

