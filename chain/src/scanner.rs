//! Chain intake — scans `addr_reg` for incoming ZNS request notes.
//!
//! Host owns this directly now (no `seer-sync`): it streams compact blocks from
//! lightwalletd via [`crate::grpc`], trial-decrypts each Orchard action with the
//! registry IVK (standard ZIP-212 — the *inbound* request notes are ordinary
//! notes; only the Name Notes the registry *mints* are non-standard), then
//! fetches the full transaction to recover the memo (compact blocks omit it).
//!
//! Scope: receive-side only. Spends of the registry's own notes are not tracked
//! here — that belongs to the (future) note-state core.

use anyhow::{anyhow, Context as _};

use orchard::{
    keys::{PreparedIncomingViewingKey, Scope},
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{CompactAction, OrchardDomain},
    Action,
};
use zcash_client_backend::proto::{
    compact_formats::CompactOrchardAction,
    service::{BlockId, BlockRange, ChainSpec, TxFilter},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{batch, try_note_decryption, EphemeralKeyBytes};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

use crate::grpc;

/// Configuration for the scanner.
pub struct ScannerConfig {
    /// The Unified Full Viewing Key of the registry address (`addr_reg`).
    pub ufvk: String,
    /// The Zcash network to scan.
    pub network: Network,
    /// Block height to start scanning from (the UFVK's "birthday").
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
pub async fn scan_incoming<F>(config: &ScannerConfig, mut callback: F) -> anyhow::Result<()>
where
    F: FnMut(Vec<IncomingNote>) -> anyhow::Result<()>,
{
    let mut client = grpc::connect(&config.lwd_url)
        .await
        .map_err(|e| anyhow!("connect to {}: {e}", config.lwd_url))?;
    // Separate client for full-transaction fetches while the block stream runs.
    let mut fetch_client = client.clone();

    let ivk = orchard_ivk(&config.network, &config.ufvk)?;

    let tip = client
        .get_latest_block(ChainSpec {})
        .await
        .context("get_latest_block")?
        .into_inner()
        .height as u32;
    if config.birthday > tip {
        return Ok(());
    }

    let mut stream = client
        .get_block_range(BlockRange {
            start: Some(BlockId { height: config.birthday as u64, hash: vec![] }),
            end: Some(BlockId { height: tip as u64, hash: vec![] }),
            // empty = all shielded pools (we filter to Orchard ourselves)
            pool_types: vec![],
        })
        .await
        .context("get_block_range")?
        .into_inner();

    while let Some(block) = stream.message().await.context("block stream")? {
        let height = block.height as u32;

        // (txid, action_index, value_zat) for every action that IVK-decrypts.
        let mut hits: Vec<([u8; 32], usize, u64)> = Vec::new();
        for ctx in &block.vtx {
            let Ok(txid) = <[u8; 32]>::try_from(&ctx.txid[..]) else {
                continue;
            };
            let actions: Vec<CompactAction> = ctx.actions.iter().filter_map(parse_orchard).collect();
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
                tx = fetch_transaction(&mut fetch_client, &txid, branch).await?;
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
        callback(batch_out)?;
    }

    Ok(())
}

/// Collect **all** notes from `birthday` to chain tip into a `Vec`.
///
/// Convenience wrapper around [`scan_incoming`]; for large ranges prefer the
/// callback form to bound memory.
pub async fn scan_incoming_all(config: &ScannerConfig) -> anyhow::Result<Vec<IncomingNote>> {
    let mut all = Vec::new();
    scan_incoming(config, |batch| {
        all.extend(batch);
        Ok(())
    })
    .await?;
    Ok(all)
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Decode the registry UFVK and prepare its external Orchard incoming viewing key.
fn orchard_ivk(network: &Network, ufvk: &str) -> anyhow::Result<PreparedIncomingViewingKey> {
    let ufvk = UnifiedFullViewingKey::decode(network, ufvk)
        .map_err(|e| anyhow!("UFVK decode failed: {e}"))?;
    let fvk = ufvk
        .orchard()
        .ok_or_else(|| anyhow!("UFVK has no Orchard component"))?;
    Ok(PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)))
}

/// Convert a proto [`CompactOrchardAction`] into an orchard [`CompactAction`].
fn parse_orchard(p: &CompactOrchardAction) -> Option<CompactAction> {
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
    client: &mut grpc::LwdClient,
    txid: &[u8; 32],
    branch: BranchId,
) -> anyhow::Result<Option<Transaction>> {
    let raw = client
        .get_transaction(TxFilter {
            block: None,
            index: 0,
            hash: txid.to_vec(),
        })
        .await
        .context("get_transaction")?
        .into_inner();
    match Transaction::read(&raw.data[..], branch) {
        Ok(tx) => Ok(Some(tx)),
        Err(_) => Ok(None),
    }
}

// ── live regtest smoke tests ─────────────────────────────────────────────────
//
// Ignored by default (need a local lightwalletd on :9067). Run with:
//   cargo test -p zns-chain scanner::regtest -- --ignored --nocapture
#[cfg(test)]
mod regtest {
    use super::*;
    use orchard::keys::{FullViewingKey, SpendingKey};
    use zcash_client_backend::proto::service::ChainSpec;
    use zcash_keys::keys::UnifiedFullViewingKey;

    const LWD: &str = "http://127.0.0.1:9067";

    /// A throwaway registry UFVK (owns nothing on the chain — we only exercise
    /// the connect + stream + trial-decrypt pipeline).
    fn registry_ufvk(network: &Network) -> String {
        let sk = SpendingKey::from_zip32_seed(&[0x42u8; 32], 1, zip32::AccountId::ZERO).unwrap();
        let fvk = FullViewingKey::from(&sk);
        UnifiedFullViewingKey::new(None, Some(fvk))
            .unwrap()
            .encode(network)
    }

    #[tokio::test]
    #[ignore = "needs a local regtest lightwalletd on :9067"]
    async fn connects_and_reads_tip() {
        let mut client = grpc::connect(LWD).await.expect("connect to lightwalletd");
        let tip = client
            .get_latest_block(ChainSpec {})
            .await
            .expect("get_latest_block")
            .into_inner();
        println!("regtest tip height: {}", tip.height);
        assert!(tip.height > 0);
    }

    #[tokio::test]
    #[ignore = "needs a local regtest lightwalletd on :9067"]
    async fn scan_pipeline_runs() {
        let network = Network::TestNetwork;
        let ufvk = registry_ufvk(&network);

        let mut client = grpc::connect(LWD).await.expect("connect");
        let tip = client
            .get_latest_block(ChainSpec {})
            .await
            .expect("tip")
            .into_inner()
            .height as u32;
        let birthday = tip.saturating_sub(300);

        let cfg = ScannerConfig { ufvk, network, birthday, lwd_url: LWD.to_string() };
        let mut count = 0usize;
        scan_incoming(&cfg, |batch| {
            count += batch.len();
            Ok(())
        })
        .await
        .expect("scan pipeline ran end-to-end against live lightwalletd");
        println!("scanned blocks {birthday}..={tip}; {count} notes for registry IVK");
    }
}
