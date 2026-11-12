//! Independent Name Note scan: `zns-verify` trial-decrypt and
//! `verify_bound_name_note` — never mint's decoder. Every field asserted by
//! the happy path is checked here, in this repo, including the chain: each
//! successor's `prev` must be its predecessor's on-chain `cmx`.

use std::io::Cursor;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use zcash_primitives::block::Block;
use zns_verify::NameNote;

use super::{account_usk, regtest_network, DEV_SEED};
use crate::{Mint, Zebrad};

/// Whitepaper §3.5 Registry `(g_d, pk_d)` for the all-zero seed (ZIP-32 is
/// network-independent, so a non-tee regtest matches the mainnet vector).
pub const VECTOR_G_D: &str = "de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e";
pub const VECTOR_PK_D: &str = "6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996";

/// A Name Note that decrypted under the Registry FVK and whose memo fields
/// reproduce the on-chain `cmx`.
pub struct VerifiedNameNote {
    pub height: u32,
    pub txid: String,
    pub name: String,
    pub action: String,
    pub ua: String,
    pub expires_at: Option<String>,
    /// The memo's `prev` slot, verbatim hex — 64 zeros for a claim.
    pub prev: String,
    /// This note's own `cmx`, as its action published it — the value a
    /// successor's `prev` must carry.
    pub own_cmx: String,
    pub value: u64,
    pub g_d: [u8; 32],
    pub pk_d: [u8; 32],
}

fn registry_fvk() -> Result<orchard::keys::FullViewingKey> {
    let usk = account_usk(&regtest_network(), &DEV_SEED, 1)?;
    Ok(orchard::keys::FullViewingKey::from(usk.orchard()))
}

fn commitment_keys_for_fvk(fvk: &orchard::keys::FullViewingKey) -> ([u8; 32], [u8; 32]) {
    fvk.address_at(0u32, orchard::keys::Scope::External)
        .zns_commitment_keys()
}

/// ZIP-32 `g_d` / `pk_d` of the non-tee Registry address (account 1, j=0).
pub fn registry_commitment_keys() -> Result<([u8; 32], [u8; 32])> {
    Ok(commitment_keys_for_fvk(&registry_fvk()?))
}

/// Mine until a Name Note for `name` is in a block and `zns-verify` accepts it.
pub async fn wait_for_verified_name_note(
    zebra: &Zebrad,
    mint: &mut Mint,
    name: &str,
    from_height: u32,
) -> Result<VerifiedNameNote> {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if !mint.is_running() {
            bail!(
                "mint died while waiting to mine the Name Note:\n{}",
                mint.exit_detail()
            );
        }
        zebra.generate_blocks(1).await?;
        if let Some(note) = find_verified_name_note(zebra, from_height, name).await? {
            return Ok(note);
        }
        if Instant::now() >= deadline {
            bail!("no verified {name} Name Note from height {from_height} within 180s");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Find a verified Name Note for `name` already in `[from_height, tip]`.
pub async fn find_verified_name_note(
    zebra: &Zebrad,
    from_height: u32,
    name: &str,
) -> Result<Option<VerifiedNameNote>> {
    let tip = zebra.tip_height().await?;
    for height in from_height..=tip {
        for note in scan_block(zebra, height).await? {
            if note.name == name {
                return Ok(Some(note));
            }
        }
    }
    Ok(None)
}

/// Whether a block contains `txid`.
pub async fn block_contains_txid(zebra: &Zebrad, height: u32, txid: &str) -> Result<bool> {
    let block = read_block(zebra, height).await?;
    Ok(block.vtx().iter().any(|tx| tx.txid().to_string() == txid))
}

/// The block's transaction ids, in block order.
pub async fn block_txids(zebra: &Zebrad, height: u32) -> Result<Vec<String>> {
    let block = read_block(zebra, height).await?;
    Ok(block.vtx().iter().map(|tx| tx.txid().to_string()).collect())
}

async fn read_block(zebra: &Zebrad, height: u32) -> Result<Block> {
    let network = regtest_network();
    let hex = zebra
        .rpc("getblock", serde_json::json!([height.to_string(), 0]))
        .await
        .with_context(|| format!("getblock {height}"))?;
    let hex = hex
        .as_str()
        .ok_or_else(|| anyhow!("getblock {height} was not hex"))?;
    let bytes = hex::decode(hex).with_context(|| format!("decode block {height}"))?;
    let block = Block::read(Cursor::new(bytes), &network)
        .with_context(|| format!("parse block {height}"))?;
    Ok(block)
}

async fn scan_block(zebra: &Zebrad, height: u32) -> Result<Vec<VerifiedNameNote>> {
    let block = read_block(zebra, height).await?;

    let fvk = registry_fvk()?;
    let registry_addr = fvk.address_at(0u32, orchard::keys::Scope::External);

    let mut found = Vec::new();
    for tx in block.vtx() {
        let Some(bundle) = tx.ironwood_bundle() else {
            continue;
        };
        if bundle.bundle_version() != orchard::bundle::BundleVersion::ironwood_v3() {
            continue;
        }
        if !bundle.flags().outputs_enabled() {
            continue;
        }
        for action in bundle.actions() {
            let Some((note, recipient, memo_bytes, cmx)) =
                zns_verify::decrypt::try_decrypt_ironwood(action, &fvk)
            else {
                continue;
            };
            if recipient != registry_addr {
                continue;
            }
            let memo = zns_verify::Memo::from_array(*memo_bytes.as_array());
            let payload = match NameNote::parse(&memo) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let (g_d, pk_d) = recipient.zns_commitment_keys();
            let value = note.value().inner();
            let rho = zns_verify::Rho::from_bytes(&action.rho().to_bytes())
                .ok_or_else(|| anyhow!("non-canonical rho at height {height}"))?;
            if !zns_verify::verify_bound_name_note(&payload, g_d, pk_d, value, rho, cmx) {
                bail!(
                    "Registry-decryptable memo at height {height} tx {} failed zns-verify",
                    tx.txid()
                );
            }
            let prev = payload.prev_rcm().map_or_else(
                || "0".repeat(64),
                |prev| String::from_utf8_lossy(&prev.to_hex()).into_owned(),
            );
            found.push(VerifiedNameNote {
                height,
                txid: tx.txid().to_string(),
                name: payload.name().as_str().to_string(),
                action: String::from_utf8_lossy(payload.action().as_bytes()).into_owned(),
                ua: payload.ua().as_str().to_string(),
                expires_at: payload.expires_at().map(|e| e.field_bytes().to_string()),
                prev,
                own_cmx: hex::encode(cmx.to_bytes()),
                value,
                g_d,
                pk_d,
            });
        }
    }
    Ok(found)
}

/// `txid=` on the mint line that reports the Name Note was submitted.
pub fn registration_txid(log: &str, name: &str) -> Option<String> {
    for line in log.lines() {
        let line = strip_ansi(line);
        let submitted = line.contains("NameNote order sent")
            || line.contains("NameNote order in flight")
            || line.contains("registration in flight");
        if !(submitted && line.contains(name)) {
            continue;
        }
        return extract_txid(&line);
    }
    None
}

/// The mint's controller-challenge line for `name`/`action`, if relayed.
pub fn challenge_txid(log: &str, name: &str, action: &str) -> Option<String> {
    for line in log.lines() {
        let line = strip_ansi(line);
        if !(line.contains("controller challenged") && line.contains(name) && line.contains(action))
        {
            continue;
        }
        return extract_txid(&line);
    }
    None
}

/// The hex `txid=` value on a line, if present and well-formed.
fn extract_txid(line: &str) -> Option<String> {
    let rest = line.split("txid=").nth(1)?;
    let txid = rest
        .split(|c: char| c.is_whitespace() || c == ',')
        .next()?
        .trim_matches('"');
    (txid.len() == 64 && txid.bytes().all(|b| b.is_ascii_hexdigit())).then(|| txid.to_string())
}

/// Strip ANSI CSI sequences — mint logs carry color escapes when the
/// environment forces them (e.g. `COLORTERM`), which otherwise splits the
/// `txid=` field separator.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitepaper_vector_is_mainnet_all_zero_registry() {
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &DEV_SEED,
            zip32::AccountId::try_from(1).expect("account 1"),
        )
        .expect("derive");
        let fvk = orchard::keys::FullViewingKey::from(usk.orchard());
        let (g_d, pk_d) = commitment_keys_for_fvk(&fvk);
        assert_eq!(hex::encode(g_d), VECTOR_G_D);
        assert_eq!(hex::encode(pk_d), VECTOR_PK_D);
    }

    #[test]
    fn no_tee_registry_keys_are_stable() {
        let (g_d, pk_d) = registry_commitment_keys().expect("derive");
        // LocalNetwork coin_type is 1, not mainnet 133, so these are not the
        // whitepaper vector. Pin the non-tee identity ceremony and mint share.
        assert_eq!(
            hex::encode(g_d),
            "ce684b50f15484a2a7f4a6625bffc14f7181940b378b467b0dcf583948386da4"
        );
        assert_eq!(
            hex::encode(pk_d),
            "4299a489d4bbe399956ed2c8dcf9c7f386634acd2d1b5027c325354a503f2a91"
        );
    }

    #[test]
    fn registration_txid_from_tracing_line() {
        let log = "2026-09-21T16:10:50Z  INFO zns_mint: NameNote order sent — the wallet holds it until the chain answers txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa name=alice action=\"claim\"";
        assert_eq!(
            registration_txid(log, "alice").as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        let legacy = "2026-09-17T11:28:01Z  INFO zns_mint: NameNote order in flight name=alice action=claim txid=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(
            registration_txid(legacy, "alice").as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    #[test]
    fn challenge_txid_from_tracing_line() {
        let log = "2026-09-30T10:00:00Z  INFO zns_mint::mint: controller challenged lane=mempool txid=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc name=alice action=update";
        assert_eq!(
            challenge_txid(log, "alice", "update").as_deref(),
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );
        assert_eq!(challenge_txid(log, "alice", "release"), None);
    }

    #[test]
    fn registration_txid_parses_through_ansi_color() {
        // Mint logs carry color escapes when the env forces them
        // (observed with `COLORTERM=truecolor`); the parser must not care.
        let log = "\u{1b}[2m2026-10-01T07:02:03Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mzns_mint\u{1b}[0m: NameNote order sent \u{1b}[2mtxid\u{1b}[0m\u{1b}[2m=\u{1b}[0mdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \u{1b}[2mname\u{1b}[0m\u{1b}[2m=\u{1b}[0malice action=\"claim\"";
        assert_eq!(
            registration_txid(log, "alice").as_deref(),
            Some("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
        );
    }
}
