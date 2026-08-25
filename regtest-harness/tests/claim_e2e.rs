//! End-to-end claim test tying the whitepaper Section 3.5 test vector to a
//! live regtest chain.
//!
//! Boots the full stack (zebrad NU6.3, zallet user wallet, zns-mint on the
//! dev all-zero seed), shields funds to Orchard, submits a real claim
//! request (`ZNS:claim:alice:<zallet UA>` + payment) to the Treasury, mines
//! until the Mint settles it, then scans the chain with the Mint's own
//! verifier (`zns-scan`, built from zns-mint's decrypt_name_notes path) and
//! asserts the on-chain Name Note against the test vector's key material:
//!
//!   g_d  de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e
//!   pk_d 6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996
//!
//! ZIP-32 Orchard key derivation is parameter-independent, so the dev
//! Registry account (m/32'/133'/1', j=0, external) has the SAME (g_d, pk_d)
//! on regtest as the mainnet vector. The ua field string differs (regtest
//! HRP), so psi/rcm differ from the vector — the construction (memo -> σ ->
//! (psi, rcm) -> cmx == on-chain cmx) is what this test verifies live.

use std::path::PathBuf;

use anyhow::{bail, Result};
use serde_json::Value;

use zns_mint_regtest_harness::{Zebrad, Zallet, ZnsMint, resolve_bin};

fn zebrad_bin() -> PathBuf {
    resolve_bin("ZEBRAD_BIN").unwrap_or_else(|| PathBuf::from("zebrad"))
}

/// The whitepaper Section 3.5 vector's Registry key material (mainnet
/// encoding of the all-zero-seed Registry account; identical bytes on
/// regtest because ZIP-32 Orchard derivation ignores network parameters).
const VECTOR_G_D: &str = "de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e";
const VECTOR_PK_D: &str = "6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996";

#[tokio::test]
async fn test_claim_e2e_matches_vector_keys() -> Result<()> {
    println!("1. Starting zebrad...");
    let mut zebrad = Zebrad::start(&zebrad_bin()).await?;

    println!("2. Initializing zallet (user wallet)...");
    let mut zallet = Zallet::init(&zebrad).await?;

    println!("3. Restarting zebrad to mine to user's address...");
    zebrad.restart_with_miner(&zallet.miner_address).await?;

    println!("4. Starting zallet daemon...");
    zallet.start_daemon().await?;

    println!("5. Mining through NU6.3 activation...");
    zebrad.generate_blocks(4).await?;

    println!("6. Starting zns-mint...");
    let _mint = ZnsMint::start().await?;

    println!("7. Mining blocks to mature coinbase...");
    zebrad.generate_blocks(110).await?;

    println!("8. Waiting for zallet to sync...");
    zallet
        .wait_until_synced(114, std::time::Duration::from_secs(300))
        .await?;

    println!("9. Shielding coinbase to Orchard...");
    let ua_val: Value = zallet
        .call("z_getaddressforaccount", serde_json::json!([0, ["orchard"]]))
        .await?;
    let u_addr = ua_val
        .get("address")
        .and_then(|a| a.as_str())
        .expect("z_getaddressforaccount returns an address")
        .to_string();
    println!("user orchard UA: {u_addr}");

    let op = zallet
        .call(
            "z_shieldcoinbase",
            serde_json::json!([zallet.miner_address, u_addr]),
        )
        .await?;
    let opid = op
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| {
            op.get("opid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .expect("z_shieldcoinbase returns an operation id");
    loop {
        let status = zallet
            .call("z_getoperationstatus", serde_json::json!([[&opid]]))
            .await?;
        let entry = &status[0];
        match entry.get("status").and_then(|s| s.as_str()).unwrap_or("") {
            "success" => break,
            "failed" => bail!("z_shieldcoinbase failed: {entry}"),
            _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
        }
    }
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    zebrad.generate_blocks(1).await?;
    zallet
        .wait_until_synced(115, std::time::Duration::from_secs(300))
        .await?;
    let balances = zallet
        .call("z_getbalanceforaccount", serde_json::json!([0]))
        .await?;
    println!("balances after shield: {balances}");

    // ------------------------------------------------------------------
    // 10. The claim request: derive the dev Treasury UA (all-zero seed,
    //     account m/32'/133'/0', j=0, external, regtest) and send
    //     2.0 ZEC with memo ZNS:claim:alice:<user UA>.
    // ------------------------------------------------------------------
    println!("10. Deriving Treasury UA and submitting claim request...");
    let one = zcash_protocol::consensus::BlockHeight::from_u32(1);
    let four = zcash_protocol::consensus::BlockHeight::from_u32(4);
    let network = zcash_protocol::local_consensus::LocalNetwork {
        overwinter: Some(one),
        sapling: Some(one),
        blossom: Some(one),
        heartwood: Some(one),
        canopy: Some(one),
        nu5: Some(one),
        nu6: Some(one),
        nu6_1: Some(four),
        nu6_2: Some(four),
        nu6_3: Some(four),
    };
    let seed = [0u8; 32];
    let treasury_usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &network,
        &seed,
        zip32::AccountId::const_from_u32(0),
    )
    .expect("dev seed derives a treasury USK");
    let treasury_fvk =
        orchard::keys::FullViewingKey::from(treasury_usk.orchard());
    let treasury_ua = zcash_keys::address::UnifiedAddress::from_receivers(
        Some(treasury_fvk.address_at(0u32, orchard::keys::Scope::External)),
        None,
        None,
    )
    .expect("treasury UA")
    .encode(&network);
    println!("treasury UA: {treasury_ua}");

    let claim_memo = format!("ZNS:claim:alice:{u_addr}");
    let memo_hex: String = claim_memo.bytes().map(|b| format!("{b:02x}")).collect();
    // Spend by account (z_sendmany from a UA sees 0 spendable in this zallet
    // build); fund_source "orchard" includes the Ironwood pool post-NU6.3.
    let accounts = zallet.call("z_listaccounts", serde_json::json!([])).await?;
    let uuid = accounts[0]
        .get("account_uuid")
        .and_then(|v| v.as_str())
        .expect("z_listaccounts returns the account uuid")
        .to_string();
    println!("zallet account uuid: {uuid}");
    let send = zallet
        .call(
            "z_sendfromaccount",
            serde_json::json!([
                uuid,
                "orchard",
                [{ "address": treasury_ua, "amount": 2.0, "memo": memo_hex }],
                1,
                "FullPrivacy"
            ]),
        )
        .await?;
    println!("claim request send result: {send}");
    let claim_txid = send.as_str().map(|s| s.to_string());

    // ------------------------------------------------------------------
    // 11. Mine until the Mint settles: intake needs 10 confirmations, the
    //     first assembly attempt fails until fee replenishment stocks the
    //     Registry pool, then the retry lands. Mine in small batches.
    // ------------------------------------------------------------------
    println!("11. Mining for settlement (single burst to keep the gRPC tip stream active)...");
    zebrad.generate_blocks(1).await?; // confirm the claim tx
    let scan_from = 116u32;
    // Build the scanner first (cached cargo build in the workspace root).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent().unwrap();
    let status = std::process::Command::new("cargo")
        .current_dir(workspace_root)
        .args(["build", "--bin", "zns-scan", "--features", "regtest"])
        .status()?;
    assert!(status.success(), "failed to build zns-scan");
    let scan_bin = workspace_root.join("target/debug/zns-scan");

    // Mine in stages: the mint's tip stream delivers burst events, so each
    // generate call triggers a catch-up+settle cycle. The claim needs:
    //   10 conf for intake → fee replenish tx → confirm → claim tx → confirm.
    // Stage 1: mine 12 blocks (brings tip to ~128, 10+ conf for the claim note).
    zebrad.generate_blocks(12).await?;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    // Stage 2: mine 5 more (confirms the replenish tx if it landed).
    zebrad.generate_blocks(5).await?;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    // Stage 3: mine 5 more (confirms the claim tx if it landed).
    zebrad.generate_blocks(5).await?;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    // Stage 4: one more batch in case retries were needed.
    zebrad.generate_blocks(5).await?;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let tip = 143u32;
    let mut alice = None;
    // Retry scan a few times in case the mint is still processing.
    for attempt in 0..5 {
        let out = std::process::Command::new(&scan_bin)
            .args(["--from", &scan_from.to_string(), "--to", &tip.to_string()])
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if v.get("name").and_then(|n| n.as_str()) == Some("alice") {
                    alice = Some(v);
                }
            }
        }
        if alice.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    // ------------------------------------------------------------------
    // 12. Assert the on-chain Name Note against the vector.
    // ------------------------------------------------------------------
    let Some(note) = alice else {
        bail!("no verified Name Note for alice found by height {tip}");
    };
    println!("on-chain Name Note: {note}");

    assert_eq!(
        note["action_kind"].as_str(),
        Some("claim"),
        "action must be claim"
    );
    assert_eq!(note["ua"].as_str(), Some(u_addr.as_str()), "bound UA");
    assert_eq!(note["expires"].as_str(), Some("none"), "expiry");
    assert_eq!(
        note["prev_rcm"].as_str(),
        Some("0000000000000000000000000000000000000000000000000000000000000000"),
        "first claim uses the zero predecessor"
    );
    assert_eq!(note["value"].as_u64(), Some(0), "Name Notes are value-0");
    assert_eq!(
        note["g_d"].as_str(),
        Some(VECTOR_G_D),
        "on-chain g_d must equal the Section 3.5 vector g_d"
    );
    assert_eq!(
        note["pk_d"].as_str(),
        Some(VECTOR_PK_D),
        "on-chain pk_d must equal the Section 3.5 vector pk_d"
    );
    let memo = note["memo_ascii"].as_str().unwrap_or_default();
    assert!(
        memo.starts_with("ZNS:claim:alice:"),
        "memo encodes the claim: {memo}"
    );
    // The scanner only prints notes whose ZNS-derived (psi, rcm) reproduce
    // the on-chain cmx (decrypt_name_notes enforces the equality), so
    // reaching here IS commitment verification. Record the values:
    println!("psi (regtest sigma): {}", note["psi"].as_str().unwrap_or(""));
    println!("rcm (regtest sigma): {}", note["rcm"].as_str().unwrap_or(""));
    println!("on-chain cmx:        {}", note["cmx"].as_str().unwrap_or(""));
    let _ = claim_txid;

    println!("E2E claim verified against the vector's key material.");
    Ok(())
}
