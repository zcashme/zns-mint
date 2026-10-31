//! Boot e2e chained into the happy path: real ownership flow (funder
//! pays the Treasury, Treasury keys author the 40-anchor ceremony, funder
//! reaped), in-process `Boot::start()` with its evidence assertions, then
//! the mint binary serving claim, update, release to a live user wallet.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use zcash_protocol::consensus::BlockHeight;
use zns_integration_tests::{zallet_bin, zebrad_bin, Mint, Zebrad};
use zns_mint::boot::Boot;
use zns_mint_integration_tests as fixture;
use zns_mint_integration_tests::{claim, release, update, Stack};

const SYNC_TIMEOUT: Duration = Duration::from_secs(300);
const BOOT_TIMEOUT: Duration = Duration::from_secs(1800);

// Zebra 7.0.0's MAX_BLOCK_REORG_HEIGHT: these blocks can be lost on
// restart before the periodic non-finalized backup catches up. Mine
// past this window so the funder's rewards are finalized on disk.
const ZEBRA_NON_FINALIZED_BLOCKS: u32 = 1000;

#[tokio::test(flavor = "multi_thread")]
async fn boot_then_claim_update_release() -> Result<()> {
    if zebrad_bin().is_none() || zallet_bin().is_none() {
        if std::env::var_os("CI").is_some() {
            bail!("zebrad and zallet required in CI — set ZEBRAD_BIN and ZALLET_BIN");
        }
        eprintln!("skipping: zebrad/zallet not found (set ZEBRAD_BIN/ZALLET_BIN)");
        return Ok(());
    }

    // Build the binary in parallel with the chain leg.
    let mint_build = tokio::task::spawn_blocking(Mint::build);

    let fixture_dir = tempfile::tempdir()?;
    std::env::set_current_dir(fixture_dir.path())?;

    let mut zebra = Zebrad::start().await?;

    // Funder coinbase first: mined before the chain's first shielded tx,
    // or the funder's transparent balance never appears (zallet
    // v0.1.0-beta.3 retrieval stall).
    let mut funder = fixture::Zallet::init(&zebra)?;
    zebra.restart_with_miner(&funder.miner_address).await?;
    zebra
        .generate_blocks(
            ZEBRA_NON_FINALIZED_BLOCKS
                + fixture::NU6_3_ACTIVATION_HEIGHT
                + fixture::COINBASE_MATURITY
                + 2,
        )
        .await?;

    // User second: its shield is the chain's first shielded tx; its
    // restart drops only the funder's unfinalized tail.
    let user = fixture::User::fund(&mut zebra, 7).await?;
    eprintln!("user miner: {}", user.miner_address);
    eprintln!("user UA: {}", user.ua);

    let funder_floor = fixture::TREASURY_PAYMENT_ZATS * 2;
    let mature = fixture::mature_coinbase_zats(&zebra, &funder.miner_address).await?;
    if mature < funder_floor {
        bail!(
            "funder has only {mature} mature coinbase zats after the miner restart; \
             need {funder_floor}: mine beyond Zebra's non-finalized window before restarting"
        );
    }

    funder.start_daemon().await?;
    let tip = zebra.tip_height().await?;
    funder.wait_until_synced(tip, SYNC_TIMEOUT).await?;

    // Wait for a floor, not the node's full mature truth — the funder
    // only needs the 1-ZEC Treasury payment, and CI's zallet credits it
    // only its deep-finalized core.
    fixture::wait_until_sees_coinbase(&funder, funder_floor, SYNC_TIMEOUT).await?;
    funder.shield_coinbase().await?;
    zebra.generate_blocks(1).await?;
    let tip = zebra.tip_height().await?;
    funder.wait_until_synced(tip, SYNC_TIMEOUT).await?;
    fixture::wait_until_shielded(&funder, fixture::TREASURY_PAYMENT_ZATS, SYNC_TIMEOUT).await?;

    let network = fixture::regtest_network();
    let (taddr, _) = fixture::treasury_taddr(&network, &fixture::DEV_SEED)?;
    fixture::fund_treasury(&funder, &zebra, &taddr).await?;

    // The funder holds no mint authority: gone before boot.
    drop(funder);

    let (birthday, anchor_txid) = fixture::publish_ceremony(&zebra).await?;

    zns_canon::regtest::write_dev_keys("keys", birthday, &anchor_txid)?;

    let boot = tokio::time::timeout(BOOT_TIMEOUT, Boot::start())
        .await
        .context("boot exceeded the harness deadline")?;

    let tip_height = BlockHeight::from_u32(birthday);
    assert_eq!(boot.birthday, tip_height);
    assert_eq!(boot.wallet.tip().block_height(), tip_height);
    assert_eq!(boot.registry.anchor_pool().len(), fixture::ANCHOR_POOL_SIZE);
    assert!(boot.registry.anchor_adoption_closed());
    assert!(boot.oracle.current().into_u64() > 0);

    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string("zns_mint_identity.json")
            .context("boot must write the identity document")?,
    )
    .context("identity document is not valid JSON")?;
    let (treasury_ua, registry_ufvk) = fixture::mint_identity_strings();
    assert_eq!(doc["mode"], "dev", "identity doc mode");
    assert_eq!(doc["network"], "regtest", "identity doc network");
    assert_eq!(doc["treasury_ua"], treasury_ua, "identity doc treasury UA");
    assert_eq!(
        doc["registry_ufvk"], registry_ufvk,
        "identity doc registry UFVK"
    );
    assert!(
        doc["report"].is_null(),
        "dev docs must not carry an attestation report"
    );

    // The binary re-derives the same keys/ contract and re-verifies the
    // anchor on its way to the run loop.
    let mint_bin = mint_build.await.expect("mint build task")?;
    let mint = Stack::launch_mint(&mut zebra, mint_bin, birthday, &anchor_txid).await?;
    let mut stack = Stack { zebra, mint, user };

    let claim_note = claim(&mut stack).await?;
    let update_note = update(&mut stack, &claim_note).await?;
    release(&mut stack, &update_note).await?;
    Ok(())
}
