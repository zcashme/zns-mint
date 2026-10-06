//! Boot-completion proof: the mint, linked in-process with `regtest`,
//! completes `Boot::start()` against a real regtest Zebra holding only
//! fixture chain facts — built through the real ownership flow. A real
//! Zallet wallet mines and shields coinbase and pays the Treasury; the
//! Treasury's own keys author the 40-anchor Registry ceremony; the wallet
//! is reaped; then boot must return within a bounded deadline. Regtest
//! selects non-tee, so the identity document is dev mode and has no report.
//!
//! Success is boot evidence, not elapsed sleep: a missing capsule, a
//! boot failure, or a dev document that still carries a report cannot pass.

use std::time::Duration;

use anyhow::{Context, Result};
use zns_integration_tests::Zebrad;
use zns_mint::boot::Boot;
use zns_mint_integration_tests as fixture;
use zns_mint_integration_tests::Zallet;

const SYNC_TIMEOUT: Duration = Duration::from_secs(300);
const BOOT_TIMEOUT: Duration = Duration::from_secs(1800);

#[tokio::test(flavor = "multi_thread")]
async fn boot_completes_on_wallet_funded_dev_ceremony() -> Result<()> {
    // One test per binary: the process CWD is the fixture boundary that
    // boot reads its capsule from and writes its attestation to.
    let fixture_dir = tempfile::tempdir()?;
    std::env::set_current_dir(fixture_dir.path())?;

    let mut zebra = Zebrad::start().await?;
    let mut zallet = Zallet::init(&zebra)?;
    eprintln!("fixture: zallet miner {}", zallet.miner_address);

    // Coinbase matures against the wallet's miner address.
    zebra.restart_with_miner(&zallet.miner_address).await?;
    zebra
        .generate_blocks(fixture::NU6_3_ACTIVATION_HEIGHT + fixture::COINBASE_MATURITY + 2)
        .await?;

    zallet.start_daemon().await?;
    let tip = zebra.tip_height().await?;
    zallet.wait_until_synced(tip, SYNC_TIMEOUT).await?;

    // The shield captures every mature UTXO only after the wallet's scan
    // reaches the node's mature-coinbase truth; status sync is not enough.
    let truth = fixture::mature_coinbase_zats(&zebra, &zallet.miner_address).await?;
    fixture::wait_until_sees_coinbase(&zallet, truth, SYNC_TIMEOUT).await?;
    zallet.shield_coinbase().await?;
    zebra.generate_blocks(1).await?;
    let tip = zebra.tip_height().await?;
    zallet.wait_until_synced(tip, SYNC_TIMEOUT).await?;
    fixture::wait_until_shielded(&zallet, fixture::TREASURY_PAYMENT_ZATS, SYNC_TIMEOUT).await?;

    // The funding wallet pays the Treasury; the Treasury's own keys then
    // author the ceremony — the real ownership flow.
    let network = fixture::regtest_network();
    let (taddr, _) = fixture::treasury_taddr(&network, &fixture::DEV_SEED)?;
    fixture::fund_treasury(&zallet, &zebra, &taddr).await?;

    // The wallet holds no mint authority: reap it before boot.
    drop(zallet);

    let tip = fixture::publish_ceremony(&zebra).await?;
    eprintln!("fixture: ceremony confirmed at tip {tip}");

    std::fs::create_dir_all("keys")?;
    std::fs::write("keys/zns_seed.capsule", fixture::seal_fixture_capsule()?)?;

    // Bounded, explicit completion. Every boot check — genesis anchors,
    // Treasury minimum, clock, initial price, proving parameters — runs
    // inside Boot::start(); returning is the proof.
    let boot = tokio::time::timeout(BOOT_TIMEOUT, Boot::start())
        .await
        .context("boot exceeded the harness deadline")?;

    let tip_height = zcash_protocol::consensus::BlockHeight::from_u32(tip);
    assert_eq!(
        boot.birthday,
        zcash_protocol::consensus::BlockHeight::from_u32(100)
    );
    assert_eq!(boot.cursor.block_height(), tip_height);
    assert_eq!(boot.registry.anchor_pool().len(), fixture::ANCHOR_POOL_SIZE);
    assert!(boot.registry.anchor_adoption_closed());
    assert!(boot.oracle.current().into_u64() > 0);

    // Boot's identity document in a non-tee build is self-declaring:
    // mode dev, no report. There is nothing to verify — that's the point.
    let doc: serde_json::Value = serde_json::from_str(
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
    Ok(())
}
