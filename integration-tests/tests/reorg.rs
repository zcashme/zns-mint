//! Live reorg of the mint queues. Needs `zebrad` and `zallet-zebra`.
//! Skips when either binary is missing.
//!
//! Run it with:
//!
//! ```sh
//! cargo test --test reorg -- --nocapture
//! ```
//!
//! The Daily workflow runs that same command at 06:00 UTC.

use std::time::Duration;

use anyhow::{bail, Result};
use zns_integration_tests::fixture::{self, Stack};
use zns_integration_tests::{zallet_bin, zebrad_bin, Mint, Zebrad};

const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

/// The user's shielded funds: five 2 ZEC payments and two 0.1 ZEC refund
/// probes, about 10.2 ZEC, with headroom.
const USER_ZATS: u64 = 2_000_000_000;

#[tokio::test(flavor = "multi_thread")]
async fn reorg_queues() -> Result<()> {
    if zebrad_bin().is_none() || zallet_bin().is_none() {
        if std::env::var_os("CI").is_some() {
            bail!("zebrad and zallet required in CI — set ZEBRAD_BIN and ZALLET_BIN");
        }
        eprintln!("skipping: zebrad/zallet not found (set ZEBRAD_BIN/ZALLET_BIN)");
        return Ok(());
    }

    let mint_build = tokio::task::spawn_blocking(Mint::build);
    let mut zebra = Zebrad::start().await?;

    // The same funding as the happy path: only the funder mines, on an
    // empty chain, and the user and the Treasury are paid by transfer, so
    // no funded chain is restarted.
    let funder = fixture::User::fund(&mut zebra, 7).await?;
    fixture::wait_until_shielded(
        &funder.zallet,
        USER_ZATS + fixture::TREASURY_PAYMENT_ZATS * 2,
        SYNC_TIMEOUT,
    )
    .await?;
    let user = fixture::User::fund_attached(&mut zebra, &funder, USER_ZATS).await?;
    let tip = zebra.tip_height().await?;
    funder.zallet.wait_until_synced(tip, SYNC_TIMEOUT).await?;
    fixture::wait_until_shielded(&funder.zallet, fixture::TREASURY_PAYMENT_ZATS, SYNC_TIMEOUT)
        .await?;
    let (taddr, _) = fixture::treasury_taddr(&fixture::regtest_network(), &fixture::DEV_SEED)?;
    fixture::fund_treasury(&funder.zallet, &zebra, &taddr).await?;
    drop(funder);

    let (birthday, anchor_txid) = fixture::publish_ceremony(&zebra).await?;
    let mint_bin = mint_build.await.expect("mint build task")?;
    let mint = Stack::launch_mint(&mut zebra, mint_bin, birthday, &anchor_txid).await?;
    let mut stack = Stack { zebra, mint, user };

    zns_integration_tests::reorg_queues(&mut stack).await
}
