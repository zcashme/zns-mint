//! Launch the mint binary against chain facts boot already verified.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use zns_integration_tests::{Mint, Zebrad};

use crate::user::User;

pub struct Stack {
    pub zebra: Zebrad,
    pub mint: Mint,
    pub user: User,
}

impl Stack {
    /// Launch the mint binary and wait for its first run loop.
    ///
    /// `birthday` and `anchor_txid` are the real ceremony facts
    /// `Boot::start()` verified in-process; the binary writes the same
    /// keys/ contract into its own directory and re-verifies the anchor
    /// against the chain on its way to the run loop.
    pub async fn launch_mint(
        zebra: &mut Zebrad,
        bin: PathBuf,
        birthday: u32,
        anchor_txid: &str,
    ) -> Result<Mint> {
        let mut mint = Mint::start(bin, birthday, anchor_txid).await?;
        mint.wait_until_live().await?;
        wait_for_first_run_loop(zebra, &mut mint).await?;
        Ok(mint)
    }
}

/// Mine one block so the run loop can fire, then wait until it applied the
/// tip's rules — evidence the loop is cycling, not just alive. Sweep is
/// optional: the claim path uses ceremony Treasury notes either way.
async fn wait_for_first_run_loop(zebra: &mut Zebrad, mint: &mut Mint) -> Result<()> {
    zebra.generate_blocks(1).await?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if !mint.is_running() {
            bail!("mint died after becoming live:\n{}", mint.exit_detail());
        }
        let log = mint.log_text();
        if mint_submitted_vault_sweep(&log) {
            break;
        }
        if log.contains("vault sweep") && log.contains("failed") {
            eprintln!("mint vault sweep failed; continuing");
            break;
        }
        if log.contains("mint rules applied") {
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "mint did not apply rules after the post-live tip:\n{}",
                mint.exit_detail()
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    zebra.generate_blocks(1).await?;
    Ok(())
}

fn mint_submitted_vault_sweep(log: &str) -> bool {
    log.lines().any(|line| {
        line.contains("submitted") && line.contains("vault sweep") && !line.contains("failed")
    })
}
