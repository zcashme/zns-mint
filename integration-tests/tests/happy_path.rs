//! The mint's happy path, black-box: claim, update, release.
//!
//! Every payment goes through a real wallet; every note is checked with
//! `zns-verify`, never mint's decoder; every expected mint log line lives
//! in this repo. Closes #267.

use anyhow::Result;
use zns_mint_integration_tests::{claim, release, seal_fixture_capsule, update, Stack};

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_claim_update_release() -> Result<()> {
    let capsule_dir = tempfile::tempdir()?;
    let capsule_path = capsule_dir.path().join("zns_seed.capsule");
    std::fs::write(&capsule_path, seal_fixture_capsule()?)?;
    std::env::set_var("ZNS_SEED_CAPSULE", &capsule_path);

    // Seven mature coinbases fund five 2.0-ZEC payments (request + echo
    // for each verb after the claim) plus fees.
    let Some(mut stack) = Stack::start(7).await? else {
        return Ok(());
    };

    let claim_note = claim(&mut stack).await?;
    let update_note = update(&mut stack, &claim_note).await?;
    release(&mut stack, &update_note).await?;
    Ok(())
}
