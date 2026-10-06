//! Regression: K underpaid claims plus one full-price claim in one block.
//! The deciding pass judges every claim in block order — the underpaid
//! claims die at the payment gate and the full-price claim takes the
//! name's slot, whichever position the buyer tx took in the block.

use std::time::Duration;

use anyhow::Result;
use zns_mint_integration_tests::{
    block_txids, expose_fixture_capsule, wait_for_verified_name_note, Stack, User,
};

const NAME: &str = "slotreg";
const DUST_ZATS: u64 = 1_000;
/// One shielded note per dust send: zallet minconf=1 refuses re-spending
/// unconfirmed change.
const NOTE_ZATS: u64 = 100_000;
const K: usize = 19;
const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

#[tokio::test(flavor = "multi_thread")]
async fn underpaid_claims_do_not_block_a_full_price_claim_same_batch() -> Result<()> {
    let _capsule_dir = expose_fixture_capsule()?;
    let Some(mut stack) = Stack::start(7).await? else {
        eprintln!("skipping: zebrad/zallet not present");
        return Ok(());
    };
    let buyer = &stack.user;
    let buyer_ua = buyer.ua.clone();

    // The attacker: a second wallet funded by shielded transfer — no
    // zebrad restart while the mint is live.
    let attacker = User::fund_attached(&mut stack.zebra, buyer, 100_000_000).await?;
    eprintln!("attacker wallet up: {}", attacker.ua);

    // One confirmed attacker note per dust send.
    for _ in 0..K {
        buyer.pay_ua(&attacker.ua, NOTE_ZATS).await?;
        stack.zebra.generate_blocks(1).await?;
        let target = stack.zebra.tip_height().await?;
        buyer.zallet.wait_until_synced(target, SYNC_TIMEOUT).await?;
        attacker
            .zallet
            .wait_until_synced(target, SYNC_TIMEOUT)
            .await?;
    }
    eprintln!("{K} attacker notes ready");

    // All K+1 claims broadcast before mining; one block confirms them.
    let mut dust_txids = Vec::new();
    for i in 0..K {
        let txid = attacker
            .pay_treasury_zats(
                &format!("ZNS:claim:forever:{NAME}:{}", attacker.ua),
                DUST_ZATS,
            )
            .await?;
        eprintln!("attacker dust #{i} {txid}");
        dust_txids.push(txid);
    }
    let buyer_txid = buyer
        .pay_treasury(&format!("ZNS:claim:forever:{NAME}:{buyer_ua}"))
        .await?;
    eprintln!("buyer full claim {buyer_txid}");

    stack.zebra.generate_blocks(1).await?;
    let mined = stack.zebra.tip_height().await?;

    // Exercise the regression: the block carries every claim, and a
    // dust claim is decoded before the buyer claim.
    let block = block_txids(&stack.zebra, mined).await?;
    for txid in &dust_txids {
        assert!(
            block.contains(txid),
            "dust claim {txid} missed block {mined}"
        );
    }
    let buyer_pos = block
        .iter()
        .position(|t| t.as_str() == buyer_txid.as_str())
        .unwrap_or_else(|| panic!("buyer claim {buyer_txid} missed block {mined}"));
    assert!(
        block[..buyer_pos].iter().any(|t| dust_txids.contains(t)),
        "no dust claim decoded before the buyer claim; re-run: this pass does not exercise the regression"
    );

    // The full-price claim is queued and wins: the Name Note is mined
    // with the buyer's UA regardless of block position.
    let note = wait_for_verified_name_note(&stack.zebra, &mut stack.mint, NAME, mined).await?;
    assert_eq!(note.action, "claim");
    assert_eq!(
        note.ua, buyer_ua,
        "the full-price claim must win the name's slot"
    );
    eprintln!("verified claim note for {NAME} at height {}", note.height);

    if !stack.mint.is_running() {
        eprintln!("mint exited after the note:\n{}", stack.mint.exit_detail());
    }
    Ok(())
}
