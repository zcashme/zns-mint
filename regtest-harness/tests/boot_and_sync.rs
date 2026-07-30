use std::path::PathBuf;
use anyhow::Result;

use zns_mint_regtest_harness::{Zebrad, Zallet, ZnsMint, resolve_bin};

fn zebrad_bin() -> PathBuf {
    resolve_bin("ZEBRAD_BIN").unwrap_or_else(|| PathBuf::from("zebrad"))
}

#[tokio::test]
async fn test_boot_and_sync() -> Result<()> {
    println!("1. Starting zebrad...");
    let mut zebrad = Zebrad::start(&zebrad_bin()).await?;
    println!("zebrad JSON-RPC listening on port {}", zebrad.rpc_port);

    println!("2. Starting zallet (user wallet)...");
    let zallet = Zallet::start(zebrad.rpc_port).await?;
    println!("zallet miner address: {}", zallet.miner_address);

    // Restart zebrad to mine to the user's address.
    println!("3. Restarting zebrad to mine to user's address...");
    zebrad.restart_with_miner(&zallet.miner_address).await?;

    println!("4. Starting zns-mint...");
    let mut mint = ZnsMint::start().await?;
    println!("zns-mint booted successfully!");

    println!("5. Mining blocks to mature coinbase...");
    // Mine 110 blocks. Coinbase maturity is 100 blocks, so this gives zallet 10 spendable coinbases.
    // This also triggers NU6.3 activation (at block 4).
    zebrad.generate_blocks(110).await?;

    println!("6. Waiting for zallet to sync the blocks...");
    zallet.wait_until_synced(110, std::time::Duration::from_secs(60)).await?;
    
    let balances = zallet.call("z_getbalanceforaccount", serde_json::json!([0])).await?;
    println!("zallet balances after mining: {}", balances);

    println!("7. Shielding coinbase to Orchard...");
    let u_addr_val: serde_json::Value = zallet.call("getnewaddress", serde_json::json!([""])).await?;
    let u_addr = u_addr_val.as_str().unwrap();
    
    let shield_op = zallet.call("z_shieldcoinbase", serde_json::json!([zallet.miner_address, u_addr])).await?;
    println!("Shield operation ID: {}", shield_op);
    
    // Wait for shielding transaction to enter mempool, then mine a block to confirm it.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    zebrad.generate_blocks(1).await?;
    zallet.wait_until_synced(111, std::time::Duration::from_secs(60)).await?;
    
    let balances_after = zallet.call("z_getbalanceforaccount", serde_json::json!([0])).await?;
    println!("zallet balances after shielding: {}", balances_after);

    println!("Test completed successfully!");
    
    // Drop logic automatically cleans up the daemons.
    Ok(())
}