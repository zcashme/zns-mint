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

    println!("2. Initializing zallet (user wallet)...");
    let mut zallet = Zallet::init(&zebrad).await?;
    println!("zallet miner address: {}", zallet.miner_address);

    // Restart zebrad to mine to the user's address.
    println!("3. Restarting zebrad to mine to user's address...");
    zebrad.restart_with_miner(&zallet.miner_address).await?;

    println!("4. Starting zallet daemon...");
    zallet.start_daemon().await?;

    println!("5. Mining through NU6.3 activation...");
    zebrad.generate_blocks(4).await?;

    println!("6. Starting zns-mint...");
    let mint = ZnsMint::start().await?;
    println!("zns-mint booted successfully!");

    println!("7. Mining blocks to mature coinbase...");
    // Mine 110 blocks. Coinbase maturity is 100 blocks, so this gives zallet 10 spendable coinbases.
    // This also triggers NU6.3 activation (at block 4).
    zebrad.generate_blocks(110).await?;

    println!("8. Waiting for zallet to sync the blocks...");
    zallet.wait_until_synced(114, std::time::Duration::from_secs(300)).await?;
    
    let balances = zallet.call("z_getbalanceforaccount", serde_json::json!([0])).await?;
    println!("zallet balances after mining: {}", balances);

    println!("9. Shielding coinbase to Orchard...");
    // zallet 0.1.0-beta has no getnewaddress/z_shieldcoinbase; use
    // z_getaddressforaccount + z_sendmany (zcashd wallet-style RPC).
    let ua_val: serde_json::Value = zallet
        .call("z_getaddressforaccount", serde_json::json!([0, ["orchard"]]))
        .await?;
    let u_addr = ua_val
        .get("address")
        .and_then(|a| a.as_str())
        .expect("z_getaddressforaccount returns an address")
        .to_string();
    println!("account 0 orchard UA: {u_addr}");

    // Coinbase UTXOs: shield them with z_shieldcoinbase (zallet handles the
    // coinbase consumption rules); poll the async operation to completion.
    let op = zallet
        .call(
            "z_shieldcoinbase",
            serde_json::json!([zallet.miner_address, u_addr]),
        )
        .await?;
    println!("shield result raw: {op}");
    let opid = op
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| op.get("operationid").or_else(|| op.get("opid")).and_then(|v| v.as_str()).map(|s| s.to_string()))
        .expect("z_shieldcoinbase returns an operation id");
    println!("Shield operation ID: {opid}");
    loop {
        let status = zallet
            .call("z_getoperationstatus", serde_json::json!([[&opid]]))
            .await?;
        let entry = &status[0];
        let state = entry.get("status").and_then(|s| s.as_str()).unwrap_or("");
        if state == "success" || state == "failed" {
            println!("shield op: {entry}");
            if state == "failed" {
                anyhow::bail!("z_shieldcoinbase failed: {entry}");
            }
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Wait for shielding transaction to enter mempool, then mine a block to confirm it.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    zebrad.generate_blocks(1).await?;
    zallet.wait_until_synced(115, std::time::Duration::from_secs(300)).await?;
    
    let balances_after = zallet.call("z_getbalanceforaccount", serde_json::json!([0])).await?;
    println!("zallet balances after shielding: {}", balances_after);

    println!("Test completed successfully!");
    
    // Drop logic automatically cleans up the daemons.
    Ok(())
}
