use zns_mint::{
    auth::OtpStore,
    boot, metrics,
    registry::Registry,
    zcash::Submitter,
    treasury::Treasury,
};
use zcash_protocol::consensus::BlockHeight;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .init();

    tracing::info!("zns-mint starting");

    // 1. Serve metrics in the background immediately
    tokio::spawn(metrics::serve());

    // 2. Boot sequence: established TEE trust, get birthday block, derive keys
    let env = zns_mint::env::MintBootEnv;
    let (mut chain, mut wallet, _treasury_keys, _registry_keys, birthday_height) = boot::boot(&env).await;

    // 3. Initialize passive state structures
    let mut registry = Registry::new();
    let mut _auth = OtpStore::new();
    let mut _submitter = Submitter::new();

    metrics::set_boot_success(true);
    
    // 4. Set the initial Watermarks
    // local_height is the low watermark (what we have processed)
    // target_height is the high watermark (the known Zebra tip)
    let mut local_height = birthday_height;
    let mut target_height = birthday_height;

    // Open the tip stream to keep our high watermark updated
    use zebra_indexer_proto::Empty;
    let mut tip_stream = chain
        .client()
        .chain_tip_change(Empty {})
        .await
        .expect("failed to open tip stream")
        .into_inner();

    tracing::info!(
        "zns-mint: boot complete, entering orchestrator loop at height {}",
        u32::from(local_height)
    );

    loop {
        // We are "synced" if our low watermark has reached the high watermark
        let is_synced = u32::from(local_height) >= u32::from(target_height);

        tokio::select! {
            // Priority 1: Graceful Shutdown
            // The mint is never deaf to the OS.
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("zns-mint: received ctrl-c, shutting down gracefully");
                break;
            }
            
            // Priority 2: Chain tip updates
            // Updates the high watermark whenever Zebra announces a new block
            maybe_tip = tip_stream.message() => {
                match maybe_tip {
                    Ok(Some(zebra_tip)) => {
                        // (Stubbed method: extract the height from the grpc message)
                        let (new_tip_height, _) = zns_mint::sync::scan::tip_height_hash(&zebra_tip);
                        
                        if u32::from(new_tip_height) > u32::from(target_height) {
                            target_height = new_tip_height;
                            tracing::debug!("sync: target_height advanced to {}", u32::from(target_height));
                        }
                    }
                    Ok(None) | Err(_) => {
                        tracing::error!("chain tip stream closed or errored, shutting down");
                        break;
                    }
                }
            }

            // Priority 3: Block Fetching & Policy Evaluation
            // Only executes if our low watermark is behind the high watermark
            _ = async { tokio::time::sleep(std::time::Duration::from_millis(5)).await }, if !is_synced => {
                let next_height = BlockHeight::from_u32(u32::from(local_height) + 1);
                
                // A. Fetch block (stubbed network call)
                let _block = zns_mint::sync::scan::fetch_verified_block(&mut chain, next_height).await;
                
                // B. Scan and apply
                // In a fully-wired implementation, we would call `sync::scan_block` 
                // and pass the `BlockOutput` to `wallet` and `registry` here.
                
                local_height = next_height;

                if u32::from(local_height) % 1_000 == 0 {
                    tracing::info!("sync: processed block {} / {}", u32::from(local_height), u32::from(target_height));
                }

                // C. Evaluate Policies (Treasury, Auth, Registry)
                let treasury = Treasury::from_wallet(&wallet);
                
                for _req in treasury.requests_in_block(local_height) {
                    // Match claim payments, issue OTPs via auth.issue(), etc.
                }

                // D. Live Action Phase (Only broadcast if fully caught up)
                if u32::from(local_height) == u32::from(target_height) {
                    tracing::info!("Mint is synced to the tip ({}). Processing live actions.", u32::from(local_height));
                    
                    // Auto-sweep policy
                    if let Some(sweep_req) = treasury.auto_sweep(local_height, None) {
                        use zns_mint::treasury::sweep::SweepRequest;
                        match sweep_req {
                            SweepRequest::Sapling { amount, .. } => {
                                tracing::info!("Sapling auto-sweep triggered for {} zatoshis", amount.into_u64());
                                // TODO: build_sapling_sweep(&mut wallet, sweep_req)
                                // submitter.submit(...)
                            }
                            SweepRequest::Orchard { amount, .. } => {
                                tracing::info!("Orchard auto-sweep triggered for {} zatoshis", amount.into_u64());
                                // TODO: build_orchard_sweep(&mut wallet, sweep_req)
                                // submitter.submit(...)
                            }
                        }
                    }
                    
                    // Registry funding policy
                    if let Some(funding_req) = treasury.registry_funding() {
                        tracing::info!("registry funding triggered for {} zatoshis", funding_req.amount);
                        // build_funding_transaction(&mut wallet, funding_req)
                        // submitter.submit(...)
                    }
                    
                    // TODO: Gather NameNoteRequests from Registry & Auth, build transactions, and submit
                }
            }
        }
    }
}