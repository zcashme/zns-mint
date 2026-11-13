//! zns-rebind: moves every live Name Note to a bound claim, once, inside the
//! migrated guest before the new mint first boots.

mod boot;
mod note;
mod registry;

use zcash_protocol::consensus::BlockHeight;
use zns_mint::mint::mtp::MtpTracker;
use zns_mint::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{CanonicalBlockSource, ChainClient};
use zns_mint::{RegistryKeys, TreasuryKeys};

/// One pass over the chain, kept at the tip. Every block applies once to
/// the wallet and the new law; blocks before H also go through the live
/// mint's copied law.
struct Scan {
    wallet: Wallet<boot::Network>,
    mtp: MtpTracker,
    /// The live mint's verdicts: the names to move.
    old: registry::Registry,
    /// The new law up to the old birthday, whose block holds the old
    /// ceremony's anchors. Dropped verdicts.
    throwaway: zns_mint::mint::registry::Registry,
    /// The new law after the old birthday: empty until the new anchor
    /// transaction, then what the new mint will build from H.
    fresh: zns_mint::mint::registry::Registry,
    old_birthday: BlockHeight,
    /// The height where `fresh` adopted its anchors: the new birthday.
    h: Option<BlockHeight>,
}

impl Scan {
    async fn sync(
        &mut self,
        network: &boot::Network,
        source: &CanonicalBlockSource,
        treasury_keys: &TreasuryKeys,
        registry_keys: &RegistryKeys,
    ) {
        let (tip, _) = source
            .exact_tip()
            .await
            .expect("FATAL: Zebra tip unavailable");
        while self.wallet.tip().block_height() < tip {
            let height = self.wallet.tip().block_height() + 1;
            let block = source
                .get_block(network, height)
                .await
                .expect("FATAL: block unavailable during the scan");
            let time = block.header().time;
            self.mtp
                .header_time_ok(time)
                .unwrap_or_else(|reason| panic!("FATAL: {reason} at height {}", u32::from(height)));

            if height >= self.old_birthday && self.h.is_none() {
                let mut next = self.mtp.clone();
                next.update(height, time);
                let block_mtp = next.current().expect("FATAL: MTP unavailable");
                registry::apply(
                    network,
                    registry_keys,
                    &block,
                    height,
                    block_mtp,
                    &mut self.old,
                );
            }

            let new_law = if height > self.old_birthday {
                &mut self.fresh
            } else {
                &mut self.throwaway
            };
            zns_mint::mint::apply_block(
                network,
                registry_keys,
                treasury_keys,
                block,
                height,
                &mut self.wallet,
                new_law,
                &mut self.mtp,
            );
            if self.h.is_none() && self.fresh.anchor_adoption_closed() {
                tracing::info!(h = u32::from(height), "rebind: new anchors adopted");
                self.h = Some(height);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // ring and aws-lc-rs are both linked. Rustls will not choose a process
    // default, and the first HTTPS client panics without one.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let network = boot::boot_network();
    let (_manifest, custody, anchor) = boot::load_manifest();
    let (treasury_keys, registry_keys) = boot::unseal(&network, &custody);
    let old_birthday = BlockHeight::from_u32(anchor.birthday);

    let chain = ChainClient::connect()
        .await
        .expect("FATAL: Zebra gRPC unreachable or timed out");
    let source = CanonicalBlockSource::new(chain);
    let origin = boot::origin_checkpoint(old_birthday, async |height| {
        source.chain_state_at(height).await
    })
    .await;
    let sapling_roots = source
        .get_subtree_roots::<sapling::Node>("sapling", 0)
        .await
        .expect("FATAL: Sapling subtree roots unavailable from Zebra");
    let ironwood_roots = source
        .get_subtree_roots::<orchard::tree::MerkleHashOrchard>("ironwood", 0)
        .await
        .expect("FATAL: Ironwood subtree roots unavailable from Zebra");
    let wallet = Wallet::new(
        [
            (TREASURY_ACCOUNT, treasury_keys.fvk()),
            (REGISTRY_ACCOUNT, registry_keys.fvk()),
        ],
        &origin,
        &sapling_roots,
        &ironwood_roots,
        network,
    )
    .expect("FATAL: failed to seed commitment trees from the verified Zebra checkpoint");
    let mtp = boot::mtp_through(origin.block_height(), &source).await;

    let mut scan = Scan {
        wallet,
        mtp,
        old: registry::Registry::new(),
        throwaway: zns_mint::mint::registry::Registry::new(),
        fresh: zns_mint::mint::registry::Registry::new(),
        old_birthday,
        h: None,
    };
    scan.sync(&network, &source, &treasury_keys, &registry_keys)
        .await;

    let live: Vec<_> = scan.old.name_chain().collect();
    tracing::info!(
        names = live.len(),
        tip = u32::from(scan.wallet.tip().block_height()),
        "rebind: live names read"
    );
}
