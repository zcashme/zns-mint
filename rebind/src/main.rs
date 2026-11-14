//! zns-rebind: moves every live Name Note to a bound claim, once, inside the
//! migrated guest before the new mint first boots.
//!
//! Unseal, read the live names, check the Treasury, anchor transaction (H),
//! claims, sweep, check, rewrite the manifest's anchor. H is the block
//! holding the anchor transaction this run sent; a rerun sends its own.

mod anchor;
mod boot;
mod claim;
mod note;
mod phase;
mod registry;
mod sweep;

use std::time::Duration;

use futures_util::{stream, StreamExt as _};
use phase::{Moved, Phase};
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zns_canon::genesis::Anchor;
use zns_mint::mint::mtp::MtpTracker;
use zns_mint::mint::registry::Registry;
use zns_mint::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{CanonicalBlockSource, ChainClient};
use zns_mint::{RegistryKeys, TreasuryKeys};

/// How often a waiting phase checks the chain again.
const POLL: Duration = Duration::from_secs(10);

/// Rebind reads only blocks this deep, so a reorg of the newest blocks
/// never touches what it applied, and what it builds anchors at H − 3, as
/// ZIP 315 recommends.
const DEPTH: u32 = 3;

/// Blocks fetched while the one before them is applied. Applying still
/// goes one block at a time, in height order.
const AHEAD: usize = 4;

/// What the run works with from start to end.
struct Rebind {
    network: boot::Network,
    source: CanonicalBlockSource,
    treasury_keys: TreasuryKeys,
    registry_keys: RegistryKeys,
    spend_prover: sapling::circuit::SpendParameters,
    output_prover: sapling::circuit::OutputParameters,
    fee_rule: FeeRule,
}

/// The chain as applied so far: the wallet, the clock, and the new law.
struct Chain {
    wallet: Wallet<boot::Network>,
    mtp: MtpTracker,
    /// The new law. Renewed at the anchor transaction's block, from where it
    /// is what the new mint builds booting from H.
    law: Registry,
    old_birthday: BlockHeight,
}

impl Chain {
    /// Applies blocks until Zebra has none [`DEPTH`] deep past the wallet's
    /// tip. `old` also takes the live mint's law over them. When the block
    /// holding `anchor_txid` arrives, `law` starts afresh there, and its
    /// height is returned: H.
    async fn sync(
        &mut self,
        rebind: &Rebind,
        mut old: Option<&mut registry::Registry>,
        anchor_txid: Option<TxId>,
    ) -> Option<BlockHeight> {
        let mut h = None;
        loop {
            let tip = settled_tip(rebind).await;
            if self.wallet.tip().block_height() >= tip {
                return h;
            }
            let next = u32::from(self.wallet.tip().block_height()) + 1;
            let mut blocks = stream::iter(next..=u32::from(tip))
                .map(|height| {
                    rebind
                        .source
                        .get_block(&rebind.network, BlockHeight::from_u32(height))
                })
                .buffered(AHEAD);
            while let Some(block) = blocks.next().await {
                let block = block.expect("FATAL: block unavailable during the scan");
                let height = self.wallet.tip().block_height() + 1;
                let time = block.header().time;
                self.mtp.header_time_ok(time).unwrap_or_else(|reason| {
                    panic!("FATAL: {reason} at height {}", u32::from(height))
                });

                if let Some(old) = old.as_deref_mut().filter(|_| height >= self.old_birthday) {
                    let mut next = self.mtp.clone();
                    next.update(height, time);
                    let block_mtp = next.current().expect("FATAL: MTP unavailable");
                    registry::apply(
                        &rebind.network,
                        &rebind.registry_keys,
                        &block,
                        height,
                        block_mtp,
                        old,
                    );
                }

                let at_h = anchor_txid.is_some_and(|txid| {
                    h.is_none() && block.vtx().iter().any(|tx| tx.txid() == txid)
                });
                if at_h {
                    self.law = Registry::new();
                    h = Some(height);
                }
                zns_mint::mint::apply_block(
                    &rebind.network,
                    &rebind.registry_keys,
                    &rebind.treasury_keys,
                    block,
                    height,
                    &mut self.wallet,
                    &mut self.law,
                    &mut self.mtp,
                );
                if at_h {
                    assert!(
                        self.law.anchor_adoption_closed(),
                        "FATAL: the anchor transaction's block did not fill the anchor pool"
                    );
                }
            }
        }
    }

    /// Returns once Zebra has a block [`DEPTH`] deep past the wallet's tip.
    async fn wait_for_block(&self, rebind: &Rebind) {
        let applied = self.wallet.tip().block_height();
        loop {
            tokio::time::sleep(POLL).await;
            if settled_tip(rebind).await > applied {
                return;
            }
        }
    }

    /// The Treasury's Ironwood the wallet can spend at the tip: what the
    /// anchor transaction draws on.
    fn treasury_ironwood(&self) -> u64 {
        let target = TargetHeight::from(self.wallet.tip().block_height());
        self.wallet
            .unspent_ironwood_notes(TREASURY_ACCOUNT, target)
            .iter()
            .map(|note| note.note().value().inner())
            .sum()
    }
}

/// Zebra's tip less [`DEPTH`]: the newest block rebind reads.
async fn settled_tip(rebind: &Rebind) -> BlockHeight {
    let (tip, _) = rebind
        .source
        .exact_tip()
        .await
        .expect("FATAL: Zebra tip unavailable");
    tip.saturating_sub(DEPTH)
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

    // 1. Unseal, and reach the node.
    let network = boot::boot_network();
    let (manifest, custody, anchor) = boot::load_manifest();
    let (treasury_keys, registry_keys) = boot::unseal(&network, &custody);
    let old_birthday = BlockHeight::from_u32(anchor.birthday);
    let (spend_prover, output_prover) = boot::sapling_provers();
    let source = CanonicalBlockSource::new(
        ChainClient::connect()
            .await
            .expect("FATAL: Zebra gRPC unreachable or timed out"),
    );
    boot::require_anchor_on_chain(&network, &source, &anchor).await;
    let fee_rule = source
        .standard_fee()
        .await
        .expect("FATAL: fee rate unavailable from Zebra");

    // The wallet starts at the live mint's own origin, so it holds every
    // Treasury note the live mint holds.
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
    let rebind = Rebind {
        network,
        source,
        treasury_keys,
        registry_keys,
        spend_prover,
        output_prover,
        fee_rule,
    };
    let mut chain = Chain {
        wallet,
        mtp,
        law: Registry::new(),
        old_birthday,
    };

    // 2. One loop over new blocks: the names, the anchor transaction (H),
    // the claims, the sweep. A phase that moved on acts at once; one that
    // stayed waits for the next block.
    let mut phase = Phase::Names {
        old: registry::Registry::new(),
    };
    let Moved {
        claims,
        h,
        anchor: anchor_txid,
    } = loop {
        let anchor_txid = phase.anchor_txid();
        let anchored = chain.sync(&rebind, phase.old_law(), anchor_txid).await;
        let stayed = std::mem::discriminant(&phase);
        phase = phase.advance(&mut chain, &rebind, anchored).await;
        if let Phase::Done(moved) = phase {
            break moved;
        }
        if std::mem::discriminant(&phase) == stayed {
            chain.wait_for_block(&rebind).await;
        }
    };

    // 3. The check: the new law holds exactly the live names, no more.
    assert_eq!(
        chain.law.name_chain().count(),
        claims.len(),
        "FATAL: the new law holds names the live mint did not"
    );
    tracing::info!(
        names = claims.len(),
        h = u32::from(h),
        "rebind: every live name held"
    );

    // 4. The manifest: only the anchor and the birthday change.
    let moved = Anchor {
        txid: hex::decode(anchor_txid.to_string())
            .expect("txid display is hex")
            .try_into()
            .expect("a txid is 32 bytes"),
        birthday: u32::from(h),
    };
    let rewritten = moved
        .rewrite(&manifest)
        .unwrap_or_else(|error| panic!("FATAL: manifest rewrite: {error}"));
    boot::write_manifest(&rewritten);
    tracing::info!(%anchor_txid, birthday = u32::from(h), "rebind: manifest moved; done");
}
