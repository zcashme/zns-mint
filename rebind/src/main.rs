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
mod registry;
mod sweep;

use std::collections::BTreeMap;
use std::time::Duration;

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zns_canon::genesis::Anchor;
use zns_mint::mint::mtp::MtpTracker;
use zns_mint::mint::registry::Registry;
use zns_mint::mint::{NameNote, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{CanonicalBlockSource, ChainClient};
use zns_mint::{RegistryKeys, TreasuryKeys};

/// How often a waiting step checks the chain again.
const POLL: Duration = Duration::from_secs(10);

/// What the Treasury must hold in Ironwood before the move starts (0.05 ZEC): about
/// four times the fees of moving ~300 names at 1,000 zats per action,
/// plus the new mint's boot floor. What the move does not spend stays.
const MIN_REBIND_BALANCE: u64 = 5_000_000;

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
    /// Applies blocks until Zebra has none past the wallet's tip. `old`
    /// also takes the live mint's law over them. When the block holding
    /// `anchor_txid` arrives, `law` starts afresh there, and its height is
    /// returned: H.
    async fn sync(
        &mut self,
        rebind: &Rebind,
        mut old: Option<&mut registry::Registry>,
        anchor_txid: Option<TxId>,
    ) -> Option<BlockHeight> {
        let mut h = None;
        loop {
            let (tip, _) = rebind
                .source
                .exact_tip()
                .await
                .expect("FATAL: Zebra tip unavailable");
            if self.wallet.tip().block_height() >= tip {
                return h;
            }
            while self.wallet.tip().block_height() < tip {
                let height = self.wallet.tip().block_height() + 1;
                let block = rebind
                    .source
                    .get_block(&rebind.network, height)
                    .await
                    .expect("FATAL: block unavailable during the scan");
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

    /// Syncs again once the chain has moved past the applied tip.
    async fn next_block(
        &mut self,
        rebind: &Rebind,
        anchor_txid: Option<TxId>,
    ) -> Option<BlockHeight> {
        let applied = self.wallet.tip().block_height();
        loop {
            tokio::time::sleep(POLL).await;
            let (tip, _) = rebind
                .source
                .exact_tip()
                .await
                .expect("FATAL: Zebra tip unavailable");
            if tip > applied {
                break;
            }
        }
        self.sync(rebind, None, anchor_txid).await
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

/// The scan to the tip with the live mint's law: one claim per live name.
/// No names means this manifest's anchor is not the live mint's: there is
/// nothing to move, and nothing may be rewritten.
async fn read_live_names(chain: &mut Chain, rebind: &Rebind) -> Vec<NameNote> {
    let mut old = registry::Registry::new();
    chain.sync(rebind, Some(&mut old), None).await;
    let claims: Vec<_> = old.name_chain().map(claim::of).collect();
    assert!(
        !claims.is_empty(),
        "FATAL: no live old-format names from {}; refusing to move an empty registry",
        u32::from(chain.old_birthday)
    );
    tracing::info!(names = claims.len(), "rebind: live names read");
    claims
}

/// The operator funds the Treasury first; a short balance refuses here,
/// before anything is sent.
fn check_funds(chain: &Chain) {
    let have = chain.treasury_ironwood();
    assert!(
        have >= MIN_REBIND_BALANCE,
        "FATAL: the Treasury holds {have} zats in Ironwood; the move needs \
         {MIN_REBIND_BALANCE}. Send {} more to the Treasury and run again.",
        MIN_REBIND_BALANCE - have
    );
}

/// Sends the anchor transaction and waits for the block that mines it: H.
async fn place_anchors(chain: &mut Chain, rebind: &Rebind, names: usize) -> (BlockHeight, TxId) {
    // A fee note can pay one claim (3 actions) in every round, its change
    // paying the next.
    let marginal = rebind.fee_rule.marginal_fee().into_u64();
    let rounds = names.div_ceil(anchor::LANES) as u64;
    let fee_note = Zatoshis::from_u64(rounds * 3 * marginal + marginal)
        .expect("fee note fits the monetary range");
    let tip = chain.wallet.tip().block_height();
    let (transaction, fee) = anchor::build(
        &rebind.network,
        &mut chain.wallet,
        &rebind.treasury_keys,
        &rebind.registry_keys,
        &rebind.spend_prover,
        &rebind.output_prover,
        &rebind.fee_rule,
        fee_note,
        tip,
    );
    assert!(
        rebind.source.submit(&transaction, "rebind anchors").await,
        "FATAL: the node refused the anchor transaction"
    );
    chain.wallet.record_sent(&transaction, tip + 1, fee);
    let anchor_txid = transaction.txid();
    tracing::info!(txid = %anchor_txid, "rebind: anchor transaction sent");
    loop {
        if let Some(h) = chain.next_block(rebind, Some(anchor_txid)).await {
            tracing::info!(h = u32::from(h), txid = %anchor_txid, "rebind: anchors at the new birthday");
            return (h, anchor_txid);
        }
    }
}

/// The claims, up to `anchor::LANES` per block, before the sweep merges
/// the Treasury's notes.
async fn claim_all(chain: &mut Chain, rebind: &Rebind, claims: &[NameNote]) {
    let mut in_flight = BTreeMap::new();
    while !claims.iter().all(|c| claim::held(&chain.law, c)) {
        claim::round(
            &rebind.network,
            &mut chain.wallet,
            &rebind.treasury_keys,
            &rebind.registry_keys,
            &rebind.spend_prover,
            &rebind.output_prover,
            &rebind.fee_rule,
            &rebind.source,
            &chain.law,
            claims,
            &mut in_flight,
        )
        .await;
        chain.next_block(rebind, None).await;
    }
}

/// The sweep, last: whatever the Treasury still holds from before H, into
/// one note the new mint sees. One sweep; a note too small to pay its own
/// spend stays behind. The manifest waits until it is mined.
async fn sweep_treasury(chain: &mut Chain, rebind: &Rebind, h: BlockHeight) {
    if !sweep::due(&chain.wallet, h, chain.wallet.tip().block_height()) {
        return;
    }
    let transaction = sweep::build(
        &rebind.network,
        &mut chain.wallet,
        &rebind.treasury_keys,
        &rebind.spend_prover,
        &rebind.output_prover,
        &rebind.fee_rule,
    );
    assert!(
        rebind.source.submit(&transaction, "rebind sweep").await,
        "FATAL: the node refused the sweep"
    );
    let txid = transaction.txid();
    tracing::info!(%txid, "rebind: sweep sent");
    while chain
        .wallet
        .get_tx_height(txid)
        .expect("FATAL: wallet transaction lookup")
        .is_none()
    {
        chain.next_block(rebind, None).await;
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

    // 2. The names to move.
    let claims = read_live_names(&mut chain, &rebind).await;
    // 3. The Treasury covers the move.
    check_funds(&chain);
    // 4. The anchor transaction: H.
    let (h, anchor_txid) = place_anchors(&mut chain, &rebind, claims.len()).await;
    // 5. The claims.
    claim_all(&mut chain, &rebind, &claims).await;
    // 6. The sweep.
    sweep_treasury(&mut chain, &rebind, h).await;

    // 7. The check: the new law holds exactly the live names, no more.
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

    // 8. The manifest: only the anchor and the birthday change.
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
