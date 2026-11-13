//! zns-rebind: moves every live Name Note to a bound claim, once, inside the
//! migrated guest before the new mint first boots.
//!
//! Unseal, scan, check the Treasury, anchor transaction (H), sweep, claims,
//! check, rewrite the manifest's anchor. Each step is done when the chain
//! says so, so a rerun picks up where the last one stopped.

mod anchor;
mod boot;
mod note;
mod registry;
mod sweep;

use std::time::Duration;

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zns_mint::mint::mtp::MtpTracker;
use zns_mint::mint::registry::ANCHOR_POOL_SIZE;
use zns_mint::mint::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zns_mint::wallet::Wallet;
use zns_mint::zcash::{CanonicalBlockSource, ChainClient};
use zns_mint::{RegistryKeys, TreasuryKeys};

/// How often a waiting step checks the chain again.
const POLL: Duration = Duration::from_secs(10);

/// What the Treasury must hold before the move starts (0.05 ZEC): about
/// four times the fees of moving ~300 names at 1,000 zats per action,
/// plus the new mint's boot floor. What the move does not spend stays.
const MIN_REBIND_BALANCE: u64 = 5_000_000;

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
    /// The new birthday and the anchor transaction mined there.
    h: Option<(BlockHeight, TxId)>,
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
                let any = *self.fresh.anchor_pool().first().expect("adopted anchors");
                let txid = *self
                    .wallet
                    .unspent_ironwood_note_by_nullifier(
                        REGISTRY_ACCOUNT,
                        any,
                        TargetHeight::from(height),
                    )
                    .expect("FATAL: adopted anchor missing from the wallet")
                    .txid();
                tracing::info!(h = u32::from(height), %txid, "rebind: new anchors adopted");
                self.h = Some((height, txid));
            }
        }
    }

    /// Syncs again once the chain has moved past the applied tip.
    async fn next_block(
        &mut self,
        network: &boot::Network,
        source: &CanonicalBlockSource,
        treasury_keys: &TreasuryKeys,
        registry_keys: &RegistryKeys,
    ) {
        let applied = self.wallet.tip().block_height();
        loop {
            tokio::time::sleep(POLL).await;
            let (tip, _) = source
                .exact_tip()
                .await
                .expect("FATAL: Zebra tip unavailable");
            if tip > applied {
                break;
            }
        }
        self.sync(network, source, treasury_keys, registry_keys)
            .await;
    }

    /// Every Treasury note the wallet can spend at the tip, both pools.
    fn treasury_balance(&self) -> u64 {
        let target = TargetHeight::from(self.wallet.tip().block_height());
        let ironwood: u64 = self
            .wallet
            .unspent_ironwood_notes(TREASURY_ACCOUNT, target)
            .iter()
            .map(|note| note.note().value().inner())
            .sum();
        let sapling: u64 = self
            .wallet
            .unspent_sapling_notes(TREASURY_ACCOUNT, target)
            .iter()
            .map(|note| note.note().value().inner())
            .sum();
        ironwood + sapling
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

    // 1. Unseal.
    let network = boot::boot_network();
    let (_manifest, custody, anchor) = boot::load_manifest();
    let (treasury_keys, registry_keys) = boot::unseal(&network, &custody);
    let old_birthday = BlockHeight::from_u32(anchor.birthday);
    let (spend_prover, output_prover) = boot::sapling_provers();

    // 2. Scan from the live mint's own wallet origin to the tip.
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

    // The names to move. None means this manifest's anchor is not the live
    // mint's: there is nothing to move, and nothing may be rewritten.
    let claims: Vec<_> = scan.old.name_chain().collect();
    assert!(
        !claims.is_empty(),
        "FATAL: no live old-format names from {}; refusing to move an empty registry",
        u32::from(old_birthday)
    );
    tracing::info!(names = claims.len(), "rebind: live names read");

    let fee_rule = source
        .standard_fee()
        .await
        .expect("FATAL: fee rate unavailable from Zebra");
    let marginal = fee_rule.marginal_fee().into_u64();

    // 3. The anchor transaction. The operator funds the Treasury first; a
    // short balance refuses here, before anything is sent.
    if scan.h.is_none() {
        let have = scan.treasury_balance();
        assert!(
            have >= MIN_REBIND_BALANCE,
            "FATAL: the Treasury holds {have} zats; the move needs {MIN_REBIND_BALANCE}. \
             Send {} more to the Treasury and run again.",
            MIN_REBIND_BALANCE - have
        );
        // Each fee note pays one claim (3 actions) per round, and keeps its
        // change for the next round.
        let rounds = claims.len().div_ceil(ANCHOR_POOL_SIZE) as u64;
        let fee_note = Zatoshis::from_u64(rounds * 3 * marginal + marginal)
            .expect("fee note fits the monetary range");
        let tip = scan.wallet.tip().block_height();
        let (transaction, fee) = anchor::build(
            &network,
            &mut scan.wallet,
            &treasury_keys,
            &registry_keys,
            &spend_prover,
            &output_prover,
            &fee_rule,
            fee_note,
            tip,
        );
        assert!(
            source.submit(&transaction, "rebind anchors").await,
            "FATAL: the node refused the anchor transaction"
        );
        scan.wallet.record_sent(&transaction, tip + 1, fee);
        tracing::info!(txid = %transaction.txid(), "rebind: anchor transaction sent");
        while scan.h.is_none() {
            scan.next_block(&network, &source, &treasury_keys, &registry_keys)
                .await;
        }
    }
    let (h, anchor_txid) = scan.h.expect("H is known");
    tracing::info!(h = u32::from(h), %anchor_txid, "rebind: anchors at the new birthday");

    // 4. The sweep: the old Treasury notes into one note the new mint sees.
    if sweep::due(&scan.wallet, h, scan.wallet.tip().block_height()) {
        let transaction = sweep::build(
            &network,
            &mut scan.wallet,
            &treasury_keys,
            &spend_prover,
            &output_prover,
            &fee_rule,
        );
        assert!(
            source.submit(&transaction, "rebind sweep").await,
            "FATAL: the node refused the sweep"
        );
        tracing::info!(txid = %transaction.txid(), "rebind: sweep sent");
    }
}
