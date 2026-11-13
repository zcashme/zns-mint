//! The boot sequence: acquire and verify every capability the run loop
//! cannot acquire for itself, then hand them over as one contract.
mod key;

pub use key::{RegistryKeys, TreasuryKeys};

use secrecy::{ExposeSecret, Secret};
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
use zcash_protocol::consensus::MainNetwork;
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
use zcash_protocol::consensus::TestNetwork;
#[cfg(feature = "regtest")]
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    TxId,
};
use zip32::fingerprint::SeedFingerprint;

use std::str::FromStr;

use crate::mint::mtp::MtpTracker;
use crate::mint::note::NameNoteQueue;
use crate::mint::presale::{self, AccessCodeDerivationKey, HttpsClient, ProtectedNames};
use crate::mint::pricing::Oracle;
use crate::mint::registry::Registry;
use crate::mint::sale::Market;
use crate::mint::treasury::{OtpQueue, RefundQueue, RequestQueue};
use crate::mint::{MIN_TREASURY_BALANCE, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;
use crate::zcash::{self, CanonicalBlockSource, ChainClient};
use sapling::circuit::{OutputParameters, SpendParameters};
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zns_canon::capsule::{hash as capsule_hash, parse_capsule, read_capsule_file, unseal_seed};
#[cfg(not(feature = "non-tee"))]
use zns_canon::sealing::derive_sealing_key;
#[cfg(feature = "non-tee")]
use zns_canon::sealing::dev_sealing_key;
#[cfg(not(feature = "non-tee"))]
use zns_canon::sealing::get_attestation;
use zns_canon::sealing::{SealingKey, TeeError};

/// `non-tee` builds use the public test key, even on an SNP guest.
/// Hardware builds require the guest sealing key.
fn sealing_key() -> Result<SealingKey, TeeError> {
    #[cfg(feature = "non-tee")]
    {
        Ok(dev_sealing_key())
    }
    #[cfg(not(feature = "non-tee"))]
    {
        derive_sealing_key()
    }
}

// ---------------------------------------------------------------------------
// Boot life-cycle
// ---------------------------------------------------------------------------

/// Public launch facts extracted from the verified identity attestation.
pub struct GuestInfo {
    pub measurement: String,
    pub guest_policy: String,
}

/// The boot product: constructed only after every boot check succeeds.
/// Consumed exactly once by `main`'s exhaustive destructure — the seam
/// contract, one criterion line per field.
pub struct Boot<P: Parameters> {
    /// verified: boot-to-loop consensus — the loop never discovers parameters
    pub network: P,
    /// acquired: boot proved that both Zebra transports are live
    pub chain: ChainClient,
    /// acquired: the node source used during boot sync
    pub source: CanonicalBlockSource,
    /// produced: trees seeded from the verified origin
    pub wallet: Wallet<P>,
    /// produced: derived from the seed — the seed dies before this exists
    pub treasury_keys: TreasuryKeys,
    /// produced: derived from the seed
    pub registry_keys: RegistryKeys,
    /// must not fail after attestation: hash-verified before the report
    pub sapling_spend: SpendParameters,
    /// must not fail after attestation: hash-verified before the report
    pub sapling_output: OutputParameters,
    /// produced: backfilled before the first scan
    pub mtp: MtpTracker,
    /// must not: fail-closed at birth — the first price or no start
    pub oracle: Oracle,
    /// initialized: pending OTP challenges
    pub challenges: OtpQueue,
    /// TEE-derived access-code key (HMAC purpose key, not the root)
    pub access_code_key: AccessCodeDerivationKey,
    /// must not: fail-closed at birth — the table or no start
    pub protected_names: ProtectedNames,
    /// initialized: the one client every pre-sale read goes through
    pub presale_client: HttpsClient,
    /// must not: fail-closed at birth — the node's fee rate or no start
    pub fee_rule: FeeRule,
    /// produced: scanned and verified during boot sync
    pub registry: Registry,
    /// initialized: pending Name Note authorizations
    pub name_notes: NameNoteQueue,
    /// initialized: pending Treasury requests
    pub requests: RequestQueue,
    /// initialized: refunds due
    pub refunds: RefundQueue,
    /// initialized: open buys
    pub market: Market,
    /// The exact encoded identity written to the boot identity document.
    pub treasury_address: String,
    pub registry_ufvk: String,
    /// Verified capsule fingerprint and hash, retained after the seed is wiped.
    pub seed_fingerprint: String,
    pub capsule_hash: String,
    #[cfg(not(feature = "non-tee"))]
    pub guest: GuestInfo,
}

/// Network label for logging.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
const NETWORK_LABEL: &str = "mainnet";

#[cfg(all(feature = "testnet", not(feature = "regtest")))]
const NETWORK_LABEL: &str = "testnet";

#[cfg(feature = "regtest")]
const NETWORK_LABEL: &str = "regtest";

/// The build-selected network type; exactly one per binary.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
type Network = MainNetwork;
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
type Network = TestNetwork;
#[cfg(feature = "regtest")]
type Network = LocalNetwork;

/// The one network value this build serves.
fn boot_network() -> Network {
    #[cfg(not(feature = "regtest"))]
    #[cfg(not(feature = "testnet"))]
    {
        zcash_protocol::consensus::MAIN_NETWORK
    }
    #[cfg(all(feature = "testnet", not(feature = "regtest")))]
    {
        zcash_protocol::consensus::TEST_NETWORK
    }
    #[cfg(feature = "regtest")]
    {
        LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(1)),
            blossom: Some(BlockHeight::from_u32(1)),
            heartwood: Some(BlockHeight::from_u32(1)),
            canopy: Some(BlockHeight::from_u32(1)),
            nu5: Some(BlockHeight::from_u32(1)),
            nu6: Some(BlockHeight::from_u32(1)),
            nu6_1: Some(BlockHeight::from_u32(4)),
            nu6_2: Some(BlockHeight::from_u32(4)),
            nu6_3: Some(BlockHeight::from_u32(4)),
            nu7: None,
        }
    }
}

/// Ceremony adoption has closed. The live set may sit below standing
/// size after a Registry spend that seated no successor.
fn require_established_ceremony(registry: &Registry) {
    assert!(
        registry.anchor_adoption_closed(),
        "FATAL: ceremony adoption has not closed"
    );
}

fn require_ceremony_network(ceremony: &CeremonyAnchor) {
    assert_eq!(
        ceremony.network, NETWORK_LABEL,
        "FATAL: {CUSTODY_MANIFEST_FILE} network does not match {NETWORK_LABEL} build"
    );
}

/// SEV-SNP attestation report length. Any other size is not a report.
#[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
const ATTESTATION_REPORT_LEN: usize = 1184;

/// The boot identity document: written once, at attestation time.
const IDENTITY_DOC_FILE: &str = "zns_mint_identity.json";

/// Keygen's custody manifest: network, seed fingerprint, anchor txid,
/// and the height it mined at. Boot accepts the seed this fingerprint
/// names when the capsule matches it; an attested build also requires
/// the keygen report. The anchor txid is checked against the chain.
/// A missing file refuses boot.
const CUSTODY_MANIFEST_FILE: &str = "keys/zns_custody_manifest.toml";

/// Genesis facts and the hex-encoded SNP report, one file. `keys/` is
/// read-only in production, so this stays in the working directory.
#[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
const GENESIS_RECORD_FILE: &str = "zns_genesis_record.json";

/// The keygen report has to cover this capsule file. It carries
/// `BLAKE2b-512(fingerprint ‖ capsule hash)` under the AMD signature.
/// A missing report, or one that does not cover this file, refuses boot.
#[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
fn require_keygen_attestation(capsule_bytes: &[u8], fingerprint: &SeedFingerprint) {
    let report = read_attestation_report(std::path::Path::new("keys/zns_attestation.bin"));
    zns_canon::attestation::verify(capsule_bytes, fingerprint, report)
        .expect("FATAL: keygen attestation report failed verification");
}

/// One open of the keygen report. The descriptor must be a regular file
/// of [`ATTESTATION_REPORT_LEN`] bytes; that same descriptor is what is read.
#[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
fn read_attestation_report(path: &std::path::Path) -> Vec<u8> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .unwrap_or_else(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                panic!("FATAL: {} is a symlink", path.display());
            }
            if error.kind() == std::io::ErrorKind::IsADirectory {
                panic!("FATAL: {} is not a regular file", path.display());
            }
            panic!("FATAL: cannot read {}: {error}", path.display());
        });
    let meta = file
        .metadata()
        .unwrap_or_else(|error| panic!("FATAL: cannot stat {}: {error}", path.display()));
    if !meta.file_type().is_file() {
        panic!("FATAL: {} is not a regular file", path.display());
    }
    if meta.len() != ATTESTATION_REPORT_LEN as u64 {
        panic!(
            "FATAL: {} is not a {ATTESTATION_REPORT_LEN}-byte SEV-SNP attestation report",
            path.display()
        );
    }
    let mut bytes = vec![0u8; ATTESTATION_REPORT_LEN];
    file.read_exact(&mut bytes)
        .unwrap_or_else(|error| panic!("FATAL: cannot read {}: {error}", path.display()));
    bytes
}

/// Attests the ceremony anchor after the seed is gone. `non-tee` builds
/// skip this: no device.
#[cfg(not(feature = "non-tee"))]
fn write_genesis_statement(capsule_hash: [u8; 32], fingerprint: [u8; 32], anchor: &CeremonyAnchor) {
    let record = genesis_record(genesis_network(), fingerprint, capsule_hash, anchor);
    let report_data = zns_canon::genesis::genesis_report_data(&record);
    let attestation = get_attestation(&report_data)
        .expect("FATAL: failed to obtain the genesis attestation report");
    let document = genesis_document(&record, anchor, attestation.as_bytes());
    // One file, like the identity document. A torn write is a partial file.
    std::fs::write(GENESIS_RECORD_FILE, &document)
        .unwrap_or_else(|error| panic!("FATAL: failed to write {GENESIS_RECORD_FILE}: {error}"));
    tracing::info!(
        txid = %anchor.txid,
        birthday = record.birthday,
        "boot: genesis attestation written"
    );
}

#[cfg(not(feature = "non-tee"))]
fn genesis_network() -> zns_canon::genesis::NetworkId {
    use zns_canon::genesis::NetworkId;
    #[cfg(feature = "testnet")]
    {
        NetworkId::Testnet
    }
    #[cfg(not(feature = "testnet"))]
    {
        NetworkId::Mainnet
    }
}

/// The genesis facts: what the attestation report will bind.
#[cfg(not(feature = "non-tee"))]
fn genesis_record(
    network: zns_canon::genesis::NetworkId,
    fingerprint: [u8; 32],
    capsule_hash: [u8; 32],
    anchor: &CeremonyAnchor,
) -> zns_canon::genesis::GenesisRecord {
    zns_canon::genesis::GenesisRecord {
        version: 1,
        network,
        seed_fingerprint: fingerprint,
        capsule_hash,
        // Display-order bytes, same as the published JSON field.
        anchor_txid: anchor.file_txid,
        birthday: anchor.birthday,
    }
}

/// Keygen's ceremony record: the build's network, the seed's fingerprint,
/// the anchor transaction, and the height it mined at. Read on every
/// network.
struct CeremonyAnchor {
    network: String,
    seed_fingerprint: String,
    /// Internal order, for `tx.txid()` equality in the chain check.
    txid: TxId,
    /// The file's own display-order bytes — what the genesis document
    /// publishes and the genesis attestation quotes. `non-tee` builds
    /// write no genesis statement.
    #[cfg(not(feature = "non-tee"))]
    file_txid: [u8; 32],
    birthday: u32,
}

/// Reads `keys/zns_custody_manifest.toml`. Missing, malformed, or a non-hex
/// txid refuses boot: the manifest is the only record of which transaction
/// anchored the mint, and a missing file must not silently skip the
/// anchor check.
fn load_ceremony_anchor() -> CeremonyAnchor {
    ceremony_anchor(
        &std::fs::read_to_string(CUSTODY_MANIFEST_FILE)
            .unwrap_or_else(|error| panic!("FATAL: cannot read {CUSTODY_MANIFEST_FILE}: {error}")),
    )
}

/// The anchor, verified against the chain: the stored txid must be
/// mined at the manifest birthday. A fabricated (birthday, txid) pair
/// refuses boot here.
async fn require_anchor_on_chain(
    fetch_block: impl AsyncFnOnce(
        BlockHeight,
    ) -> Result<zcash_primitives::block::Block, zcash::TransportError>,
    birthday: BlockHeight,
    anchor: TxId,
) {
    let block = fetch_block(birthday).await.unwrap_or_else(|error| {
        panic!("FATAL: cannot fetch block at the manifest birthday {birthday}: {error}")
    });
    assert!(
        block.vtx().iter().any(|tx| tx.txid() == anchor),
        "FATAL: ceremony anchor {anchor} is not mined at the manifest birthday {birthday}"
    );
    tracing::info!(
        txid = %anchor,
        birthday = u32::from(birthday),
        "boot: ceremony anchor verified on chain"
    );
}

/// Parses the custody manifest's text. That string is `Transaction::txid`'s
/// display form.
fn ceremony_anchor(text: &str) -> CeremonyAnchor {
    #[derive(serde::Deserialize)]
    struct RawAnchor {
        anchor_txid: Option<String>,
        birthday: Option<u32>,
        network: Option<String>,
        seed_fingerprint: Option<String>,
    }
    let raw: RawAnchor = toml::from_str(text)
        .unwrap_or_else(|error| panic!("FATAL: {CUSTODY_MANIFEST_FILE} is invalid: {error}"));
    let txid_hex = raw
        .anchor_txid
        .filter(|txid| !txid.trim().is_empty())
        .unwrap_or_else(|| panic!("FATAL: {CUSTODY_MANIFEST_FILE} has no anchor txid"));
    let birthday = raw
        .birthday
        .unwrap_or_else(|| panic!("FATAL: {CUSTODY_MANIFEST_FILE} has no birthday"));
    let network = raw
        .network
        .unwrap_or_else(|| panic!("FATAL: {CUSTODY_MANIFEST_FILE} has no network"));
    let seed_fingerprint = raw
        .seed_fingerprint
        .unwrap_or_else(|| panic!("FATAL: {CUSTODY_MANIFEST_FILE} has no seed fingerprint"));
    #[cfg(not(feature = "non-tee"))]
    let file_txid: [u8; 32] = hex::decode(txid_hex.trim())
        .unwrap_or_else(|_| panic!("FATAL: {CUSTODY_MANIFEST_FILE} txid is not hex"))
        .try_into()
        .unwrap_or_else(|_| panic!("FATAL: {CUSTODY_MANIFEST_FILE} txid is not 32 bytes"));
    CeremonyAnchor {
        network,
        seed_fingerprint,
        // Display form: `from_hex` inverts it, `from_bytes` would not.
        txid: TxId::from_hex(txid_hex.trim())
            .unwrap_or_else(|| panic!("FATAL: {CUSTODY_MANIFEST_FILE} txid is not hex")),
        #[cfg(not(feature = "non-tee"))]
        file_txid,
        birthday,
    }
}

#[cfg(not(feature = "non-tee"))]
fn genesis_document(
    record: &zns_canon::genesis::GenesisRecord,
    anchor: &CeremonyAnchor,
    report: &[u8],
) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "version": record.version,
        "network": NETWORK_LABEL,
        "seed_fingerprint": hex::encode(record.seed_fingerprint),
        "capsule_hash": hex::encode(record.capsule_hash),
        "anchor_txid": anchor.txid.to_string(),
        "birthday": record.birthday,
        "report": hex::encode(report),
    }))
    .expect("FATAL: genesis record serialization")
}

impl Boot<Network> {
    /// Boot sequence for this build's network.
    pub async fn start() -> Self {
        // ring and aws-lc-rs are both linked. Rustls will not choose a
        // process default, and the first HTTPS client panics without one.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let network = boot_network();
        tracing::info!("boot: starting");

        #[cfg(feature = "non-tee")]
        tracing::warn!(
            "boot: NON-TEE BUILD — sealing keys are public and there is no attestation; \
             never point at production"
        );

        // 1. Liveness + connect: confirm both Zebra transports, get chain client.
        let chain_client = connect_zebra().await;

        // The one node handle: both dialects behind one door, bound to the
        // client this boot proved live.
        let source = CanonicalBlockSource::new(chain_client.clone());

        // Ceremony facts — the custody manifest, every network: keygen
        // writes it in deployment, the fixture on regtest.
        let ceremony = load_ceremony_anchor();
        require_ceremony_network(&ceremony);
        let mint_birthday = BlockHeight::from_u32(ceremony.birthday);

        // 1b. Select the build's sealing mode: public dev key for
        // regtest/non-tee, hardware key for attested builds.

        // 2. Seed intake + verification: read capsule, require the keygen
        //    report for this file, unseal, then
        //    derive keys. The seed lives only inside this block — Secret's
        //    Drop wipes it. The access-code key derives from the seed: an
        //    X25519 scalar agreed with the issuer's public key.
        let (
            treasury_keys,
            registry_keys,
            ceremony_fingerprint,
            ceremony_capsule_hash,
            access_code_key,
        ) = {
            tracing::info!("boot: reading seed capsule from keys/zns_seed.capsule");
            let blob = read_capsule_file("keys/zns_seed.capsule").expect(
                "FATAL: failed to read keys/zns_seed.capsule. The mint cannot boot without the sealed seed.",
            );
            let capsule = parse_capsule(&blob).expect("FATAL: failed to parse zns_seed.capsule");
            // Manifest, capsule field, and the attested fingerprint are one
            // value. Unseal then requires that value of the decrypted seed.
            let expected = SeedFingerprint::from_str(ceremony.seed_fingerprint.trim())
                .unwrap_or_else(|_| {
                    panic!("FATAL: invalid seed_fingerprint in {CUSTODY_MANIFEST_FILE}")
                });
            if expected.to_bytes() != capsule.fingerprint {
                panic!("FATAL: capsule fingerprint does not match {CUSTODY_MANIFEST_FILE}");
            }
            #[cfg(not(feature = "non-tee"))]
            require_keygen_attestation(&blob, &expected);
            tracing::info!("boot: resolving capsule sealing key");
            let capsule_key = sealing_key().expect("FATAL: sealing key unavailable");
            let seed = unseal_seed(&capsule_key, &capsule)
                .expect("FATAL: failed to unseal seed. Capsule tampering, wrong TEE, or wrong capsule for this instance.");
            let access_code_key = AccessCodeDerivationKey::from_seed(seed.expose_secret());
            verify_fingerprint(&seed, ceremony.seed_fingerprint.trim());
            let sealed_hash = capsule_hash(&blob);
            (
                TreasuryKeys::derive(&network, &seed),
                RegistryKeys::derive(&network, &seed),
                capsule.fingerprint,
                sealed_hash,
                access_code_key,
            )
        };
        tracing::info!("boot: keys derived (treasury=acct0, registry=acct1); seed wiped");

        // 2b. The anchor, verified against the chain before anything
        //     downstream trusts the ceremony file.
        require_anchor_on_chain(
            |height| source.get_block(&network, height),
            mint_birthday,
            ceremony.txid,
        )
        .await;

        // The genesis attestation, written after the seed is wiped;
        // `non-tee` builds have no device.
        #[cfg(not(feature = "non-tee"))]
        write_genesis_statement(ceremony_capsule_hash, ceremony_fingerprint, &ceremony);

        // 3. Born complete: fetch the origin checkpoint and both
        // subtree-root batches, then one `Wallet::new`.
        let origin = origin_checkpoint(mint_birthday, async |height| {
            source.chain_state_at(height).await
        })
        .await;
        let checkpoint_height = origin.block_height();
        let sapling_roots = source
            .get_subtree_roots::<sapling::Node>("sapling", 0)
            .await
            .expect("FATAL: Sapling subtree roots unavailable from Zebra");
        let ironwood_roots = source
            .get_subtree_roots::<orchard::tree::MerkleHashOrchard>("ironwood", 0)
            .await
            .expect("FATAL: Ironwood subtree roots unavailable from Zebra");
        let mut wallet = Wallet::new(
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
        tracing::info!(
            height = u32::from(checkpoint_height),
            sapling_roots = sapling_roots.len(),
            ironwood_roots = ironwood_roots.len(),
            "boot: wallet born complete from the origin checkpoint"
        );

        // 3d. The mint's birthday: a throwaway window ending at the
        // birthday block, whose median is the birthday block's MTP —
        // the day-zero anchor for `current_day`.
        let mut birthday = MtpTracker::default();
        birthday
            .backfill(mint_birthday, |height| {
                let source = source.clone();
                async move { source.header_time(height).await }
            })
            .await
            .expect("FATAL: birthday MTP backfill from Zebra failed");
        let birthday_mtp = birthday
            .current()
            .expect("FATAL: birthday MTP unavailable from Zebra");
        let mut mtp = MtpTracker::born(birthday_mtp);

        // 3e. MTP backfill: the 11 header timestamps through the origin
        // checkpoint, so the MTP window is complete before the first scan.
        mtp.backfill(checkpoint_height, |height| {
            let source = source.clone();
            async move { source.header_time(height).await }
        })
        .await
        .expect("FATAL: MTP backfill from Zebra failed");
        tracing::info!(
            "boot: MTP backfilled from headers through checkpoint {}",
            u32::from(checkpoint_height)
        );

        // 4. Boot sync: scan from checkpoint to chain tip. The body is
        // `apply_block` — the same one the run loop calls — with scratch
        // queues: arrivals from history are balance, not instruction, so
        // each block's intake lands in a queue that falls out of scope with
        // the iteration.
        let mut registry = Registry::new();
        let (best_height, _best_hash) = source
            .exact_tip()
            .await
            .expect("FATAL: Zebra tip unavailable during boot sync");
        tracing::info!(
            from = u32::from(checkpoint_height),
            to = u32::from(best_height),
            "boot: syncing to chain tip"
        );
        let fee_rule = source
            .standard_fee()
            .await
            .expect("FATAL: fee rate unavailable from Zebra");
        tracing::info!(
            zats_per_action = fee_rule.marginal_fee().into_u64(),
            "boot: fee rate read"
        );
        while wallet.tip().block_height() < best_height {
            let from_height = wallet.tip().block_height();
            let next_height = from_height + 1;

            let block = source
                .get_block(&network, next_height)
                .await
                .expect("FATAL: block unavailable during boot sync");
            mtp.header_time_ok(block.header().time)
                .unwrap_or_else(|reason| {
                    panic!("FATAL: {reason} at height {}", u32::from(next_height))
                });

            crate::mint::apply_block(
                &network,
                &registry_keys,
                &treasury_keys,
                block,
                next_height,
                &mut wallet,
                &mut registry,
                &mut mtp,
            );
        }
        tracing::info!(
            height = u32::from(wallet.tip().block_height()),
            "boot: synced to chain tip"
        );

        // 5. Genesis sanity checks. Ceremony adoption has closed. A later
        // Registry spend may leave the live set short.
        require_established_ceremony(&registry);
        let anchor_count = registry.anchor_pool().len();
        // Boot refuses to run with a treasury below MIN_TREASURY_BALANCE.
        // The node's tip is never pushed into the wallet.
        let treasury_balance = wallet
            .get_wallet_summary(crate::wallet::CONFIRMATIONS)
            .expect("FATAL: balance summary failed")
            .expect("FATAL: chain knowledge missing at boot balance check")
            .account_balances()
            .get(&TREASURY_ACCOUNT)
            .expect("FATAL: treasury account missing from summary")
            .ironwood_balance()
            .total()
            .into_u64();
        assert!(
            treasury_balance >= MIN_TREASURY_BALANCE,
            "FATAL: Treasury balance {treasury_balance} below minimum {MIN_TREASURY_BALANCE}"
        );
        tracing::info!(
            anchors = anchor_count,
            treasury_balance,
            "boot: genesis sanity checks passed"
        );

        // 6. Price fetch (MTP is now at the tip).
        let price = crate::mint::pricing::fetch_round()
            .await
            .expect("FATAL: initial price fetch failed; restart when exchanges are reachable");
        let oracle = Oracle::new(price);
        tracing::info!(
            usd_per_zec = %price.round_dp(2),
            zats_per_usd = oracle.current().into_u64(),
            "boot: initial price ingested"
        );

        // 6b. Pre-sale table: fail-closed at birth — no table, no start.
        let presale_client = presale::https_client();
        let protected_names = loop {
            match presale::fetch(&presale_client).await {
                Ok(names) => {
                    tracing::info!("boot: pre-sale table fetched");
                    break names;
                }
                Err(error) => {
                    tracing::warn!(%error, "boot: pre-sale table unavailable; retrying");
                }
            }
            tokio::time::sleep(zcash::RETRY_PAUSE).await;
        };

        let name_notes = NameNoteQueue::default();
        let requests = RequestQueue::default();
        let refunds = RefundQueue::default();
        let challenges = OtpQueue::default();
        let market = Market::default();

        // 7. Sapling proving parameters. Loading and hash verification happen
        // before attestation: a mint that produces a report can also prove
        // every transaction shape it is responsible for broadcasting.
        let sapling_spend = load_sapling_spend_params();
        let sapling_output = load_sapling_output_params();

        // 8. Identity. Nothing fallible is acquired after this point.
        //
        // Regtest selects non-tee, so its identity document declares
        // development mode and contains no attestation report.
        let (treasury_address, registry_ufvk) =
            mint_identity(&network, &treasury_keys, &registry_keys);
        #[cfg(not(feature = "non-tee"))]
        let guest = {
            let report_data = identity_report_data(&treasury_address, &registry_ufvk);
            let attestation = get_attestation(&report_data)
                .expect("FATAL: failed to obtain TEE attestation report");
            let parsed =
                zns_canon::attestation::stored(attestation.as_bytes().to_vec(), &report_data)
                    .expect("FATAL: failed to verify TEE identity attestation report");
            let doc = identity_document(
                NETWORK_LABEL,
                &treasury_address,
                &registry_ufvk,
                attestation.as_bytes(),
            );
            // Regenerated every boot. A torn write is a partial file; a
            // consumer accepts the document only after the report binding checks.
            std::fs::write(IDENTITY_DOC_FILE, &doc)
                .expect("FATAL: failed to write identity doc to disk");
            tracing::info!(
                doc_hash = %blake2b_simd::Params::new().hash_length(32).hash(&doc).to_hex(),
                "boot: identity doc written to zns_mint_identity.json"
            );
            GuestInfo {
                measurement: hex::encode(parsed.measurement),
                guest_policy: format!("0x{:x}", parsed.guest_policy),
            }
        };
        #[cfg(feature = "non-tee")]
        {
            let doc = dev_identity_document(NETWORK_LABEL, &treasury_address, &registry_ufvk);
            std::fs::write(IDENTITY_DOC_FILE, &doc)
                .expect("FATAL: failed to write identity doc to disk");
            tracing::info!(
                doc_hash = %blake2b_simd::Params::new().hash_length(32).hash(&doc).to_hex(),
                "boot: DEV identity doc written (no attestation)"
            );
        }

        tracing::info!(
            network = NETWORK_LABEL,
            "boot: complete at tip {}",
            u32::from(wallet.tip().block_height())
        );

        Boot {
            network,
            chain: chain_client,
            source,
            wallet,
            treasury_keys,
            registry_keys,
            sapling_spend,
            sapling_output,
            mtp,
            oracle,
            challenges,
            access_code_key,
            protected_names,
            presale_client,
            fee_rule,
            registry,
            name_notes,
            requests,
            refunds,
            market,
            treasury_address,
            registry_ufvk,
            seed_fingerprint: hex::encode(ceremony_fingerprint),
            capsule_hash: hex::encode(ceremony_capsule_hash),
            #[cfg(not(feature = "non-tee"))]
            guest,
        }
    }
}

// ---------------------------------------------------------------------------
// Step 1: Liveness + connect
// ---------------------------------------------------------------------------

/// Zebra liveness.
async fn connect_zebra() -> ChainClient {
    // JSON-RPC liveness
    let rpc = zcash::JsonRpc::new();
    let info = rpc
        .get_blockchain_info()
        .await
        .expect("FATAL: JSON-RPC getblockchaininfo failed, Zebra is unreachable");
    tracing::info!(
        height = info.blocks,
        hash = %info.bestblockhash,
        "boot: zebra json-rpc liveness ok"
    );

    // gRPC liveness
    let mut chain = ChainClient::connect()
        .await
        .expect("FATAL: Zebra gRPC unreachable or timed out");
    chain
        .chain_tip_change_stream()
        .await
        .expect("FATAL: chain_tip_change gRPC call failed");
    tracing::info!("boot: gRPC chain client connected");

    chain
}

// ---------------------------------------------------------------------------
// Step 2: Seed intake + verification
// ---------------------------------------------------------------------------

fn verify_fingerprint(seed: &Secret<[u8; 32]>, expected: &str) {
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");

    let expected_fp = SeedFingerprint::from_str(expected)
        .unwrap_or_else(|_| panic!("FATAL: invalid seed_fingerprint in {CUSTODY_MANIFEST_FILE}"));

    if actual != expected_fp {
        // Redacted panic: do not print either fingerprint.
        panic!(
            "FATAL: SEED FINGERPRINT MISMATCH — decrypted seed does not match {CUSTODY_MANIFEST_FILE}"
        );
    }
    tracing::info!("boot: seed fingerprint verified");
}

// ---------------------------------------------------------------------------
// Step 3: Initialize (origin checkpoint, subtree roots, wallet, MTP)
// ---------------------------------------------------------------------------

/// Fetches the treestate immediately before the wallet scan window.
/// The checkpoint height must sit at or after every pool's activation —
/// `z_gettreestate` omits pool sections that were never active.
///
/// Zebra is part of the same measured TEE image; its identity is guaranteed
/// by the SEV-SNP attestation, not by runtime RPC checks.
async fn origin_checkpoint(
    birthday: BlockHeight,
    treestate: impl AsyncFnOnce(BlockHeight) -> Result<ChainState, zcash::TransportError>,
) -> ChainState {
    let checkpoint_height = birthday - 1;

    let chain_state = treestate(checkpoint_height)
        .await
        .expect("FATAL: wallet origin treestate unavailable from Zebra");

    tracing::info!(
        "boot: origin checkpoint at height {}, hash {}",
        u32::from(checkpoint_height),
        chain_state.block_hash()
    );

    chain_state
}

// ---------------------------------------------------------------------------
// Step 4: Sapling proving parameters
// ---------------------------------------------------------------------------

/// The BLAKE2b-512 hash of the canonical `sapling-spend.params` file.
const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";

/// The BLAKE2b-512 hash of the canonical `sapling-output.params` file.
const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";

/// Expected file sizes for the Sapling parameter files.
const SAPLING_SPEND_BYTES: u64 = 47_958_396;
const SAPLING_OUTPUT_BYTES: u64 = 3_592_860;

fn sapling_params_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("ZCASH_PARAMS_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    std::path::PathBuf::from(home).join(".zcash-params")
}

fn read_verified_sapling_params(
    path: &std::path::Path,
    expected_hash: &str,
    expected_bytes: u64,
) -> Vec<u8> {
    use std::io::Read;

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        size,
        expected_bytes,
        "Sapling params size mismatch at {}: expected {expected_bytes}, got {size}",
        path.display(),
    );

    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        panic!(
            "FATAL: cannot open Sapling params at {}: {e}",
            path.display()
        )
    });
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes).unwrap_or_else(|e| {
        panic!(
            "FATAL: cannot read Sapling params at {}: {e}",
            path.display()
        )
    });

    let hash_hex = blake2b_simd::blake2b(&bytes).to_hex();
    assert_eq!(
        hash_hex.as_str(),
        expected_hash,
        "Sapling params hash mismatch at {}: expected {expected_hash}, got {hash_hex}",
        path.display(),
    );
    bytes
}

/// Loads and verifies the Sapling spend prover: size, BLAKE2b-512 hash,
/// then upstream's own deserializer.
///
/// `verify_point_encodings: false` is upstream-documented for exactly this
/// pattern: verify the parameters another way, "such as checking the hash of
/// the parameters file on disk" (sapling-crypto 0.7.0, circuit.rs).
fn load_sapling_spend_params() -> SpendParameters {
    let dir = sapling_params_dir();
    let path = dir.join("sapling-spend.params");
    let bytes = read_verified_sapling_params(&path, SAPLING_SPEND_HASH, SAPLING_SPEND_BYTES);
    SpendParameters::read(&bytes[..], false)
        .expect("FATAL: failed to deserialize sapling-spend.params")
}

/// Loads and verifies the Sapling output prover. See
/// [`load_sapling_spend_params`].
fn load_sapling_output_params() -> OutputParameters {
    let dir = sapling_params_dir();
    let path = dir.join("sapling-output.params");
    let bytes = read_verified_sapling_params(&path, SAPLING_OUTPUT_HASH, SAPLING_OUTPUT_BYTES);
    OutputParameters::read(&bytes[..], false)
        .expect("FATAL: failed to deserialize sapling-output.params")
}

// ---------------------------------------------------------------------------
// Step 5: Attestation
// ---------------------------------------------------------------------------

/// The Treasury's published address shape: Orchard and Sapling receivers,
/// never transparent. `SHIELDED` only allows Sapling, and drops it whenever
/// diversifier index 0 is not a valid Sapling diversifier; requiring both
/// takes the first index valid for each.
pub const TREASURY_ADDRESS_REQUEST: zcash_keys::keys::UnifiedAddressRequest = {
    use zcash_keys::keys::ReceiverRequirement::{Omit, Require};
    zcash_keys::keys::UnifiedAddressRequest::unsafe_custom(Require, Require, Omit)
};

/// The mint's public identity: the Treasury's shielded default address and
/// the Registry's UFVK, in exactly the encoded form the attestation binds.
fn mint_identity(
    network: &Network,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
) -> (String, String) {
    let (treasury_addr, _) = treasury_keys
        .fvk()
        .default_address(TREASURY_ADDRESS_REQUEST)
        .expect("FATAL: Treasury FVK missing default address");
    (
        treasury_addr.encode(network),
        registry_keys
            .fvk()
            .encode(network)
            .expect("FATAL: Registry UFVK encoding failed"),
    )
}

/// Constructs the 64-byte attestation report data: BLAKE2b-512 of
/// `treasury_ua || "||" || registry_ufvk`.
///
/// An external verifier checks this against the published Treasury address
/// and Registry UFVK, binding the attestation to the mint's identity.
/// Hardware builds only: `non-tee` builds have no report to bind.
#[cfg(not(feature = "non-tee"))]
fn identity_report_data(treasury_ua: &str, registry_ufvk: &str) -> [u8; 64] {
    let mut hasher = blake2b_simd::State::new();
    hasher.update(treasury_ua.as_bytes());
    hasher.update(b"||");
    hasher.update(registry_ufvk.as_bytes());
    *hasher.finalize().as_array()
}

#[cfg(not(feature = "non-tee"))]
fn identity_document(
    network: &str,
    treasury_ua: &str,
    registry_ufvk: &str,
    report: &[u8],
) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "network": network,
        "mode": "hardware",
        "treasury_ua": treasury_ua,
        "registry_ufvk": registry_ufvk,
        "report": hex::encode(report),
    }))
    .expect("FATAL: identity document serialization")
}

#[cfg(feature = "non-tee")]
fn dev_identity_document(network: &str, treasury_ua: &str, registry_ufvk: &str) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "network": network,
        "mode": "dev",
        "treasury_ua": treasury_ua,
        "registry_ufvk": registry_ufvk,
        "report": null,
    }))
    .expect("FATAL: identity document serialization")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity strings come from the same default-address derivation
    /// the attestation binds: an Orchard and a Sapling receiver, never a
    /// transparent one.
    #[test]
    fn mint_identity_is_shielded_only() {
        let seed = Secret::new([0x42u8; 32]);
        let network = boot_network();
        let treasury_keys = TreasuryKeys::derive(&network, &seed);
        let (treasury_ua, _) = mint_identity(
            &network,
            &treasury_keys,
            &RegistryKeys::derive(&network, &seed),
        );

        let decoded = zcash_keys::address::Address::decode(&network, &treasury_ua)
            .expect("FATAL: identity UA does not decode");
        let ua = match decoded {
            zcash_keys::address::Address::Unified(ua) => ua,
            _ => panic!("FATAL: identity is not a unified address"),
        };
        assert!(
            ua.orchard().is_some(),
            "identity UA lacks an Orchard receiver"
        );
        assert!(
            ua.sapling().is_some(),
            "identity UA lacks a Sapling receiver"
        );
        assert!(
            ua.transparent().is_none(),
            "identity UA carries a transparent receiver"
        );
    }

    /// Different identities bind to different report data — otherwise the
    /// seam would silently accept identity confusion. The fixed vector pins
    /// the exact commitment — algorithm, separator, encoding order — that
    /// external verifiers depend on.
    #[cfg(not(feature = "non-tee"))]
    #[test]
    fn identity_report_data_distinguishes_identities() {
        // Golden vector: the commitment algorithm external verifiers
        // depend on. An accidental change to separator or order lands here.
        assert_eq!(
            hex::encode(identity_report_data("u1treasury", "u1registry")),
            "f730323e01e9a258d3973eaf7bb9a0c734cf9fd3013cd65460811926f63372ecf4e78ba21ff78265157f93a9a9a477539ffce08ca821bcc9cd0e95f2344b311c"
        );
    }

    #[cfg(not(feature = "non-tee"))]
    #[test]
    fn genesis_record_carries_the_anchor_in_display_order() {
        // Non-palindrome vector: pins display vs internal byte order.
        let txid_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let txid = hex::encode(txid_bytes);
        let anchor = CeremonyAnchor {
            network: NETWORK_LABEL.to_string(),
            seed_fingerprint: String::new(),
            txid: TxId::from_hex(&txid).unwrap(),
            file_txid: txid_bytes,
            birthday: 4408922,
        };
        let record = genesis_record(genesis_network(), [0x11; 32], [0x22; 32], &anchor);
        assert_eq!(record.anchor_txid, txid_bytes);
        let document = genesis_document(&record, &anchor, &[7u8; 4]);
        let value: serde_json::Value = serde_json::from_slice(&document).expect("json");
        assert_eq!(value["anchor_txid"], txid);
    }

    #[test]
    fn ceremony_anchor_reads_the_manifest_fields() {
        let txid_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let txid = hex::encode(txid_bytes);
        let anchor = ceremony_anchor(&format!(
            "network = \"testnet\"\nseed_fingerprint = \"zip32seedfp1x\"\nanchor_txid = \"{txid}\"\nbirthday = 4408922\n"
        ));
        assert_eq!(anchor.network, "testnet");
        assert_eq!(anchor.seed_fingerprint, "zip32seedfp1x");
        assert_eq!(anchor.birthday, 4408922);
        assert_eq!(anchor.txid.to_string(), txid);
        #[cfg(not(feature = "non-tee"))]
        assert_eq!(anchor.file_txid, txid_bytes);
    }

    /// A one-transaction block, for anchor-check fixtures.
    fn test_block_with(
        tx: zcash_primitives::transaction::Transaction,
        height: BlockHeight,
    ) -> zcash_primitives::block::Block {
        let header = zcash_primitives::block::BlockHeaderData {
            version: 4,
            prev_block: zcash_primitives::block::BlockHash([0; 32]),
            merkle_root: [0; 32],
            final_sapling_root: [0; 32],
            time: u32::from(height),
            bits: 0,
            nonce: [0; 32],
            solution: vec![],
        }
        .freeze()
        .unwrap();
        zcash_primitives::block::Block::from_parts(header, (tx, Vec::new()).into(), height)
    }

    /// One funding output to the Treasury, frozen into a transaction.
    fn fixture_transaction(network: &Network) -> zcash_primitives::transaction::Transaction {
        let treasury = TreasuryKeys::derive(network, &Secret::new([0; 32]));
        let version = orchard::bundle::BundleVersion::ironwood_v3();
        let mut builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            version,
            version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(
                None,
                treasury
                    .orchard_fvk()
                    .address_at(0u32, zip32::Scope::External),
                orchard::value::NoteValue::from_raw(1),
                [0; 512],
            )
            .unwrap();
        scan_transaction(builder)
    }

    #[tokio::test]
    async fn anchor_check_accepts_the_anchor_mined_at_the_birthday() {
        let network = boot_network();
        let tx = fixture_transaction(&network);
        let txid = tx.txid();
        let block = test_block_with(tx, BlockHeight::from_u32(109));
        require_anchor_on_chain(async |_| Ok(block), BlockHeight::from_u32(109), txid).await;
    }

    #[tokio::test]
    #[should_panic(expected = "is not mined at the manifest birthday")]
    async fn anchor_check_refuses_an_anchor_not_mined_at_the_birthday() {
        let network = boot_network();
        let tx = fixture_transaction(&network);
        let block = test_block_with(tx, BlockHeight::from_u32(109));
        let other = TxId::from_bytes(core::array::from_fn(|i| i as u8 + 1));
        require_anchor_on_chain(async |_| Ok(block), BlockHeight::from_u32(109), other).await;
    }

    #[test]
    #[should_panic(expected = "has no anchor txid")]
    fn ceremony_anchor_refuses_a_missing_txid() {
        ceremony_anchor("network = \"testnet\"\n");
    }

    #[test]
    #[should_panic(expected = "txid is not hex")]
    fn ceremony_anchor_refuses_a_non_hex_txid() {
        ceremony_anchor(
            "network = \"testnet\"\nseed_fingerprint = \"x\"\nanchor_txid = \"zz\"\nbirthday = 1\n",
        );
    }

    #[test]
    #[should_panic(expected = "has no birthday")]
    fn ceremony_anchor_refuses_a_missing_birthday() {
        ceremony_anchor(&format!("anchor_txid = \"{}\"\n", "ab".repeat(32)));
    }

    #[test]
    #[should_panic(expected = "has no network")]
    fn ceremony_anchor_refuses_a_missing_network() {
        ceremony_anchor(&format!(
            "anchor_txid = \"{}\"\nbirthday = 1\nseed_fingerprint = \"x\"\n",
            "ab".repeat(32)
        ));
    }

    #[test]
    #[should_panic(expected = "has no seed fingerprint")]
    fn ceremony_anchor_refuses_a_missing_seed_fingerprint() {
        ceremony_anchor(&format!(
            "anchor_txid = \"{}\"\nbirthday = 1\nnetwork = \"testnet\"\n",
            "ab".repeat(32)
        ));
    }

    #[tokio::test]
    async fn origin_checkpoint_selects_the_scan_boundary() {
        use zcash_primitives::block::BlockHash;

        let birthday = BlockHeight::from_u32(10_000);
        let (checkpoint, first) = (birthday - 1, birthday);

        let origin = origin_checkpoint(birthday, async |height| {
            assert_eq!(height, checkpoint);
            Ok(ChainState::empty(height, BlockHash([0; 32])))
        })
        .await;
        assert_eq!(origin.block_height(), checkpoint);
        assert_eq!(origin.block_height() + 1, first);
    }

    /// Builds encrypted scan fixtures with dummy proofs and signatures.
    fn scan_transaction(
        builder: orchard::builder::Builder,
    ) -> zcash_primitives::transaction::Transaction {
        let (bundle, _) = builder
            .build::<zcash_protocol::value::ZatBalance>(rand::rand_core::UnwrapErr(
                rand::rngs::SysRng,
            ))
            .unwrap()
            .unwrap();
        let proof_size = orchard::Proof::expected_proof_size(bundle.actions().len());
        let bundle = bundle.map_authorization(
            &mut (),
            |_, _, _| [0u8; 64].into(),
            |_, _| {
                orchard::bundle::Authorized::from_parts(
                    orchard::Proof::new(vec![0; proof_size]),
                    [0u8; 64].into(),
                )
            },
        );
        zcash_primitives::transaction::TransactionData::from_parts_v6(
            zcash_protocol::consensus::BranchId::Nu6_3,
            0,
            BlockHeight::from_u32(0),
            None,
            None,
            None,
            Some(bundle),
        )
        .freeze()
        .unwrap()
    }

    #[test]
    #[should_panic(expected = "FATAL: SEED FINGERPRINT MISMATCH")]
    fn verify_fingerprint_mismatch_is_redacted() {
        let seed = Secret::new([0xAB; 32]);
        let wrong_fp = SeedFingerprint::from_seed(&[0xCD; 32]).unwrap().to_string();
        verify_fingerprint(&seed, &wrong_fp);
    }

    #[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
    fn attestation_scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zns-mint-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&dir).expect("scratch dir");
        dir
    }

    #[test]
    #[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
    fn attestation_report_read_returns_the_opened_bytes() {
        let dir = attestation_scratch("report");
        let path = dir.join("report.bin");
        let body = vec![0x5A; ATTESTATION_REPORT_LEN];
        std::fs::write(&path, &body).unwrap();
        assert_eq!(read_attestation_report(&path), body);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
    #[should_panic(expected = "is a symlink")]
    fn attestation_report_symlink_is_refused() {
        let dir = attestation_scratch("symlink");
        let target = dir.join("target.bin");
        let link = dir.join("report.bin");
        std::fs::write(&target, vec![0u8; ATTESTATION_REPORT_LEN]).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let _ = read_attestation_report(&link);
    }

    #[test]
    #[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
    #[should_panic(expected = "is not a regular file")]
    fn attestation_report_directory_is_refused() {
        let dir = attestation_scratch("directory");
        let _ = read_attestation_report(&dir);
    }

    #[test]
    #[cfg(all(not(feature = "regtest"), not(feature = "non-tee")))]
    #[should_panic(expected = "is not a 1184-byte")]
    fn attestation_report_wrong_length_is_refused() {
        let dir = attestation_scratch("length");
        let path = dir.join("report.bin");
        std::fs::write(&path, vec![0u8; ATTESTATION_REPORT_LEN + 1]).unwrap();
        let _ = read_attestation_report(&path);
    }
}
