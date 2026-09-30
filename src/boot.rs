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
use zcash_protocol::consensus::{BlockHeight, Parameters};
#[cfg(feature = "regtest")]
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;
use zip32::fingerprint::SeedFingerprint;

#[cfg(not(feature = "regtest"))]
use std::str::FromStr;

use crate::mint::mtp::MtpTracker;
use crate::mint::note::NameNoteQueue;
use crate::mint::presale::{self, AccessCodeDerivationKey, ProtectedNames};
use crate::mint::pricing::Oracle;
use crate::mint::registry::Registry;
use crate::mint::treasury::{OtpQueue, RequestQueue};
use crate::mint::{OtpMemo, MIN_TREASURY_BALANCE, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;
use crate::zcash::{self, CanonicalBlockSource, ChainClient};
use sapling::circuit::{OutputParameters, SpendParameters};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::{chain::ChainState, BlockMetadata};
use zns_canon::capsule::{parse_capsule, read_capsule_file, unseal_seed};
use zns_canon::sealing::Tee;

// ---------------------------------------------------------------------------
// Boot life-cycle
// ---------------------------------------------------------------------------

/// The boot product: constructed only after every boot check succeeds.
/// Consumed exactly once by `main`'s exhaustive destructure — the seam
/// contract, one criterion line per field.
pub struct Boot<P: Parameters> {
    /// verified: boot-to-loop consensus — the loop never discovers parameters
    pub network: P,
    /// verified: Registry birth and the run loop's reorg boundary
    pub birthday: BlockHeight,
    /// acquired: boot proved that both Zebra transports are live
    pub chain: ChainClient,
    /// acquired: the node source used during boot sync
    pub source: CanonicalBlockSource,
    /// produced: trees seeded from the verified origin
    pub wallet: Wallet<P>,
    /// produced: the origin cursor the loop extends
    pub cursor: BlockMetadata,
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
    /// boot-initialized faculty: born empty, filled by `main`
    pub challenges: OtpQueue,
    /// TEE-derived access-code key (HMAC purpose key, not the root)
    pub access_code_key: AccessCodeDerivationKey,
    /// must not: fail-closed at birth — the table or no start
    pub protected_names: ProtectedNames,
    /// produced: scanned and verified during boot sync
    pub registry: Registry,
    /// initialized: pending Name Note authorizations
    pub name_notes: NameNoteQueue,
    /// initialized: pending Treasury requests
    pub requests: RequestQueue,
    /// initialized: pending OTP echoes
    pub echoes: Vec<(OtpMemo, Zatoshis, BlockHeight)>,
    /// initialized: no pre-sale refresh is in flight
    pub presale_refresh: Option<tokio::task::JoinHandle<Option<ProtectedNames>>>,
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
        regtest_network()
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

/// Regtest birth: the fixture boundary. NU6.3 activates at height 4;
/// the fixture's coinbase maturity runs through 104; nothing the mint
/// owns is earlier. Mainnet and testnet take the birthday from
/// `keys/zns_mint.conf`.
#[cfg(feature = "regtest")]
const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(100);

/// Keygen's deployment record. The fingerprint is accepted only when the
/// keygen attestation binds it to the capsule bytes. The birthday is the
/// anchor's inclusion height; this report does not cover it.
#[cfg(not(feature = "regtest"))]
#[derive(serde::Deserialize)]
struct MintConfig {
    network: String,
    expected_seed_fingerprint: String,
    birthday: u32,
}

#[cfg(not(feature = "regtest"))]
fn load_mint_config() -> MintConfig {
    let raw = std::fs::read_to_string("keys/zns_mint.conf")
        .expect("FATAL: cannot read keys/zns_mint.conf");
    toml::from_str(&raw).expect("FATAL: invalid keys/zns_mint.conf")
}

#[cfg(feature = "testnet")]
fn require_config_network(config: &MintConfig) {
    assert_eq!(
        config.network, "testnet",
        "FATAL: keys/zns_mint.conf network does not match testnet build"
    );
}

#[cfg(not(any(feature = "testnet", feature = "regtest")))]
fn require_config_network(config: &MintConfig) {
    assert_eq!(
        config.network, "mainnet",
        "FATAL: keys/zns_mint.conf network does not match mainnet build"
    );
}

/// SEV-SNP attestation report length. Any other size is not a report.
#[cfg(not(feature = "regtest"))]
const ATTESTATION_REPORT_LEN: usize = 1184;

/// The boot identity document: written once, at attestation time.
const IDENTITY_DOC_FILE: &str = "zns_mint_identity.json";

/// The conf fingerprint is not an identity pin by itself. The keygen
/// report must carry `BLAKE2b-512(fingerprint ‖ capsule hash)` under the
/// AMD signature before that fingerprint is used.
#[cfg(not(feature = "regtest"))]
fn require_keygen_attestation(capsule_bytes: &[u8], fingerprint: &SeedFingerprint) {
    let capsule_hash = blake2b256(capsule_bytes);
    let expected = zns_canon::attestation::report_data(fingerprint, &capsule_hash);
    let bytes = read_attestation_report(std::path::Path::new("keys/zns_attestation.bin"));
    let _checked = zns_canon::attestation::stored(bytes, &expected);
}

/// One open of the keygen report. The descriptor must be a regular file
/// of [`ATTESTATION_REPORT_LEN`] bytes; that same descriptor is what is read.
#[cfg(not(feature = "regtest"))]
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

fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(bytes)
        .finalize()
        .as_bytes()[..32]
        .try_into()
        .expect("BLAKE2b-256 is 32 bytes")
}

impl Boot<Network> {
    /// Boot sequence for this build's network.
    pub async fn start() -> Self {
        // ring and aws-lc-rs are both linked. Rustls will not choose a
        // process default, and the first HTTPS client panics without one.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let network = boot_network();
        tracing::info!("boot: starting");

        // 1. Liveness + connect: confirm both Zebra transports, get chain client.
        let chain_client = connect_zebra().await;

        // The one node handle: both dialects behind one door, bound to the
        // client this boot proved live.
        let source = CanonicalBlockSource::new(chain_client.clone());

        // Ceremony facts: network, the seed fingerprint, and the birthday.
        // Regtest has no ceremony file; its birthday is the fixture boundary.
        #[cfg(not(feature = "regtest"))]
        let mint_config = load_mint_config();
        #[cfg(not(feature = "regtest"))]
        require_config_network(&mint_config);
        #[cfg(not(feature = "regtest"))]
        let mint_birthday = BlockHeight::from_u32(mint_config.birthday);
        #[cfg(feature = "regtest")]
        let mint_birthday = MINT_BIRTHDAY;

        // 1b. TEE handshake: pick the enclave seam. Production = `RealSnpTee`;
        // `fake-tee` feature = `FakeTee` for off-SNP tests. Capsule AEAD and
        // `report_data` stay real; only the key/report source changes.
        let tee = select_tee();

        // Access-code root from the TEE, then HMAC to the purpose key
        // (`access-code-v1`). Issuers with that purpose key can recompute
        // codes offline; the mint never stores codes in Supabase.
        let access_code_key = {
            let root = tee
                .derive_sealing_key(presale::ACCESS_CODE_KEY_CONTEXT)
                .expect("FATAL: access-code root key unavailable from the TEE");
            AccessCodeDerivationKey::from_private_key(&root)
        };

        // 2. Seed intake + verification: read capsule, require the keygen
        //    attestation to bind its fingerprint, unseal, then derive keys.
        //    The seed lives only inside this block — Secret's Drop wipes it.
        let (treasury_keys, registry_keys) = {
            tracing::info!("boot: reading seed capsule from keys/zns_seed.capsule");
            let blob = read_capsule_file("keys/zns_seed.capsule").expect(
                "FATAL: failed to read keys/zns_seed.capsule. The mint cannot boot without the sealed seed.",
            );
            let capsule = parse_capsule(&blob).expect("FATAL: failed to parse zns_seed.capsule");
            // Config, capsule field, and the attested fingerprint are one
            // value. Unseal then requires that value of the decrypted seed.
            #[cfg(not(feature = "regtest"))]
            {
                let expected =
                    SeedFingerprint::from_str(mint_config.expected_seed_fingerprint.trim())
                        .expect("FATAL: invalid expected_seed_fingerprint in keys/zns_mint.conf");
                if expected.to_bytes() != capsule.fingerprint {
                    panic!("FATAL: capsule fingerprint does not match keys/zns_mint.conf");
                }
                require_keygen_attestation(&blob, &expected);
            }
            tracing::info!("boot: deriving instance-bound sealing key from the TEE");
            let seed = unseal_seed(tee.as_ref(), &capsule)
                .expect("FATAL: failed to unseal seed. Capsule tampering, wrong TEE, or wrong capsule for this instance.");
            #[cfg(not(feature = "regtest"))]
            verify_fingerprint(&seed, mint_config.expected_seed_fingerprint.trim());
            #[cfg(feature = "regtest")]
            verify_fingerprint(&seed, "");
            (
                TreasuryKeys::derive(&network, &seed),
                RegistryKeys::derive(&network, &seed),
            )
        };
        tracing::info!("boot: keys derived (treasury=acct0, registry=acct1); seed wiped");

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
                async move {
                    let (_, _, timestamp) = source.get_block_header(height).await?;
                    Ok::<_, zcash::TransportError>(
                        u32::try_from(timestamp.as_seconds())
                            .expect("Zcash block-header timestamps are u32 seconds"),
                    )
                }
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
            async move {
                let (_, _, timestamp) = source.get_block_header(height).await?;
                Ok::<_, zcash::TransportError>(
                    u32::try_from(timestamp.as_seconds())
                        .expect("Zcash block-header timestamps are u32 seconds"),
                )
            }
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
        let mut cursor = block_metadata(&origin);
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
        while cursor.block_height() < best_height {
            let from_height = cursor.block_height();
            let next_height = from_height + 1;

            let from_state = source
                .chain_state_at(from_height)
                .await
                .expect("FATAL: chain state unavailable during boot sync");
            let block = source
                .get_block(&network, next_height)
                .await
                .expect("FATAL: block unavailable during boot sync");

            let _ = crate::mint::apply_block(
                &network,
                mint_birthday,
                &registry_keys,
                &treasury_keys,
                &from_state,
                block,
                next_height,
                &mut wallet,
                &mut registry,
                &mut mtp,
                &mut cursor,
            );
        }
        tracing::info!(
            height = u32::from(cursor.block_height()),
            "boot: synced to chain tip"
        );

        // 5. Genesis sanity checks. Ceremony adoption has closed. A later
        // Registry spend may leave the live set short.
        require_established_ceremony(&registry);
        let anchor_count = registry.anchor_pool().len();
        // Boot refuses to run with a treasury below MIN_TREASURY_BALANCE.
        // The node's tip is never pushed into the wallet.
        let treasury_balance = wallet
            .get_wallet_summary(ConfirmationsPolicy::MIN)
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
        let mtp_now = mtp.current().expect("MTP complete after sync");
        let today = mtp.current_day().expect("MTP complete after sync");
        let price = crate::mint::pricing::fetch_round()
            .await
            .expect("FATAL: initial price fetch failed; restart when exchanges are reachable");
        let oracle = Oracle::new(price, today, mtp_now);
        tracing::info!(
            usd_per_zec = %price.round_dp(2),
            zats_per_usd = oracle.current().into_u64(),
            "boot: initial price ingested"
        );

        // 6b. Pre-sale table: fail-closed at birth — no table, no start.
        let protected_names = loop {
            if let Some(names) = presale::fetch().await {
                tracing::info!("boot: pre-sale table fetched");
                break names;
            }
            tracing::warn!("boot: pre-sale table unavailable; retrying");
            tokio::time::sleep(crate::zcash::RETRY_PAUSE).await;
        };

        // The challenge memory: empty by construction, filled by the run
        // loop as update/release relays are issued.
        let challenges = OtpQueue::new();
        let name_notes = NameNoteQueue::default();
        let requests = RequestQueue::default();
        let echoes = Vec::new();
        let presale_refresh = None;

        // 7. Sapling proving parameters. Loading and hash verification happen
        // before attestation: a mint that produces a report can also prove
        // every transaction shape it is responsible for broadcasting.
        let sapling_spend = load_sapling_spend_params();
        let sapling_output = load_sapling_output_params();

        // 8. Identity. Nothing fallible is acquired after this point.
        //
        // Regtest does NOT skip attestation: regtest is a local-consensus
        // toggle, not a TEE toggle. `--features fake-tee` (typically with
        // `regtest,fake-tee`) is what substitutes the report source so
        // the mint can produce a report outside SEV-SNP.
        {
            let (treasury_ua, registry_ufvk) =
                mint_identity(&network, &treasury_keys, &registry_keys);
            let report_data = identity_report_data(&treasury_ua, &registry_ufvk);
            let attestation = tee
                .get_attestation(&report_data)
                .expect("FATAL: failed to obtain TEE attestation report");
            let doc = identity_document(
                NETWORK_LABEL,
                &treasury_ua,
                &registry_ufvk,
                attestation.as_bytes(),
            );
            // Regenerated every boot. A torn write is a partial file; a
            // consumer accepts the document only after the report binding checks.
            std::fs::write(IDENTITY_DOC_FILE, &doc)
                .expect("FATAL: failed to write identity doc to disk");
            tracing::info!(
                doc_hash = %hex::encode(blake2b256(&doc)),
                "boot: identity doc written to zns_mint_identity.json"
            );
        }

        tracing::info!(
            network = NETWORK_LABEL,
            "boot: complete at tip {}",
            u32::from(cursor.block_height())
        );

        Boot {
            network,
            birthday: mint_birthday,
            chain: chain_client,
            source,
            cursor,
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
            registry,
            name_notes,
            requests,
            echoes,
            presale_refresh,
        }
    }
}

use crate::wallet::block_metadata;

#[cfg(feature = "regtest")]
fn regtest_network() -> LocalNetwork {
    // Matches the live integration harness (zns-integration-tests
    // `zebra.rs`): every upgrade through NU6 defaults to 1 on regtest;
    // the NU6.x family activates at 4 — ahead of the mint's birthday.
    let one = BlockHeight::from_u32(1);
    let four = BlockHeight::from_u32(4);
    LocalNetwork {
        overwinter: Some(one),
        sapling: Some(one),
        blossom: Some(one),
        heartwood: Some(one),
        canopy: Some(one),
        nu5: Some(one),
        nu6: Some(one),
        nu6_1: Some(four),
        nu6_2: Some(four),
        nu6_3: Some(four),
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

    // gRPC liveness; the tip stream is change-only, so the boot tip comes
    // from the getblockchaininfo answer above.
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

/// Selects the TEE seam for this build: [`zns_canon::sealing::FakeTee`]
/// behind the `fake-tee` feature (dev-only; blocked from release by a
/// `compile_error!` in `crate::lib`), otherwise [`zns_canon::sealing::RealSnpTee`].
///
/// Returned as a boxed trait object because boot doesn't specialise on
/// which TEE it holds — the two capabilities it needs (sealing key,
/// attestation) are exactly what the trait exposes.
fn select_tee() -> Box<dyn Tee> {
    #[cfg(feature = "fake-tee")]
    {
        tracing::warn!(
            "boot: FAKE TEE selected — sealing key and attestation are dev-only; \
             any real verifier rejects this report"
        );
        Box::new(zns_canon::sealing::FakeTee)
    }
    #[cfg(not(feature = "fake-tee"))]
    {
        Box::new(zns_canon::sealing::RealSnpTee)
    }
}

fn verify_fingerprint(seed: &Secret<[u8; 32]>, expected: &str) {
    let actual = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("seed is 32 bytes, within ZIP-32's 32..=252 range");

    #[cfg(feature = "regtest")]
    {
        let _ = expected;
        tracing::warn!(
            "boot: regtest fingerprint = {} (verification skipped)",
            actual
        );
    }

    #[cfg(not(feature = "regtest"))]
    {
        let expected_fp = SeedFingerprint::from_str(expected)
            .expect("FATAL: invalid expected_seed_fingerprint in keys/zns_mint.conf");

        if actual != expected_fp {
            // Redacted panic: do not print either fingerprint.
            panic!(
                "FATAL: SEED FINGERPRINT MISMATCH — decrypted seed does not match keys/zns_mint.conf"
            );
        }
        tracing::info!("boot: seed fingerprint verified");
    }
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
    treestate: impl std::ops::AsyncFnOnce(BlockHeight) -> Result<ChainState, zcash::TransportError>,
) -> ChainState {
    #[cfg(not(feature = "regtest"))]
    let checkpoint_height = birthday - 101;
    #[cfg(feature = "regtest")]
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

    let hash = blake2b_simd::Params::new().hash_length(64).hash(&bytes);
    let hash_hex = hex::encode(hash.as_bytes());
    assert_eq!(
        hash_hex,
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

/// The mint's public identity: the Treasury's shielded default address and
/// the Registry's UFVK, in exactly the encoded form the attestation binds.
fn mint_identity(
    network: &Network,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
) -> (String, String) {
    use zcash_keys::keys::UnifiedAddressRequest;

    let (treasury_addr, _) = treasury_keys
        .fvk()
        .default_address(UnifiedAddressRequest::SHIELDED)
        .expect("FATAL: Treasury FVK missing default address");
    (
        treasury_addr.encode(network),
        registry_keys.fvk().encode(network),
    )
}

/// Constructs the 64-byte attestation report data: BLAKE2b-512 of
/// `treasury_ua || "||" || registry_ufvk`.
///
/// An external verifier checks this against the published Treasury address
/// and Registry UFVK, binding the attestation to the mint's identity.
/// Production code path — not gated on any dev feature, so a `fake-tee`
/// build still binds a real identity into its (unverifiable) report.
fn identity_report_data(treasury_ua: &str, registry_ufvk: &str) -> [u8; 64] {
    let mut hasher = blake2b_simd::Params::new().hash_length(64).to_state();
    hasher.update(treasury_ua.as_bytes());
    hasher.update(b"||");
    hasher.update(registry_ufvk.as_bytes());
    let hash = hasher.finalize();

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(hash.as_bytes());
    report_data
}

/// The boot identity document: the attested identity strings and the
/// hex-encoded 1184-byte SNP report binding them.
fn identity_document(
    network: &str,
    treasury_ua: &str,
    registry_ufvk: &str,
    report: &[u8],
) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "network": network,
        "treasury_ua": treasury_ua,
        "registry_ufvk": registry_ufvk,
        "report": hex::encode(report),
    }))
    .expect("FATAL: identity document serialization")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity strings come from the same SHIELDED default-address
    /// derivation the attestation binds; the Treasury receiver must never
    /// be transparent.
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
            ua.transparent().is_none(),
            "identity UA carries a transparent receiver"
        );
    }

    /// Different identities bind to different report data — otherwise the
    /// seam would silently accept identity confusion. The fixed vector pins
    /// the exact commitment — algorithm, separator, encoding order — that
    /// external verifiers depend on.
    #[test]
    fn identity_report_data_distinguishes_identities() {
        let treasury_ua = "u1treasury";
        let registry_ufvk = "u1registry";
        assert_eq!(
            hex::encode(identity_report_data(treasury_ua, registry_ufvk)),
            "f730323e01e9a258d3973eaf7bb9a0c734cf9fd3013cd65460811926f63372ecf4e78ba21ff78265157f93a9a9a477539ffce08ca821bcc9cd0e95f2344b311c"
        );
        assert_ne!(
            identity_report_data(treasury_ua, registry_ufvk),
            identity_report_data(registry_ufvk, treasury_ua)
        );
    }

    /// The document carries the four contract fields and the report
    /// survives the hex round-trip.
    #[test]
    fn identity_document_round_trips() {
        let report = [7u8; 1184];
        let doc = identity_document("testnet", "u1ua", "u1ufvk", &report);
        let value: serde_json::Value = serde_json::from_slice(&doc).expect("valid JSON");
        assert_eq!(value["network"], "testnet");
        assert_eq!(value["treasury_ua"], "u1ua");
        assert_eq!(value["registry_ufvk"], "u1ufvk");
        let decoded = hex::decode(value["report"].as_str().expect("hex report")).expect("hex");
        assert_eq!(decoded, report);
    }

    #[tokio::test]
    async fn origin_checkpoint_selects_the_scan_boundary() {
        use zcash_primitives::block::BlockHash;

        #[cfg(not(feature = "regtest"))]
        let birthday = BlockHeight::from_u32(10_000);
        #[cfg(feature = "regtest")]
        let birthday = MINT_BIRTHDAY;
        #[cfg(not(feature = "regtest"))]
        let (checkpoint, first) = (birthday - 101, birthday - 100);
        #[cfg(feature = "regtest")]
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
            .build::<zcash_protocol::value::ZatBalance>(rand::rngs::OsRng)
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
    fn birthday_gates_protocol_processing_without_skipping_wallet_history() {
        use std::collections::{BTreeMap, BTreeSet};

        use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
        use incrementalmerkletree::witness::IncrementalWitness;
        use orchard::builder::{Builder, BundleType};
        use orchard::bundle::BundleVersion;
        use orchard::tree::MerkleHashOrchard;
        use orchard::value::NoteValue;
        use zcash_client_backend::data_api::wallet::TargetHeight;
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_primitives::block::{Block, BlockHash, BlockHeaderData};

        use crate::mint::{decrypt_name_notes, Action, Expiry, Name, NameNote, Request, Term};

        let network = boot_network();
        let seed = Secret::new([0; 32]);
        let treasury_keys = TreasuryKeys::derive(&network, &seed);
        let registry_keys = RegistryKeys::derive(&network, &seed);
        let treasury_fvk = treasury_keys.orchard_fvk();
        let registry_fvk = registry_keys.orchard_fvk();
        let first_height = network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
            .unwrap()
            + 100;
        let ceremony_height = first_height + 1;
        let claim_height = ceremony_height + 1;
        let origin = ChainState::empty(first_height - 1, BlockHash([0; 32]));
        let version = BundleVersion::ironwood_v3();
        let builder = |anchor| {
            Builder::new(
                BundleType::DEFAULT,
                version,
                version.default_flags(),
                anchor,
            )
            .unwrap()
        };
        let test_block = |tx, height: BlockHeight, prev_block| {
            let header = BlockHeaderData {
                version: 4,
                prev_block,
                merkle_root: [0; 32],
                final_sapling_root: [0; 32],
                time: u32::from(height),
                bits: 0,
                nonce: [0; 32],
                solution: vec![],
            }
            .freeze()
            .unwrap();
            Block::from_parts(header, (tx, Vec::new()).into(), height)
        };
        let (ua, _) = treasury_keys
            .fvk()
            .default_address(UnifiedAddressRequest::SHIELDED)
            .unwrap();
        let name = Name::parse("alice").unwrap();
        let expected_request = Request::Claim {
            name: name.clone(),
            ua: ua.clone(),
            term: Term::Forever,
            code: None,
        };
        let request_memo = zcash_protocol::memo::MemoBytes::from_bytes(
            format!("ZNS:claim:forever:alice:{}", ua.encode(&network)).as_bytes(),
        )
        .unwrap();

        let mut funding = builder(orchard::Anchor::empty_tree());
        funding
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::from_raw(60_000),
                *request_memo.as_array(),
            )
            .unwrap();
        let funding_tx = scan_transaction(funding);
        let funding_bundle = funding_tx.ironwood_bundle().unwrap();
        let (payment_index, _, payment, _, _) = funding_bundle
            .decrypt_outputs_with_keys(&[treasury_fvk.to_ivk(zip32::Scope::External)])
            .pop()
            .unwrap();
        let payment_nf = payment.nullifier(&treasury_fvk);
        let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let mut witness = None;
        for (index, action) in funding_bundle.actions().iter().enumerate() {
            let leaf = MerkleHashOrchard::from_cmx(action.cmx());
            tree.append(leaf).unwrap();
            if index == payment_index {
                witness = IncrementalWitness::from_tree(tree.clone());
            } else if let Some(witness) = witness.as_mut() {
                witness.append(leaf).unwrap();
            }
        }
        let first_root = tree.root();
        let funding_block = test_block(funding_tx, first_height, origin.block_hash());
        let funded = ChainState::new(
            first_height,
            funding_block.header().hash(),
            Frontier::empty(),
            Frontier::empty(),
            tree.to_frontier(),
        );
        let mut ceremony = builder(tree.root().into());
        ceremony
            .add_spend(
                treasury_fvk.clone(),
                payment,
                witness.unwrap().path().unwrap().into(),
            )
            .unwrap();
        ceremony
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::from_raw(50_000),
                *request_memo.as_array(),
            )
            .unwrap();
        for _ in 0..crate::mint::registry::ANCHOR_POOL_SIZE {
            ceremony
                .add_output(
                    None,
                    registry_fvk.address_at(0u32, zip32::Scope::External),
                    NoteValue::ZERO,
                    [0; 512],
                )
                .unwrap();
        }
        let ceremony_tx = scan_transaction(ceremony);
        let ceremony_txid = ceremony_tx.txid();
        let ceremony_bundle = ceremony_tx.ironwood_bundle().unwrap();
        let anchors = ceremony_bundle
            .decrypt_outputs_with_keys(&[registry_fvk.to_ivk(zip32::Scope::External)]);
        assert_eq!(anchors.len(), crate::mint::registry::ANCHOR_POOL_SIZE);
        let ceremony_pool: BTreeSet<_> = anchors
            .iter()
            .map(|(_, _, note, _, _)| note.nullifier(&registry_fvk))
            .collect();
        let (anchor_index, _, anchor_note, _, _) = anchors[0];
        let anchor_nf = anchor_note.nullifier(&registry_fvk);
        let (fee_index, _, fee_note, _, _) = ceremony_bundle
            .decrypt_outputs_with_keys(&[treasury_fvk.to_ivk(zip32::Scope::External)])
            .pop()
            .unwrap();
        let mut witnesses: BTreeMap<_, IncrementalWitness<MerkleHashOrchard, 32>> = BTreeMap::new();
        for (index, action) in ceremony_bundle.actions().iter().enumerate() {
            let leaf = MerkleHashOrchard::from_cmx(action.cmx());
            tree.append(leaf).unwrap();
            for witness in witnesses.values_mut() {
                witness.append(leaf).unwrap();
            }
            if index == anchor_index || index == fee_index {
                witnesses.insert(index, IncrementalWitness::from_tree(tree.clone()).unwrap());
            }
        }
        let ceremony_root = tree.root();
        let ceremony_block = test_block(ceremony_tx, ceremony_height, funded.block_hash());
        let ceremonied = ChainState::new(
            ceremony_height,
            ceremony_block.header().hash(),
            Frontier::empty(),
            Frontier::empty(),
            tree.to_frontier(),
        );
        let payload = NameNote::Claim {
            name: name.clone(),
            ua,
            expires_at: Expiry::Never,
        };
        let mut claim = builder(tree.root().into());
        for (fvk, note, index) in [
            (registry_fvk.clone(), anchor_note, anchor_index),
            (treasury_fvk.clone(), fee_note, fee_index),
        ] {
            claim
                .add_spend(
                    fvk,
                    note,
                    witnesses.remove(&index).unwrap().path().unwrap().into(),
                )
                .unwrap();
        }
        claim
            .add_zns_output(
                None,
                registry_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::ZERO,
                payload.encode(&network),
                orchard::note::NoteCommitTrapdoor::from_inner(payload.rcm(&network)),
                payload.psi(&network),
            )
            .unwrap();
        claim
            .add_output(
                None,
                registry_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::ZERO,
                [0; 512],
            )
            .unwrap();
        claim
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::Internal),
                NoteValue::from_raw(40_000),
                [0; 512],
            )
            .unwrap();
        let claim_tx = scan_transaction(claim);
        let claim_bundle = claim_tx.ironwood_bundle().unwrap();
        let (_, _, successor, _, _) = claim_bundle
            .decrypt_outputs_with_keys(&[registry_fvk.to_ivk(zip32::Scope::External)])
            .pop()
            .unwrap();
        let successor_nf = successor.nullifier(&registry_fvk);
        for action in claim_bundle.actions().iter() {
            tree.append(MerkleHashOrchard::from_cmx(action.cmx()))
                .unwrap();
        }
        let roots = [first_root, ceremony_root, tree.root()];
        let claim_block = test_block(claim_tx, claim_height, ceremonied.block_hash());
        let candidates = decrypt_name_notes(&network, &claim_block, &registry_keys);
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.payload, payload);
        let mut succeeded_pool = ceremony_pool.clone();
        assert!(succeeded_pool.remove(&anchor_nf));
        assert!(succeeded_pool.insert(successor_nf));
        let blocks = [
            (origin.clone(), funding_block),
            (funded, ceremony_block),
            (ceremonied, claim_block),
        ];

        for birthday in [claim_height + 1, ceremony_height] {
            let mut wallet = Wallet::new(
                [
                    (TREASURY_ACCOUNT, treasury_keys.fvk()),
                    (REGISTRY_ACCOUNT, registry_keys.fvk()),
                ],
                &origin,
                &[],
                &[],
                network,
            )
            .unwrap();
            let mut registry = Registry::new();
            let mut mtp = MtpTracker::default();
            let mut cursor = block_metadata(&origin);
            let mut tree_size = 0;
            for (index, (from_state, block)) in blocks.iter().enumerate() {
                let height = first_height + u32::try_from(index).unwrap();
                tree_size +=
                    u32::try_from(block.vtx()[0].ironwood_bundle().unwrap().actions().len())
                        .unwrap();
                let arrivals = crate::mint::apply_block(
                    &network,
                    birthday,
                    &registry_keys,
                    &treasury_keys,
                    from_state,
                    test_block(block.vtx()[0].clone(), height, from_state.block_hash()),
                    height,
                    &mut wallet,
                    &mut registry,
                    &mut mtp,
                    &mut cursor,
                );
                assert_eq!(cursor.block_height(), height);
                assert_eq!(cursor.block_hash(), block.header().hash());
                assert_eq!(cursor.ironwood_tree_size(), Some(tree_size));
                assert_eq!(
                    wallet.ironwood_anchor(height).unwrap().unwrap(),
                    roots[index].into()
                );
                assert_eq!(
                    mtp.current().unwrap().as_seconds(),
                    i64::from(u32::from(
                        [first_height, ceremony_height, ceremony_height][index]
                    ))
                );
                let tip = TargetHeight::from(height + 1);
                let notes = wallet.unspent_ironwood_notes(TREASURY_ACCOUNT, tip);
                assert_eq!(notes.len(), 1);
                assert_eq!(
                    notes[0].note().value().inner(),
                    [60_000, 50_000, 40_000][index]
                );
                assert_eq!(
                    wallet
                        .unspent_ironwood_note_by_nullifier(TREASURY_ACCOUNT, payment_nf, tip)
                        .is_some(),
                    index == 0,
                );
                assert_eq!(
                    wallet
                        .unspent_ironwood_note_by_nullifier(REGISTRY_ACCOUNT, anchor_nf, tip)
                        .is_some(),
                    index == 1,
                );
                if height < birthday || index == 2 {
                    assert!(arrivals.is_empty());
                } else {
                    assert!(matches!(
                        arrivals.as_slice(),
                        [(txid, crate::mint::MintInbound::Request(request), paid)]
                            if *txid == ceremony_txid && request == &expected_request
                                && paid.into_u64() == 50_000
                    ));
                }
                let expected_pool = match (height >= birthday, index) {
                    (true, 1) => ceremony_pool.clone(),
                    (true, 2) => succeeded_pool.clone(),
                    _ => BTreeSet::new(),
                };
                assert_eq!(registry.anchor_pool(), &expected_pool);
                let stored = wallet.unspent_ironwood_note_by_nullifier(
                    REGISTRY_ACCOUNT,
                    candidate.nullifier,
                    tip,
                );
                if height < birthday || index < 2 {
                    assert!(registry.record(&name).is_none());
                    assert!(registry.record_history(&name).is_empty());
                    assert!(stored.is_none());
                } else {
                    let record = registry.record(&name).unwrap();
                    assert_eq!(record.action, Action::Claim);
                    assert_eq!(record.commitment, payload.commitment(&network));
                    assert_eq!(&record.ua, payload.ua());
                    assert_eq!(record.expires_at, Expiry::Never);
                    assert_eq!(record.confirmed_height, claim_height);
                    assert_eq!(record.predecessor_nullifier, candidate.nullifier);
                    assert_eq!(registry.record_history(&name).len(), 1);
                    let stored = stored.unwrap();
                    assert_eq!(*stored.note(), candidate.note);
                    assert_eq!(
                        wallet.get_memo(*stored.internal_note_id()).unwrap(),
                        Some(zcash_protocol::memo::Memo::Future(
                            zcash_protocol::memo::MemoBytes::from_bytes(&candidate.memo).unwrap()
                        ))
                    );
                    assert_eq!(
                        wallet.witness(&stored, height).unwrap().root(candidate.cmx),
                        roots[index].into()
                    );
                }
            }
        }
    }

    /// A Registry spend leaves the closed pool short. An unbacked Claim's
    /// ordinary output does not refill it, and the boot check accepts
    /// that replayed history.
    #[test]
    fn depleted_pool_excludes_an_unbacked_claim_successor() {
        use std::collections::{BTreeMap, BTreeSet};

        use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
        use incrementalmerkletree::witness::IncrementalWitness;
        use orchard::builder::{Builder, BundleType};
        use orchard::bundle::BundleVersion;
        use orchard::tree::MerkleHashOrchard;
        use orchard::value::NoteValue;
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_primitives::block::{Block, BlockHash, BlockHeaderData};

        use crate::mint::registry::ANCHOR_POOL_SIZE;
        use crate::mint::{decrypt_name_notes, Expiry, Name, NameNote};

        let network = boot_network();
        let seed = Secret::new([0; 32]);
        let treasury_keys = TreasuryKeys::derive(&network, &seed);
        let registry_keys = RegistryKeys::derive(&network, &seed);
        let treasury_fvk = treasury_keys.orchard_fvk();
        let registry_fvk = registry_keys.orchard_fvk();
        let first_height = network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
            .unwrap()
            + 100;
        let ceremony_height = first_height + 1;
        let deplete_height = ceremony_height + 1;
        let unbacked_height = deplete_height + 1;
        let origin = ChainState::empty(first_height - 1, BlockHash([0; 32]));
        let version = BundleVersion::ironwood_v3();
        let builder = |anchor| {
            Builder::new(
                BundleType::DEFAULT,
                version,
                version.default_flags(),
                anchor,
            )
            .unwrap()
        };
        let test_block = |tx, height: BlockHeight, prev_block| {
            let header = BlockHeaderData {
                version: 4,
                prev_block,
                merkle_root: [0; 32],
                final_sapling_root: [0; 32],
                time: u32::from(height),
                bits: 0,
                nonce: [0; 32],
                solution: vec![],
            }
            .freeze()
            .unwrap();
            Block::from_parts(header, (tx, Vec::new()).into(), height)
        };
        let (ua, _) = treasury_keys
            .fvk()
            .default_address(UnifiedAddressRequest::SHIELDED)
            .unwrap();
        let name = Name::parse("alice").unwrap();

        let mut funding = builder(orchard::Anchor::empty_tree());
        funding
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::from_raw(60_000),
                [0; 512],
            )
            .unwrap();
        let funding_tx = scan_transaction(funding);
        let funding_bundle = funding_tx.ironwood_bundle().unwrap();
        let (payment_index, _, payment, _, _) = funding_bundle
            .decrypt_outputs_with_keys(&[treasury_fvk.to_ivk(zip32::Scope::External)])
            .pop()
            .unwrap();
        let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let mut payment_witness = None;
        for (index, action) in funding_bundle.actions().iter().enumerate() {
            let leaf = MerkleHashOrchard::from_cmx(action.cmx());
            tree.append(leaf).unwrap();
            if index == payment_index {
                payment_witness = IncrementalWitness::from_tree(tree.clone());
            } else if let Some(witness) = payment_witness.as_mut() {
                witness.append(leaf).unwrap();
            }
        }
        let funding_block = test_block(funding_tx, first_height, origin.block_hash());
        let funded = ChainState::new(
            first_height,
            funding_block.header().hash(),
            Frontier::empty(),
            Frontier::empty(),
            tree.to_frontier(),
        );

        let mut ceremony = builder(tree.root().into());
        ceremony
            .add_spend(
                treasury_fvk.clone(),
                payment,
                payment_witness.unwrap().path().unwrap().into(),
            )
            .unwrap();
        ceremony
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::from_raw(50_000),
                [0; 512],
            )
            .unwrap();
        for _ in 0..ANCHOR_POOL_SIZE {
            ceremony
                .add_output(
                    None,
                    registry_fvk.address_at(0u32, zip32::Scope::External),
                    NoteValue::ZERO,
                    [0; 512],
                )
                .unwrap();
        }
        let ceremony_tx = scan_transaction(ceremony);
        let ceremony_bundle = ceremony_tx.ironwood_bundle().unwrap();
        let mut anchors = ceremony_bundle
            .decrypt_outputs_with_keys(&[registry_fvk.to_ivk(zip32::Scope::External)]);
        assert_eq!(anchors.len(), ANCHOR_POOL_SIZE);
        let ceremony_pool: BTreeSet<_> = anchors
            .iter()
            .map(|(_, _, note, _, _)| note.nullifier(&registry_fvk))
            .collect();
        let (a0_index, _, a0_note, _, _) = anchors.remove(0);
        let (a1_index, _, a1_note, _, _) = anchors.remove(0);
        let a0_nf = a0_note.nullifier(&registry_fvk);
        let a1_nf = a1_note.nullifier(&registry_fvk);
        let (fee_index, _, fee_note, _, _) = ceremony_bundle
            .decrypt_outputs_with_keys(&[treasury_fvk.to_ivk(zip32::Scope::External)])
            .pop()
            .unwrap();
        let mut anchor_witnesses: BTreeMap<_, IncrementalWitness<MerkleHashOrchard, 32>> =
            BTreeMap::new();
        let mut fee_witness: Option<IncrementalWitness<MerkleHashOrchard, 32>> = None;
        for (index, action) in ceremony_bundle.actions().iter().enumerate() {
            let leaf = MerkleHashOrchard::from_cmx(action.cmx());
            tree.append(leaf).unwrap();
            for witness in anchor_witnesses.values_mut() {
                witness.append(leaf).unwrap();
            }
            if let Some(witness) = fee_witness.as_mut() {
                witness.append(leaf).unwrap();
            }
            let tracked = IncrementalWitness::from_tree(tree.clone()).unwrap();
            if index == a0_index || index == a1_index {
                anchor_witnesses.insert(index, tracked);
            } else if index == fee_index {
                fee_witness = Some(tracked);
            }
        }
        let ceremony_block = test_block(ceremony_tx, ceremony_height, funded.block_hash());
        let ceremonied = ChainState::new(
            ceremony_height,
            ceremony_block.header().hash(),
            Frontier::empty(),
            Frontier::empty(),
            tree.to_frontier(),
        );

        let mut deplete = builder(tree.root().into());
        for (index, note) in [(a0_index, a0_note), (a1_index, a1_note)] {
            deplete
                .add_spend(
                    registry_fvk.clone(),
                    note,
                    anchor_witnesses
                        .remove(&index)
                        .unwrap()
                        .path()
                        .unwrap()
                        .into(),
                )
                .unwrap();
        }
        let deplete_tx = scan_transaction(deplete);
        let deplete_bundle = deplete_tx.ironwood_bundle().unwrap();
        let mut fee_witness = fee_witness.unwrap();
        for action in deplete_bundle.actions().iter() {
            let leaf = MerkleHashOrchard::from_cmx(action.cmx());
            tree.append(leaf).unwrap();
            fee_witness.append(leaf).unwrap();
        }
        let deplete_block = test_block(deplete_tx, deplete_height, ceremonied.block_hash());
        let depleted = ChainState::new(
            deplete_height,
            deplete_block.header().hash(),
            Frontier::empty(),
            Frontier::empty(),
            tree.to_frontier(),
        );

        let payload = NameNote::Claim {
            name: name.clone(),
            ua,
            expires_at: Expiry::Never,
        };
        let mut unbacked = builder(tree.root().into());
        unbacked
            .add_spend(
                treasury_fvk.clone(),
                fee_note,
                fee_witness.path().unwrap().into(),
            )
            .unwrap();
        unbacked
            .add_zns_output(
                None,
                registry_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::ZERO,
                payload.encode(&network),
                orchard::note::NoteCommitTrapdoor::from_inner(payload.rcm(&network)),
                payload.psi(&network),
            )
            .unwrap();
        unbacked
            .add_output(
                None,
                registry_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::ZERO,
                [0; 512],
            )
            .unwrap();
        unbacked
            .add_output(
                None,
                treasury_fvk.address_at(0u32, zip32::Scope::External),
                NoteValue::from_raw(40_000),
                [0; 512],
            )
            .unwrap();
        let unbacked_tx = scan_transaction(unbacked);
        let unbacked_bundle = unbacked_tx.ironwood_bundle().unwrap();
        let registry_outs = unbacked_bundle
            .decrypt_outputs_with_keys(&[registry_fvk.to_ivk(zip32::Scope::External)]);
        assert_eq!(registry_outs.len(), 1);
        let (_, _, successor, _, _) = registry_outs.into_iter().next().unwrap();
        let successor_nf = successor.nullifier(&registry_fvk);
        let unbacked_block = test_block(unbacked_tx, unbacked_height, depleted.block_hash());
        assert_eq!(
            decrypt_name_notes(&network, &unbacked_block, &registry_keys).len(),
            1
        );

        let mut wallet = Wallet::new(
            [
                (TREASURY_ACCOUNT, treasury_keys.fvk()),
                (REGISTRY_ACCOUNT, registry_keys.fvk()),
            ],
            &origin,
            &[],
            &[],
            network,
        )
        .unwrap();
        let mut registry = Registry::new();
        let mut mtp = MtpTracker::default();
        let mut cursor = block_metadata(&origin);
        let mut expected = BTreeSet::new();
        for (height, from_state, block) in [
            (first_height, &origin, &funding_block),
            (ceremony_height, &funded, &ceremony_block),
            (deplete_height, &ceremonied, &deplete_block),
            (unbacked_height, &depleted, &unbacked_block),
        ] {
            crate::mint::apply_block(
                &network,
                ceremony_height,
                &registry_keys,
                &treasury_keys,
                from_state,
                test_block(block.vtx()[0].clone(), height, from_state.block_hash()),
                height,
                &mut wallet,
                &mut registry,
                &mut mtp,
                &mut cursor,
            );
            if height == ceremony_height {
                expected = ceremony_pool.clone();
                assert!(registry.anchor_adoption_closed());
            } else if height == deplete_height {
                expected.remove(&a0_nf);
                expected.remove(&a1_nf);
                assert!(registry.anchor_adoption_closed());
            } else if height == unbacked_height {
                assert!(registry.anchor_adoption_closed());
                assert!(!registry.anchor_pool().contains(&successor_nf));
                assert!(registry.record(&name).is_none());
            }
            assert_eq!(registry.anchor_pool(), &expected);
        }
        require_established_ceremony(&registry);
        assert_eq!(registry.anchor_pool().len(), ANCHOR_POOL_SIZE - 2);
    }

    #[test]
    #[cfg(not(feature = "regtest"))]
    #[should_panic(expected = "FATAL: SEED FINGERPRINT MISMATCH")]
    fn verify_fingerprint_mismatch_is_redacted() {
        use secrecy::Secret;
        let seed = Secret::new([0xAB; 32]);
        let wrong_fp = SeedFingerprint::from_seed(&[0xCD; 32]).unwrap().to_string();
        verify_fingerprint(&seed, &wrong_fp);
    }

    #[cfg(feature = "regtest")]
    #[test]
    fn regtest_parameters_match_the_pinned_harness_schedule() {
        use zcash_protocol::consensus::NetworkUpgrade;

        let network = regtest_network();
        let one = BlockHeight::from_u32(1);
        let four = BlockHeight::from_u32(4);

        assert_eq!(
            network.network_type(),
            zcash_protocol::consensus::NetworkType::Regtest
        );
        for upgrade in [
            NetworkUpgrade::Overwinter,
            NetworkUpgrade::Sapling,
            NetworkUpgrade::Blossom,
            NetworkUpgrade::Heartwood,
            NetworkUpgrade::Canopy,
            NetworkUpgrade::Nu5,
            NetworkUpgrade::Nu6,
        ] {
            assert_eq!(network.activation_height(upgrade), Some(one));
        }
        for upgrade in [
            NetworkUpgrade::Nu6_1,
            NetworkUpgrade::Nu6_2,
            NetworkUpgrade::Nu6_3,
        ] {
            assert_eq!(network.activation_height(upgrade), Some(four));
        }
        // The regtest birthday sits past the NU6.3 activation and the
        // fixture's coinbase-maturity boilerplate: the wallet's history
        // begins at the fixture boundary.
        assert_eq!(MINT_BIRTHDAY, BlockHeight::from_u32(100));
    }

    #[cfg(not(feature = "regtest"))]
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
    #[cfg(not(feature = "regtest"))]
    fn attestation_report_read_returns_the_opened_bytes() {
        let dir = attestation_scratch("report");
        let path = dir.join("report.bin");
        let body = vec![0x5A; ATTESTATION_REPORT_LEN];
        std::fs::write(&path, &body).unwrap();
        assert_eq!(read_attestation_report(&path), body);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(not(feature = "regtest"))]
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
    #[cfg(not(feature = "regtest"))]
    #[should_panic(expected = "is not a regular file")]
    fn attestation_report_directory_is_refused() {
        let dir = attestation_scratch("directory");
        let _ = read_attestation_report(&dir);
    }

    #[test]
    #[cfg(not(feature = "regtest"))]
    #[should_panic(expected = "is not a 1184-byte")]
    fn attestation_report_wrong_length_is_refused() {
        let dir = attestation_scratch("length");
        let path = dir.join("report.bin");
        std::fs::write(&path, vec![0u8; ATTESTATION_REPORT_LEN + 1]).unwrap();
        let _ = read_attestation_report(&path);
    }
}
