//! Dev-only fixture: the chain facts `Boot::start()` requires, built the
//! way production builds them. A real Zallet wallet mines and shields
//! coinbase and pays the Treasury's transparent address; the Treasury's
//! own keys — derived from the all-zero seed exactly as boot derives them
//! — then author the 40-anchor Registry ceremony plus their own Ironwood
//! funding. One transaction, one input, the whole ownership flow.
//!
//! Vendored from `zns-integration-tests` `src/ceremony.rs` and `src/tx.rs`
//! at f28fabfb56e4962a7e95283134791fb41c51337c (themselves adapted from
//! zns-keygen's anchor builder), with two deliberate divergences:
//! 1. no coinbase-maturity filter on the Treasury input — the funding
//!    payment is a regular UTXO, not coinbase;
//! 2. no ceremony-tx cache — the funding txid is random, so a cached
//!    ceremony transaction cannot be reproducible across runs.
//!
//! `mod zallet` (with `child`) is vendored from the same rev: the wallet
//! client there is still private to the sibling crate.
//!
//! The `happy_path` test binary drives the mint as a black box through
//! claim → update → release: request memos from a real wallet, the mint's
//! on-chain OTP challenges answered with echo payments, and every
//! successor note verified with `zns-verify`, including the `rcm` chain
//! linkage. The `zns-integration-tests` dep there is process plumbing
//! only (`Zebrad`, `Mint`, the dev ceremony) — every assertion lives in
//! this repo.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use blake2b_simd::Params as Blake2b;
use orchard::builder::{Builder as OrchardBuilder, BundleType};
use orchard::bundle::BundleVersion;
use rand::rngs::OsRng;
use secrecy::Secret;
use serde::Deserialize;
use serde_json::json;
use transparent::builder::{
    SpendInfo, TransparentBuilder, TransparentInputInfo, TransparentSigningSet,
};
use transparent::bundle::OutPoint;
use transparent::keys::{IncomingViewingKey, NonHardenedChildIndex};
use zcash_keys::encoding::encode_transparent_address_p;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::builder::cached_orchard_proving_key;
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_primitives::transaction::fees::transparent::InputSize;
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317;
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{self, Transaction, TransactionData};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::{ZatBalance, Zatoshis};
use zip32::AccountId;

pub use zallet::Zallet;
use zns_integration_tests::Zebrad;

mod child;
mod phases;
mod stack;
mod user;
mod verify;
mod zallet;

pub use phases::{claim, release, update};
pub use stack::Stack;
pub use user::User;
pub use verify::{
    block_txids, challenge_txid, find_verified_name_note, registration_txid,
    registry_commitment_keys, wait_for_verified_name_note, VerifiedNameNote, VECTOR_G_D,
    VECTOR_PK_D,
};

/// Matches `zns-mint::mint::registry::ANCHOR_POOL_SIZE`.
pub const ANCHOR_POOL_SIZE: usize = 40;

/// Matches `zns-mint::mint::MIN_TREASURY_BALANCE` (0.002 ZEC).
pub const MIN_TREASURY_ZATS: u64 = 200_000;

/// Zebra `MIN_TRANSPARENT_COINBASE_MATURITY`.
pub const COINBASE_MATURITY: u32 = 100;

/// NU6.1/6.2/6.3 activate here on regtest; boot's birthday is 100.
pub const NU6_3_ACTIVATION_HEIGHT: u32 = 4;

/// The all-zero seed sealed by the integration fixtures.
pub const DEV_SEED: [u8; 32] = [0u8; 32];

/// One whole-ZEC transparent payment covers 42 ZIP-317 actions plus the
/// 200,000-zat Treasury minimum with orders of magnitude to spare.
pub const TREASURY_PAYMENT_ZATS: u64 = 100_000_000;

/// Same `LocalNetwork` as mint boot's regtest selection.
pub fn regtest_network() -> LocalNetwork {
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

pub fn account_usk(
    network: &LocalNetwork,
    seed: &[u8; 32],
    account: u32,
) -> Result<UnifiedSpendingKey> {
    UnifiedSpendingKey::from_seed(
        network,
        seed,
        AccountId::try_from(account).expect("account 0/1"),
    )
    .map_err(|e| anyhow!("ZIP-32 USK account {account}: {e}"))
}

/// The Treasury's transparent P2PKH (ZIP-32 account 0, j=0 external).
pub fn treasury_taddr(
    network: &LocalNetwork,
    seed: &[u8; 32],
) -> Result<(String, NonHardenedChildIndex)> {
    let usk = account_usk(network, seed, 0)?;
    let (addr, child) = usk
        .transparent()
        .to_account_pubkey()
        .derive_external_ivk()
        .map_err(|e| anyhow!("external IVK: {e}"))?
        .default_address();
    Ok((encode_transparent_address_p(network, &addr), child))
}

/// One entry of zebra's `getaddressutxos` response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressUtxo {
    txid: String,
    output_index: u32,
    satoshis: u64,
    script: String,
}

pub struct Coin {
    pub outpoint: OutPoint,
    pub coin: transparent::bundle::TxOut,
}

/// The Treasury's unspent transparent UTXOs, largest first. No maturity
/// filter: the funding payment is a regular output, spendable on
/// confirmation. `getaddressutxos` is itself the unspent set — zebra's
/// `gettxout` answers null for these non-coinbase outputs, so it is no
/// use as a liveness re-check here (zebra regtest, observed).
pub async fn collect_treasury_utxos(zebra: &Zebrad, taddr: &str) -> Result<Vec<Coin>> {
    let utxos: Vec<AddressUtxo> = serde_json::from_value(
        zebra
            .rpc("getaddressutxos", json!([taddr]))
            .await
            .context("getaddressutxos")?,
    )
    .context("getaddressutxos response")?;

    let mut coins = Vec::new();
    for utxo in utxos {
        let script = hex::decode(&utxo.script).context("script hex")?;
        // Canonical display hex is big-endian; OutPoint wants the
        // internal byte order, so reverse and self-check the round-trip.
        let mut txid: [u8; 32] = hex::decode(&utxo.txid)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| anyhow!("txid length"))?;
        txid.reverse();
        let outpoint = OutPoint::new(txid, utxo.output_index);
        if outpoint.txid().to_string() != utxo.txid {
            bail!(
                "txid round-trip mismatch: {} vs {}",
                outpoint.txid(),
                utxo.txid
            );
        }
        coins.push(Coin {
            outpoint,
            coin: transparent::bundle::TxOut::new(
                Zatoshis::from_u64(utxo.satoshis).context("satoshis range")?,
                transparent::address::Script(zcash_script::script::Code(script)),
            ),
        });
    }
    coins.sort_by_key(|c| std::cmp::Reverse(c.coin.value()));
    Ok(coins)
}

/// Node-side mature-coinbase truth: total value paid to `address` that is
/// spendable under zebra's inclusive rule, `h + 100 <= tip + 1` — the
/// same rule the wallet's `transparent.coinbase.spendable` bucket applies.
pub async fn mature_coinbase_zats(zebra: &Zebrad, address: &str) -> Result<u64> {
    let tip = zebra.tip_height().await?;
    let utxos: Vec<serde_json::Value> = serde_json::from_value(
        zebra
            .rpc("getaddressutxos", json!([address]))
            .await
            .context("getaddressutxos")?,
    )
    .context("getaddressutxos response")?;
    let mut sum = 0u64;
    for utxo in utxos {
        let height = utxo["height"].as_u64().context("utxo height")? as u32;
        if height + COINBASE_MATURITY <= tip + 1 {
            sum += utxo["satoshis"].as_u64().context("utxo satoshis")?;
        }
    }
    Ok(sum)
}

/// Poll until the wallet's scan reaches the node's mature-coinbase truth,
/// so a shield sees every UTXO and not a mid-scan prefix. Status sync is
/// not enough: the balance scan trails the sync engine, and the shield
/// snapshots whatever the wallet has scanned so far.
pub async fn wait_until_sees_coinbase(
    zallet: &Zallet,
    expected_zats: u64,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(balances) = zallet.call("z_getbalances", json!([])).await {
            let seen = balances
                .pointer("/accounts/0/transparent/coinbase/spendable/valueZat")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if seen >= expected_zats {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            bail!("wallet never saw {expected_zats} mature coinbase zats within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Poll until account 0's spendable shielded balance reaches `min_zats`;
/// the wallet's scan of its fresh shielded note trails the confirming
/// block, so the budget is a wait, not an immediate assert.
pub async fn wait_until_shielded(zallet: &Zallet, min_zats: u64, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let have = shielded_spendable_zats(zallet).await?;
        if have >= min_zats {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("wallet never held {min_zats} spendable shielded zats within {timeout:?} (last seen: {have})");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Account 0's spendable shielded balance: `ironwood` plus `orchard`.
/// Ironwood (NU6.3, ZIP 2005) notes are Orchard-shaped, and funds received
/// to an Orchard receiver once NU6.3 is active are reported under
/// `ironwood` — reading `orchard` alone is always zero on this chain.
pub async fn shielded_spendable_zats(zallet: &Zallet) -> Result<u64> {
    let balances = zallet.call("z_getbalanceforaccount", json!([0])).await?;
    let pool = |name: &str| {
        balances
            .pointer(&format!("/pools/{name}/valueZat"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    Ok(pool("ironwood") + pool("orchard"))
}

/// The funding wallet pays the Treasury's transparent address one whole
/// ZEC (no memo: memos are refused to transparent recipients), mines a
/// confirming block, and waits for the UTXO to answer on the node.
pub async fn fund_treasury(zallet: &Zallet, zebra: &Zebrad, taddr: &str) -> Result<()> {
    let amount = TREASURY_PAYMENT_ZATS as f64 / 100_000_000.0;
    let sent = zallet
        .send_from_account(
            "orchard",
            json!([{ "address": taddr, "amount": amount }]),
            "AllowRevealedRecipients",
        )
        .await
        .context("zallet pays treasury")?;
    eprintln!("fixture: treasury funding txid {sent} to {taddr}");
    zebra.generate_blocks(1).await?;

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let coins = collect_treasury_utxos(zebra, taddr).await?;
        if !coins.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let raw = zebra.rpc("getaddressutxos", json!([taddr])).await?;
            bail!("treasury t-addr never showed the funding UTXO: {raw}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

type UnprovenIronwood = orchard::Bundle<
    orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
    ZatBalance,
>;

/// Sign the transparent inputs, prove+sign the Ironwood bundle, freeze a
/// v6 tx. Vendored verbatim from `zns-integration-tests` `src/tx.rs` at
/// f28fabf: one place owns the sign/prove/freeze sequence.
pub fn assemble_v6_transparent_ironwood<P: Parameters>(
    network: &P,
    target: BlockHeight,
    expiry: BlockHeight,
    transparent: Option<transparent::bundle::Bundle<transparent::builder::Unauthorized>>,
    ironwood: UnprovenIronwood,
    signing: &TransparentSigningSet,
) -> Result<Transaction> {
    let branch_id = BranchId::for_height(network, target);

    let unauthed: TransactionData<transaction::Unauthorized> = TransactionData::from_parts_v6(
        branch_id,
        0,
        expiry,
        transparent.clone(),
        None,
        None,
        Some(ironwood.clone()),
    );
    let txid_parts = unauthed.digest(TxIdDigester);

    let transparent = transparent
        .map(|b| {
            b.apply_signatures(
                |index| {
                    *signature_hash(&unauthed, &SignableInput::Transparent(index), &txid_parts)
                        .as_ref()
                },
                signing,
            )
        })
        .transpose()?;

    let bundle_v = bundle_version_for_branch(branch_id, orchard::ValuePool::Ironwood)
        .expect("ironwood bundle implies NU6.3");
    let ironwood = ironwood
        .create_proof(
            cached_orchard_proving_key(bundle_v.circuit_version()),
            &mut OsRng,
        )?
        .prepare(
            OsRng,
            *signature_hash(&unauthed, &SignableInput::Shielded, &txid_parts).as_ref(),
        )
        .finalize()?;

    Ok(TransactionData::from_parts_v6(
        branch_id,
        0,
        expiry,
        transparent,
        None,
        None,
        Some(ironwood),
    )
    .freeze()?)
}

/// The dev ceremony: the Treasury's transparent input becomes 40
/// zero-value Registry Ironwood anchors plus the Treasury's Ironwood
/// funding, paying ZIP-317 fees — authored by the Treasury's own keys.
pub fn build_ceremony_tx(
    network: &LocalNetwork,
    treasury_usk: &UnifiedSpendingKey,
    registry_usk: &UnifiedSpendingKey,
    miner_sk: secp256k1::SecretKey,
    coins: Vec<Coin>,
    target: BlockHeight,
) -> Result<Transaction> {
    let coin = coins
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no treasury inputs"))?;
    let input_value = coin.coin.value();

    let ironwood_actions = ANCHOR_POOL_SIZE + 2;
    let fee = Zip317::standard()
        .fee_required(
            network,
            target,
            std::iter::once(InputSize::STANDARD_P2PKH),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            ironwood_actions,
        )
        .map_err(|e| anyhow!("ZIP-317 fee: {e}"))?;
    if input_value.into_u64() <= fee.into_u64() {
        bail!(
            "treasury input {} zats cannot cover fee {}",
            input_value.into_u64(),
            fee.into_u64()
        );
    }
    let treasury_value = Zatoshis::from_u64(input_value.into_u64() - fee.into_u64())
        .expect("input minus fee is in range");
    if treasury_value.into_u64() < MIN_TREASURY_ZATS {
        bail!(
            "Treasury would be {} zats; mint needs {MIN_TREASURY_ZATS}",
            treasury_value.into_u64()
        );
    }

    let mut signing = TransparentSigningSet::new();
    let pubkey = signing.add_key(miner_sk);
    let mut transparent_builder = TransparentBuilder::empty();
    transparent_builder.add_input(TransparentInputInfo::from_parts(
        coin.outpoint,
        coin.coin,
        SpendInfo::P2pkh { pubkey },
    )?);
    let transparent = transparent_builder.build();

    let mut ironwood_builder = OrchardBuilder::new(
        BundleType::UNPADDED,
        BundleVersion::ironwood_v3(),
        BundleVersion::ironwood_v3().default_flags(),
        orchard::Anchor::empty_tree(),
    )?;
    let registry_fvk = orchard::keys::FullViewingKey::from(registry_usk.orchard());
    let registry_addr = registry_fvk.address_at(0u32, orchard::keys::Scope::External);
    let registry_ovk = registry_fvk.to_ovk(orchard::keys::Scope::External);
    for _ in 0..ANCHOR_POOL_SIZE {
        ironwood_builder.add_output(
            Some(registry_ovk.clone()),
            registry_addr,
            orchard::value::NoteValue::from_raw(0),
            [0; 512],
        )?;
    }
    let treasury_fvk = orchard::keys::FullViewingKey::from(treasury_usk.orchard());
    let treasury_addr = treasury_fvk.address_at(0u32, orchard::keys::Scope::External);
    let treasury_ovk = treasury_fvk.to_ovk(orchard::keys::Scope::External);
    ironwood_builder.add_output(
        Some(treasury_ovk.clone()),
        treasury_addr,
        orchard::value::NoteValue::from_raw(treasury_value.into_u64()),
        [0; 512],
    )?;
    ironwood_builder.add_output(
        Some(treasury_ovk),
        treasury_addr,
        orchard::value::NoteValue::from_raw(0),
        [0; 512],
    )?;
    let (ironwood, _) = ironwood_builder
        .build::<ZatBalance>(&mut OsRng)?
        .expect("ironwood bundle exists");

    assemble_v6_transparent_ironwood(
        network,
        target,
        BlockHeight::from(0),
        transparent,
        ironwood,
        &signing,
    )
}

/// Broadcast the ceremony and mine a confirming block; returns the new
/// tip. Halo2 proving is the long pole — minutes on the 42-action bundle.
pub async fn publish_ceremony(zebra: &Zebrad) -> Result<u32> {
    let network = regtest_network();
    let (taddr, child) = treasury_taddr(&network, &DEV_SEED)?;
    let treasury_usk = account_usk(&network, &DEV_SEED, 0)?;
    let registry_usk = account_usk(&network, &DEV_SEED, 1)?;

    let tip = zebra.tip_height().await?;
    let coins = collect_treasury_utxos(zebra, &taddr).await?;
    if coins.is_empty() {
        bail!("no Treasury UTXO to fund the ceremony");
    }

    let sk = treasury_usk
        .transparent()
        .derive_external_secret_key(child)
        .map_err(|e| anyhow!("derive treasury secret key: {e}"))?;

    let target = BlockHeight::from_u32(tip + 1);
    eprintln!(
        "ceremony: proving {ironwood_actions} Ironwood actions at target {target}",
        ironwood_actions = ANCHOR_POOL_SIZE + 2
    );
    let tx = tokio::task::spawn_blocking(move || {
        build_ceremony_tx(&network, &treasury_usk, &registry_usk, sk, coins, target)
    })
    .await
    .context("ceremony proving task")??;
    eprintln!("ceremony: broadcast {}", tx.txid());

    let mut raw = Vec::new();
    tx.write(&mut raw).context("serialize ceremony tx")?;
    zebra
        .rpc("sendrawtransaction", json!([hex::encode(&raw)]))
        .await
        .map_err(|e| anyhow!("sendrawtransaction ceremony: {e:#}"))?;
    zebra.generate_blocks(1).await?;
    Ok(tip + 1)
}

/// The attested identity strings: the Treasury's default shielded
/// address and the Registry UFVK, both derived from the seed alone.
pub fn mint_identity_strings() -> (String, String) {
    let network = regtest_network();
    let treasury_fvk = account_usk(&network, &DEV_SEED, 0)
        .expect("treasury usk")
        .to_unified_full_viewing_key();
    let registry_fvk = account_usk(&network, &DEV_SEED, 1)
        .expect("registry usk")
        .to_unified_full_viewing_key();
    let (treasury_addr, _) = treasury_fvk
        .default_address(UnifiedAddressRequest::SHIELDED)
        .expect("treasury default address");
    (
        treasury_addr.encode(&network),
        registry_fvk.encode(&network),
    )
}

/// The attested identity: `BLAKE2b-512(treasury default shielded address
/// || "||" || registry UFVK)` — boot's report-data contract, recomputed
/// from the seed alone, the way an external verifier would.
pub fn identity_report_data() -> [u8; 64] {
    let (treasury_addr_str, registry_fvk_str) = mint_identity_strings();

    let mut hasher = Blake2b::new().hash_length(64).to_state();
    hasher.update(treasury_addr_str.as_bytes());
    hasher.update(b"||");
    hasher.update(registry_fvk_str.as_bytes());
    let hash = hasher.finalize();

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(hash.as_bytes());
    report_data
}

/// Seal the all-zero seed under the dev-escape sealing key — the
/// fixture's `keys/zns_seed.capsule`.
pub fn seal_fixture_capsule() -> Result<Vec<u8>> {
    let key = zns_canon::sealing::dev_sealing_key(zns_canon::capsule::CAPSULE_KEY_CONTEXT);
    let capsule = zns_canon::capsule::seal_seed(&key, &Secret::new(DEV_SEED), &mut OsRng)
        .map_err(|e| anyhow!("seal capsule: {e}"))?;
    zns_canon::capsule::serialize_capsule(&capsule).map_err(|e| anyhow!("serialize capsule: {e}"))
}
