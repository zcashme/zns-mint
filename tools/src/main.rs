//! ZNS developer tool — 3-of-5 transparent P2SH multisig demo.
//!
//! # Commands
//!
//!   zns-tools keygen
//!       Generate a fresh miner P2PKH key and five multisig participant keys.
//!       Prints WIF private keys, public keys, and the 3-of-5 P2SH address.
//!       Writes the miner address into zebrad.toml automatically.
//!
//!   zns-tools demo-sign
//!       Build a synthetic P2SH spend (fake prevout) and sign it with participants
//!       1, 2, 3 to demonstrate that the 3-of-5 threshold signing code is correct.
//!       Prints the signed v5 transaction as hex.

use std::{env, fs, path::Path};

use blake2b_simd::Params as Blake2bParams;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zcash_address::{ToAddress, ZcashAddress};
use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};
use zcash_script::{
    pattern::check_multisig,
    script::{Code, Component, Evaluable, FromChain},
};
use zcash_transparent::{
    address::{Script, TransparentAddress},
    builder::TransparentBuilder,
    bundle::{Authorized as TrAuthorized, Bundle, OutPoint, TxIn, TxOut},
    sighash::TransparentAuthorizingContext,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// V5 transaction header (nVersion = 5, overwintered flag set).
const V5_HEADER: u32 = 0x8000_0005;
/// V5 version group id (ZIP-225).
const V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
/// Nu6_2 branch ID (for our regtest which activates Nu6_2 at height 22).
const NU6_2_BRANCH_ID: u32 = 0x5437_F330;

const ZEBRAD_TOML: &str = "/Users/jules/ZcashNames/zebra-regtest/zebrad.toml";

// ── BLAKE2b helper ────────────────────────────────────────────────────────────

fn blake2b_256(personal: &[u8; 16]) -> blake2b_simd::State {
    Blake2bParams::new()
        .hash_length(32)
        .personal(personal)
        .to_state()
}

fn hash_finalize(state: blake2b_simd::State) -> [u8; 32] {
    *state
        .finalize()
        .as_bytes()
        .first_chunk::<32>()
        .expect("32-byte output")
}

// ── WIF encoding ─────────────────────────────────────────────────────────────

/// WIF-encode a private key for testnet / regtest (version byte 0xEF, compressed).
fn wif_encode(sk: &SecretKey) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(0xEF);
    payload.extend_from_slice(&sk.secret_bytes());
    payload.push(0x01);
    let h1 = Sha256::digest(&payload);
    let h2 = Sha256::digest(&h1);
    payload.extend_from_slice(&h2[..4]);
    bs58::encode(payload).into_string()
}

/// Decode a WIF private key (testnet, compressed).
fn wif_decode(wif: &str) -> anyhow::Result<SecretKey> {
    let raw = bs58::decode(wif)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("bs58: {e}"))?;
    anyhow::ensure!(raw.len() == 38, "WIF must be 38 bytes, got {}", raw.len());
    anyhow::ensure!(raw[0] == 0xEF, "wrong WIF version byte");
    anyhow::ensure!(raw[33] == 0x01, "expected compressed WIF");
    let checksum = &raw[34..];
    let payload = &raw[..34];
    let h = Sha256::digest(Sha256::digest(payload));
    anyhow::ensure!(&h[..4] == checksum, "WIF checksum mismatch");
    Ok(SecretKey::from_slice(&raw[1..33])?)
}

// ── Address helpers ───────────────────────────────────────────────────────────

fn p2pkh_address(pk: &PublicKey) -> String {
    use zcash_protocol::consensus::NetworkType;
    let compressed = pk.serialize();
    let h160 = zcash_transparent::util::hash160::hash(&compressed);
    ZcashAddress::from_transparent_p2pkh(NetworkType::Test, h160).encode()
}

fn p2sh_address(h160: &[u8; 20]) -> String {
    use zcash_protocol::consensus::NetworkType;
    ZcashAddress::from_transparent_p2sh(NetworkType::Test, *h160).encode()
}

// ── Redeem script ─────────────────────────────────────────────────────────────

fn build_3of5_redeem_script(pks: &[PublicKey; 5]) -> FromChain {
    let pk_bytes: Vec<[u8; 33]> = pks.iter().map(|pk| pk.serialize()).collect();
    let pk_refs: Vec<&[u8]> = pk_bytes.iter().map(|b| b.as_ref()).collect();
    let opcodes =
        check_multisig(3, &pk_refs, false).expect("check_multisig should not fail for valid keys");
    Component(opcodes).weaken()
}

// ── ZIP-244 transparent sighash ───────────────────────────────────────────────
//
// Implemented inline because zcash_primitives exposes the v5 sighash only
// through its full transaction Builder which requires Sapling provers even for
// transparent-only transactions.  The derivation follows ZIP-244 §S.2 exactly.

struct TxSigHasher {
    header_digest: [u8; 32],
    prevouts_digest: [u8; 32],
    amounts_digest: [u8; 32],
    scripts_digest: [u8; 32],
    sequence_digest: [u8; 32],
    outputs_digest: [u8; 32],
    /// (prevout bytes [36], value i64_le [8], script_pubkey serialised, sequence [4])
    /// Stored per-input for the per-input hash step.
    per_input_preimage: Vec<Vec<u8>>,
}

impl TxSigHasher {
    fn new<Auth: zcash_transparent::bundle::Authorization + TransparentAuthorizingContext>(
        bundle: &zcash_transparent::bundle::Bundle<Auth>,
        expiry_height: u32,
    ) -> Self {
        // S.1 header digest
        let header_digest = {
            let mut h = blake2b_256(b"ZTxIdHeadersHash");
            h.update(&V5_HEADER.to_le_bytes());
            h.update(&V5_VERSION_GROUP_ID.to_le_bytes());
            h.update(&NU6_2_BRANCH_ID.to_le_bytes());
            h.update(&0u32.to_le_bytes()); // lock_time
            h.update(&expiry_height.to_le_bytes());
            hash_finalize(h)
        };

        // S.2b prevouts digest
        let prevouts_digest = {
            let mut h = blake2b_256(b"ZTxIdPrevoutHash");
            for txin in &bundle.vin {
                let mut buf = Vec::new();
                txin.prevout().write(&mut buf).unwrap();
                h.update(&buf);
            }
            hash_finalize(h)
        };

        // S.2c amounts digest (sig-specific, not txid)
        let amounts_digest = {
            let mut h = blake2b_256(b"ZTxTrAmountsHash");
            for amount in bundle.authorization.input_amounts() {
                h.update(&amount.to_i64_le_bytes());
            }
            hash_finalize(h)
        };

        // S.2d scriptPubKeys digest (sig-specific)
        let scripts_digest = {
            let mut h = blake2b_256(b"ZTxTrScriptsHash");
            for script in bundle.authorization.input_scriptpubkeys() {
                let mut buf = Vec::new();
                script.write(&mut buf).unwrap();
                h.update(&buf);
            }
            hash_finalize(h)
        };

        // S.2e sequence digest
        let sequence_digest = {
            let mut h = blake2b_256(b"ZTxIdSequencHash");
            for txin in &bundle.vin {
                h.update(&txin.sequence().to_le_bytes());
            }
            hash_finalize(h)
        };

        // S.2f outputs digest
        let outputs_digest = {
            let mut h = blake2b_256(b"ZTxIdOutputsHash");
            for txout in &bundle.vout {
                let mut buf = Vec::new();
                txout.write(&mut buf).unwrap();
                h.update(&buf);
            }
            hash_finalize(h)
        };

        // Pre-compute per-input preimages for the per-input hash (S.2g)
        let amounts = bundle.authorization.input_amounts();
        let script_pubkeys = bundle.authorization.input_scriptpubkeys();
        let per_input_preimage: Vec<Vec<u8>> = bundle
            .vin
            .iter()
            .zip(amounts.iter())
            .zip(script_pubkeys.iter())
            .map(|((txin, amount), spk)| {
                let mut buf = Vec::new();
                txin.prevout().write(&mut buf).unwrap();
                buf.extend_from_slice(&amount.to_i64_le_bytes());
                spk.write(&mut buf).unwrap();
                buf.extend_from_slice(&txin.sequence().to_le_bytes());
                buf
            })
            .collect();

        Self {
            header_digest,
            prevouts_digest,
            amounts_digest,
            scripts_digest,
            sequence_digest,
            outputs_digest,
            per_input_preimage,
        }
    }

    /// Compute the ZIP-244 §S.2 signature hash for input `idx`.
    fn sighash_for(&self, idx: usize) -> [u8; 32] {
        // S.2g: per-input hash
        let txin_digest = {
            let mut h = blake2b_256(b"Zcash___TxInHash");
            h.update(&self.per_input_preimage[idx]);
            hash_finalize(h)
        };

        // S.2: transparent sig digest
        let trans_sig_digest = {
            let mut h = blake2b_256(b"ZTxIdTranspaHash");
            h.update(&[0x01]); // SIGHASH_ALL
            h.update(&self.prevouts_digest);
            h.update(&self.amounts_digest);
            h.update(&self.scripts_digest);
            h.update(&self.sequence_digest);
            h.update(&self.outputs_digest);
            h.update(&txin_digest);
            hash_finalize(h)
        };

        // S.3 empty Sapling + Orchard digests
        let sapling_digest = hash_finalize(blake2b_256(b"ZTxIdSaplingHash"));
        let orchard_digest = hash_finalize(blake2b_256(b"ZTxIdOrchardHash"));

        // Top-level sighash personalisation: "ZcashTxHash_" || branch_id_le
        let mut personal = [0u8; 16];
        personal[..12].copy_from_slice(b"ZcashTxHash_");
        personal[12..].copy_from_slice(&NU6_2_BRANCH_ID.to_le_bytes());

        let mut h = blake2b_256(&personal);
        h.update(&self.header_digest);
        h.update(&trans_sig_digest);
        h.update(&sapling_digest);
        h.update(&orchard_digest);
        hash_finalize(h)
    }
}

// ── Key struct ────────────────────────────────────────────────────────────────

struct KeySet {
    miner_sk: SecretKey,
    miner_pk: PublicKey,
    ms_keys: [(SecretKey, PublicKey); 5],
    redeem_script: FromChain,
    p2sh_h160: [u8; 20],
}

impl KeySet {
    fn generate() -> Self {
        let secp = Secp256k1::new();
        let mut rng = rand::rngs::OsRng;

        let miner_sk = loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if let Ok(sk) = SecretKey::from_slice(&b) {
                break sk;
            }
        };
        let miner_pk = PublicKey::from_secret_key(&secp, &miner_sk);

        let ms_keys: [(SecretKey, PublicKey); 5] = std::array::from_fn(|_| {
            let sk = loop {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                if let Ok(sk) = SecretKey::from_slice(&b) {
                    break sk;
                }
            };
            let pk = PublicKey::from_secret_key(&secp, &sk);
            (sk, pk)
        });

        let pks: [PublicKey; 5] = std::array::from_fn(|i| ms_keys[i].1);
        let redeem_script = build_3of5_redeem_script(&pks);
        let script_bytes = redeem_script.to_bytes();
        let p2sh_h160 = zcash_transparent::util::hash160::hash(&script_bytes);

        Self {
            miner_sk,
            miner_pk,
            ms_keys,
            redeem_script,
            p2sh_h160,
        }
    }

    fn print_keys(&self) {
        println!("═══ MINER KEY (replace zebrad.toml miner_address) ════════════════════════");
        println!("  WIF:     {}", wif_encode(&self.miner_sk));
        println!("  Address: {}", p2pkh_address(&self.miner_pk));
        println!();

        for (i, (sk, pk)) in self.ms_keys.iter().enumerate() {
            println!(
                "═══ MULTISIG PARTICIPANT {} ══════════════════════════════════════════════",
                i + 1
            );
            println!("  WIF:    {}", wif_encode(sk));
            println!("  PubKey: {}", hex::encode(pk.serialize()));
        }
        println!();

        println!("═══ 3-OF-5 P2SH COLD VAULT ══════════════════════════════════════════════");
        println!("  Address:       {}", p2sh_address(&self.p2sh_h160));
        println!(
            "  RedeemScript:  {}",
            hex::encode(self.redeem_script.to_bytes())
        );
        println!();
    }
}

// ── keygen command ────────────────────────────────────────────────────────────

fn cmd_keygen() -> anyhow::Result<()> {
    let keys = KeySet::generate();
    keys.print_keys();

    let miner_addr = p2pkh_address(&keys.miner_pk);
    update_zebrad_toml(&miner_addr)?;
    println!("✓  Updated zebrad.toml miner_address = \"{}\"", miner_addr);
    println!();
    println!("Next steps:");
    println!(
        "  1. Restart zebrad — it will mine new blocks to {}",
        miner_addr
    );
    println!("  2. After 100 confirmations, send ZEC from that address to the P2SH vault");
    println!("  3. Run `zns-tools demo-sign <key1_wif> <key2_wif> <key3_wif> <txid> <vout> <value_zat> <dest_addr>`");
    Ok(())
}

fn update_zebrad_toml(miner_addr: &str) -> anyhow::Result<()> {
    let path = Path::new(ZEBRAD_TOML);
    let content =
        fs::read_to_string(path).map_err(|e| anyhow::anyhow!("read {}: {}", ZEBRAD_TOML, e))?;
    let updated = content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("miner_address") {
                format!("miner_address = \"{}\"", miner_addr)
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, updated + "\n").map_err(|e| anyhow::anyhow!("write {}: {}", ZEBRAD_TOML, e))?;
    Ok(())
}

// ── demo-sign command ─────────────────────────────────────────────────────────
//
// Usage:
//   zns-tools demo-sign \
//     <key1_wif> <key2_wif> <key3_wif> \
//     <txid_hex> <vout> <value_zat> \
//     <dest_addr> <expiry_height>
//
// If txid_hex / vout / value_zat are omitted, a synthetic (fake) prevout is used.

fn cmd_demo_sign(args: &[String]) -> anyhow::Result<()> {
    // ── Argument parsing ──────────────────────────────────────────────────
    let (wif1, wif2, wif3, txid_hex, vout, value_zat, dest_addr, expiry_height) = if args.len() >= 8
    {
        (
            &args[0],
            &args[1],
            &args[2],
            args[3].clone(),
            args[4].parse::<u32>()?,
            args[5].parse::<u64>()?,
            args[6].clone(),
            args[7].parse::<u32>().unwrap_or(100),
        )
    } else if args.len() >= 3 {
        // only keys provided — generate synthetic prevout + dummy dest
        (
            &args[0],
            &args[1],
            &args[2],
            "0".repeat(64),
            0u32,
            50_000u64,
            "".to_owned(),
            100u32,
        )
    } else {
        anyhow::bail!(
            "Usage: zns-tools demo-sign <wif1> <wif2> <wif3> \
                 [<txid_hex> <vout> <value_zat> <dest_addr> [<expiry>]]"
        );
    };

    let secp = Secp256k1::new();

    let sk1 = wif_decode(wif1)?;
    let sk2 = wif_decode(wif2)?;
    let sk3 = wif_decode(wif3)?;

    let pk1 = PublicKey::from_secret_key(&secp, &sk1);
    let pk2 = PublicKey::from_secret_key(&secp, &sk2);
    let pk3 = PublicKey::from_secret_key(&secp, &sk3);

    // We need the full 5-key set to build the redeem script; derive the
    // remaining 2 from deterministic seeds (they hold no signing power here,
    // they are only needed for the address commitment).
    let dummy_bytes: [[u8; 32]; 2] = [
        {
            let mut b = [0u8; 32];
            b[0] = 0xd4;
            b[1] = 0;
            b
        },
        {
            let mut b = [0u8; 32];
            b[0] = 0xd5;
            b[1] = 1;
            b
        },
    ];
    // Validate dummy bytes produce valid keys
    let _dummy1 = SecretKey::from_slice(&dummy_bytes[0])
        .map_err(|_| anyhow::anyhow!("dummy key 1 invalid"))?;
    let _dummy2 = SecretKey::from_slice(&dummy_bytes[1])
        .map_err(|_| anyhow::anyhow!("dummy key 2 invalid"))?;

    println!("Note: demo-sign uses the supplied 3 keys as participants 1-2-3.");
    println!("      Participants 4-5 are fixed dummy keys (not needed to satisfy 3-of-5).");
    println!();

    let pk_dummy1 = PublicKey::from_secret_key(&secp, &_dummy1);
    let pk_dummy2 = PublicKey::from_secret_key(&secp, &_dummy2);

    let pks: [PublicKey; 5] = [pk1, pk2, pk3, pk_dummy1, pk_dummy2];
    let redeem_script = build_3of5_redeem_script(&pks);
    let script_bytes = redeem_script.to_bytes();
    let p2sh_h160 = zcash_transparent::util::hash160::hash(&script_bytes);
    let p2sh_addr_str = p2sh_address(&p2sh_h160);

    println!("P2SH Address (the vault being spent): {}", p2sh_addr_str);

    // ── Build the UTXO being spent ─────────────────────────────────────────
    let mut txid = [0u8; 32];
    if txid_hex.len() == 64 {
        hex::decode_to_slice(&txid_hex, &mut txid)
            .map_err(|e| anyhow::anyhow!("bad txid hex: {e}"))?;
    }
    let outpoint = OutPoint::new(txid, vout);

    let p2sh_script_pubkey: Script = TransparentAddress::ScriptHash(p2sh_h160).script().into();
    let coin = TxOut::new(
        Zatoshis::from_u64(value_zat).map_err(|_| anyhow::anyhow!("value_zat out of range"))?,
        p2sh_script_pubkey,
    );

    // ── Choose the destination ─────────────────────────────────────────────
    let dest: TransparentAddress = if dest_addr.is_empty() {
        // send back to ourselves at a fresh P2PKH (just for the demo)
        let dummy_sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let dummy_pk = PublicKey::from_secret_key(&secp, &dummy_sk);
        let h160 = zcash_transparent::util::hash160::hash(&dummy_pk.serialize());
        TransparentAddress::PublicKeyHash(h160)
    } else {
        parse_transparent_address(&dest_addr)?
    };

    // fee = 1000 zat; send remainder to dest
    let fee_zat = 1_000u64;
    anyhow::ensure!(value_zat > fee_zat, "value_zat must exceed fee of 1000 zat");
    let send_zat = value_zat - fee_zat;

    // ── Transparent transaction builder ───────────────────────────────────
    let mut builder = TransparentBuilder::empty();
    builder
        .add_p2sh_input(redeem_script.clone(), outpoint, coin)
        .map_err(|e| anyhow::anyhow!("add_p2sh_input: {e:?}"))?;
    builder
        .add_output(
            &dest,
            Zatoshis::from_u64(send_zat).map_err(|_| anyhow::anyhow!("send_zat out of range"))?,
        )
        .map_err(|e| anyhow::anyhow!("add_output: {e:?}"))?;

    let bundle = builder
        .build()
        .ok_or_else(|| anyhow::anyhow!("empty bundle"))?;

    // ── Pre-compute ZIP-244 sighash parts ─────────────────────────────────
    let hasher = TxSigHasher::new(&bundle, expiry_height);
    let sighash = hasher.sighash_for(0);
    let msg = secp256k1::Message::from_digest(sighash);

    // ── Sign with keys 1, 2, 3 directly ──────────────────────────────────
    let ecdsa_sig1 = secp.sign_ecdsa(&msg, &sk1);
    let ecdsa_sig2 = secp.sign_ecdsa(&msg, &sk2);
    let ecdsa_sig3 = secp.sign_ecdsa(&msg, &sk3);

    // ── Build scriptSig with correct PUSHDATA encoding ────────────────────
    // zcash_script 0.4.x has a bug: num::serialize(n) for n>=128 returns 2 bytes
    // (script-number encoding) instead of 1 byte (plain unsigned), so push_script
    // emits [0x4C, 0xAD, 0x00, ...] instead of [0x4C, 0xAD, ...] for 173-byte
    // redeem scripts.  We build the scriptSig as raw bytes and put them directly
    // into Script(Vec<u8>) — that is Authorized::ScriptSig — to avoid the bug.
    let mut ssig: Vec<u8> = Vec::new();
    ssig.push(0x00); // OP_0  (CHECKMULTISIG off-by-one dummy arg)
    for ecdsa_sig in [&ecdsa_sig1, &ecdsa_sig2, &ecdsa_sig3] {
        let mut push = ecdsa_sig.serialize_der().to_vec();
        push.push(0x01); // SIGHASH_ALL
                         // DER signatures are 70-72 bytes + 1 SIGHASH byte = 71-73 bytes, all < 0x4C
        ssig.push(push.len() as u8);
        ssig.extend_from_slice(&push);
    }
    let redeem_bytes = redeem_script.to_bytes();
    let rlen = redeem_bytes.len();
    if rlen <= 75 {
        ssig.push(rlen as u8);
    } else if rlen <= 255 {
        ssig.push(0x4C); // OP_PUSHDATA1
        ssig.push(rlen as u8); // correct single unsigned byte length
    } else {
        ssig.push(0x4D); // OP_PUSHDATA2
        ssig.extend_from_slice(&(rlen as u16).to_le_bytes());
    }
    ssig.extend_from_slice(&redeem_bytes);

    // ── Build authorized bundle from raw scriptSig bytes ─────────────────
    let prevout = bundle.vin[0].prevout().clone();
    let vout = bundle.vout.clone();
    let authorized_bundle = Bundle {
        vin: vec![TxIn::<TrAuthorized>::from_parts(
            prevout,
            Script(Code(ssig)),
            u32::MAX,
        )],
        vout,
        authorization: TrAuthorized,
    };

    // ── Wrap in a v5 TransactionData and serialize ─────────────────────────
    let tx_data = TransactionData::<Authorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu6_2,
        0,
        BlockHeight::from_u32(expiry_height),
        Some(authorized_bundle),
        None,
        None,
        None,
    );
    let tx: Transaction = tx_data
        .freeze()
        .map_err(|e| anyhow::anyhow!("freeze: {e}"))?;
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|e| anyhow::anyhow!("serialize: {e}"))?;
    let txid_bytes: [u8; 32] = *tx.txid().as_ref();

    println!();
    println!("═══ SIGNED TRANSACTION ══════════════════════════════════════════════════════");
    println!("  TxId:   {}", hex::encode(txid_bytes));
    println!("  Length: {} bytes", tx_bytes.len());
    println!("  Hex:    {}", hex::encode(&tx_bytes));
    println!();
    println!("Broadcast via lightwalletd gRPC with `zns-tools broadcast <hex>` (TBD).");
    Ok(())
}

/// Very minimal transparent address parser for the demo.
fn parse_transparent_address(s: &str) -> anyhow::Result<TransparentAddress> {
    let za = ZcashAddress::try_from_encoded(s).map_err(|e| anyhow::anyhow!("bad address: {e}"))?;
    za.convert::<TransparentAddress>()
        .map_err(|e| anyhow::anyhow!("not a transparent address: {e:?}"))
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = match args.get(1).map(|s| s.as_str()) {
        Some("keygen") | None => cmd_keygen(),
        Some("demo-sign") => cmd_demo_sign(&args[2..]),
        Some(cmd) => {
            eprintln!("Unknown command: {cmd}");
            eprintln!("Usage: zns-tools <keygen | demo-sign>");
            std::process::exit(1);
        }
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
