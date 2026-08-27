//! Signing and serialization: proves, signs, and freezes V6 shielded
//! bundles into an authorized [`Transaction`].
//!
//! The single entry point is [`assemble_v6_transaction`] — the shared
//! assembler for every mint transaction, which may carry spends from
//! *multiple* authorities (Treasury and Registry accounts share one seed
//! but hold distinct capabilities) and outputs-only transparent components.
//!
//! Authority is per-spend, not per-pool: the Orchard-family builder signs each
//! action with the spending key that controls it (matched by `ak`), so one
//! Ironwood bundle can settle a Treasury payment spend and a Registry Name
//! Note spend under the same V6 sighash. Least authority is preserved by the
//! callers: each assembly path passes exactly the signers its spends require.
//!
//! Both entry points follow the same ordering as
//! [`zcash_primitives::transaction::Builder`]: every effecting bundle is placed
//! into one unauthorized transaction before computing the shared shielded
//! signature hash, then each bundle is proven and signed over that exact
//! commitment. This hand-rolled assembler handles Ironwood-only transactions
//! (Name Notes, vault sweeps with reserve). Sapling sweeps to the
//! transparent vault go through upstream `propose_send_max_transfer` +
//! `create_proposed_transactions` instead, using the cached Sapling prover
//! loaded by [`sapling_provers`]. Orchard bundles are not accepted: NU6.3
//! disables Orchard cross-address transfers, so users cannot send the Treasury
//! Orchard notes and the mint has no Orchard spend lane.
//!
//! # Transparent bundle design
//!
//! The transparent bundle goes through two phases:
//!
//! 1. **Unauthed** (`Bundle<transparent::builder::Unauthorized>`): constructed
//!    via [`transparent::builder::TransparentBuilder`], placed in the unauthed
//!    `TransactionData<Unauthorized>` for sighash computation.
//! 2. **Authorized** (`Bundle<transparent::bundle::Authorized>`): converted from
//!    the unauthed bundle via [`Bundle::apply_signatures`] after the sighash is
//!    computed. For outputs-only bundles (no transparent inputs), this is a
//!    no-op that re-wraps the same `vout` with the `Authorized` marker.
//!
//! This mirrors the upstream `zcash_primitives::transaction::builder::Builder`
//! pattern and avoids any manual `Bundle` construction or `zcash_script`
//! dependency.

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::key::{RegistryKeys, TreasuryKeys};
use sapling::circuit::{OutputParameters, SpendParameters};
use transparent::address::TransparentAddress;
use transparent::builder::{TransparentBuilder, TransparentSigningSet};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

/// A transparent output for a v6 transaction (e.g. the cold-storage destination
/// of a Treasury auto-sweep). The Treasury UA omits the transparent receiver,
/// so transparent *inputs* are never needed — only outputs.
///
/// Carries a [`TransparentAddress`] (the upstream type) rather than raw script
/// bytes, so [`transparent::builder::TransparentBuilder::add_output`] can be
/// used directly — no `zcash_script` dependency needed.
#[derive(Clone, Debug)]
pub struct TransparentOutput {
    pub address: TransparentAddress,
    pub value: Zatoshis,
}

/// The expiry height buffer: 20 blocks (~25 minutes at 75s/block).
const TX_EXPIRY_BUFFER: u32 = 20;

/// The common unsigned bundle type used by this module.
type UnsignedBundle = orchard::Bundle<
    orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
    zcash_protocol::value::ZatBalance,
>;

/// Proves, signs, and serializes a V6 transaction containing one Ironwood
/// bundle and optional outputs-only transparent components.
///
/// This is the shared assembler used by every mint transaction: Registry Name
/// Note lifecycle (Registry authority only), OTP relays and sweeps (Treasury
/// authority only), and atomic claims (dual authority: one bundle settles the
/// Treasury payment spend and the Registry Name Note under one sighash). It
/// follows the same sighash ordering as
/// [`zcash_primitives::transaction::Builder`]: every effecting bundle is placed
/// into one unauthorized transaction before computing the shared shielded
/// signature hash, then the bundle is proven and signed over that exact
/// commitment.
///
/// Returns the built, authorized transaction. Callers derive the txid via
/// `tx.txid()`; broadcast serialization goes through [`serialize_tx`].
pub fn assemble_v6_transaction<P: Parameters>(
    network: &P,
    ironwood_bundle: UnsignedBundle,
    treasury_signer: Option<&TreasuryKeys>,
    registry_signer: Option<&RegistryKeys>,
    transparent_outputs: Option<&[TransparentOutput]>,
    target_height: BlockHeight,
) -> Result<Transaction, crate::mint::AssemblyError> {
    use orchard::circuit::{ProvingKey, VerifyingKey};
    use rand::rngs::OsRng;
    use std::sync::OnceLock;
    use zcash_primitives::transaction::{
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
        Authorized, TransactionData, Unauthorized,
    };
    use zcash_protocol::consensus::BranchId;

    assert_eq!(
        ironwood_bundle.bundle_version(),
        orchard::bundle::BundleVersion::ironwood_v3(),
        "only ironwood_v3 bundles are constructed by the mint"
    );

    // Cache the proving and verifying keys across calls. The circuit version
    // is PostNu6_3 for ironwood_v3 (and orchard_v3), so a single pair serves
    // all transactions at NU6.3 and later.
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    static VK: OnceLock<VerifyingKey> = OnceLock::new();

    let branch_id = BranchId::for_height(network, target_height);
    let expiry_height = BlockHeight::from_u32(
        u32::from(target_height)
            .checked_add(TX_EXPIRY_BUFFER)
            .expect("target_height + TX_EXPIRY_BUFFER fits in u32"),
    );

    // --- Transparent bundle: phase 1 (unauthed) ---
    //
    // Use `TransparentBuilder` to produce `Bundle<builder::Unauthorized>`,
    // the correct auth type for `TransactionData<Unauthorized>`. The Treasury
    // UA omits the transparent receiver, so there are never transparent inputs
    // — only outputs (auto-sweep to cold storage).
    let transparent_bundle_unauthed = transparent_outputs.and_then(|outputs| {
        if outputs.is_empty() {
            return None;
        }
        let mut builder = TransparentBuilder::empty();
        for o in outputs {
            builder
                .add_output(&o.address, o.value)
                .expect("TransparentAddress is always a valid output");
        }
        builder.build() // Option<Bundle<builder::Unauthorized>>
    });

    // --- Unauthed transaction (for sighash) ---
    //
    // V6 transaction (`from_parts_v6`). Every effecting bundle must be present
    // before the shared shielded signature hash is computed.
    let unauthed_tx: TransactionData<Unauthorized> = TransactionData::from_parts_v6(
        branch_id,
        0, // lock_time
        expiry_height,
        transparent_bundle_unauthed,
        None, // sapling (not supported in the attested boundary)
        None, // orchard (no Orchard spend lane; NU6.3 forbids user Orchard intake)
        Some(ironwood_bundle.clone()),
    );

    let txid_parts = unauthed_tx.digest(TxIdDigester);
    let shielded_sig_commitment =
        signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

    // --- Prove and sign the shielded bundle ---
    //
    // Authority is an explicit per-bundle list: each caller passes exactly the
    // signers its spends require, and the builder's `sign` matches each action
    // to the one key that controls it (by `ak`). Output-only bundles pass no
    // real signing key and are completed using the builder's retained dummy
    // authorizing keys.
    let mut signing_keys: Vec<orchard::keys::SpendAuthorizingKey> = Vec::new();
    if let Some(keys) = treasury_signer {
        signing_keys.push(orchard::keys::SpendAuthorizingKey::from(
            keys.orchard_spending_key(),
        ));
    }
    if let Some(keys) = registry_signer {
        signing_keys.push(orchard::keys::SpendAuthorizingKey::from(
            keys.orchard_spending_key(),
        ));
    }
    let mut rng = OsRng;

    let circuit_version = ironwood_bundle.circuit_version();

    let pk = PK.get_or_init(|| ProvingKey::build(circuit_version));
    let vk = VK.get_or_init(|| VerifyingKey::build(circuit_version));
    assert_eq!(
        pk.circuit_version(),
        circuit_version,
        "proving key built from circuit version"
    );
    assert_eq!(
        vk.circuit_version(),
        circuit_version,
        "verifying key built from circuit version"
    );

    let proven = ironwood_bundle
        .create_proof(pk, &mut rng)
        .map_err(|_| crate::mint::AssemblyError::ProofCreation)?;
    let authorized_ironwood = proven
        .apply_signatures(rng, *shielded_sig_commitment.as_ref(), &signing_keys)
        .map_err(|_| crate::mint::AssemblyError::SigningAuth)?;
    authorized_ironwood
        .verify_proof(vk)
        .map_err(|_| crate::mint::AssemblyError::ProofVerification)?;

    // --- Transparent bundle: phase 2 (authorized) ---
    //
    // Convert `Bundle<builder::Unauthorized>` → `Bundle<bundle::Authorized>`
    // using `apply_signatures`. For outputs-only bundles (no inputs), the
    // signing set is empty and the closure is never called — the conversion
    // just re-wraps the same `vout` with the `Authorized` marker.
    let transparent_bundle_authorized = unauthed_tx.transparent_bundle().map(|b| {
        b.clone()
            .apply_signatures(
                |input| {
                    *signature_hash(
                        &unauthed_tx,
                        &SignableInput::Transparent(input),
                        &txid_parts,
                    )
                    .as_ref()
                },
                &TransparentSigningSet::new(),
            )
            .expect("outputs-only transparent bundle has no inputs to sign")
    });

    // --- Final authorized transaction ---
    let final_tx: TransactionData<Authorized> = TransactionData::from_parts_v6(
        branch_id,
        0,
        expiry_height,
        transparent_bundle_authorized,
        None, // sapling (must match the unauthorized transaction)
        None, // orchard (must match the unauthorized transaction)
        Some(authorized_ironwood),
    );

    // TX-005: authorization data may change across the two phases, but the
    // effecting data committed by the V6 shielded sighash may not. Compare the
    // canonical upstream-generated digests of the exact transaction that will
    // be serialized against the digests used for the shielded sighash. This
    // catches a future bundle, header, or transparent-output mutation before
    // broadcast without relying on the `signature_hash` generic bound (which
    // cannot be satisfied by `TransactionData<Authorized>`).
    let final_txid_parts = final_tx.digest(TxIdDigester);

    let tx_digests_match = final_txid_parts.header_digest.as_bytes()
        == txid_parts.header_digest.as_bytes()
        && final_txid_parts.transparent_digests.as_ref().map(|d| {
            (
                d.prevouts_digest.as_bytes(),
                d.sequence_digest.as_bytes(),
                d.outputs_digest.as_bytes(),
            )
        }) == txid_parts.transparent_digests.as_ref().map(|d| {
            (
                d.prevouts_digest.as_bytes(),
                d.sequence_digest.as_bytes(),
                d.outputs_digest.as_bytes(),
            )
        })
        && final_txid_parts
            .sapling_digest
            .as_ref()
            .map(|h| h.as_bytes())
            == txid_parts.sapling_digest.as_ref().map(|h| h.as_bytes())
        && final_txid_parts
            .orchard_digest
            .as_ref()
            .map(|h| h.as_bytes())
            == txid_parts.orchard_digest.as_ref().map(|h| h.as_bytes())
        && final_txid_parts
            .ironwood_digest
            .as_ref()
            .map(|h| h.as_bytes())
            == txid_parts.ironwood_digest.as_ref().map(|h| h.as_bytes());

    if !tx_digests_match {
        return Err(crate::mint::AssemblyError::SighashMismatch);
    }

    let tx = final_tx
        .freeze()
        .map_err(|_| crate::mint::AssemblyError::Serialize)?;
    Ok(tx)
}

/// Serializes an authorized transaction to broadcastable hex.
pub fn serialize_tx(tx: &Transaction) -> Result<String, crate::mint::AssemblyError> {
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|_| crate::mint::AssemblyError::Serialize)?;
    Ok(hex::encode(tx_bytes))
}

// ---------------------------------------------------------------------------
// Sapling Groth16 proving parameters
// ---------------------------------------------------------------------------

/// The BLAKE2b-512 hash of the canonical `sapling-spend.params` file from the
/// Sapling Powers of Tau ceremony. Same constant as `zcash_proofs`.
const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";

/// The BLAKE2b-512 hash of the canonical `sapling-output.params` file.
const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";

/// Expected file sizes for the Sapling parameter files.
const SAPLING_SPEND_BYTES: u64 = 47_958_396;
const SAPLING_OUTPUT_BYTES: u64 = 3_592_860;

use std::io::Read as _;

/// Reads a Sapling parameter file, verifying its size and BLAKE2b hash
/// against the known ceremony constants before returning the raw bytes.
/// Panics on mismatch (tampered or missing params are a halt condition,
/// not a recoverable error).
fn read_verified_sapling_params(
    path: &std::path::Path,
    expected_hash: &str,
    expected_bytes: u64,
) -> Vec<u8> {
    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        panic!(
            "FATAL: cannot open Sapling params at {}: {e}",
            path.display()
        )
    });

    // Check file size before reading.
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        size,
        expected_bytes,
        "Sapling params size mismatch at {}: expected {expected_bytes}, got {size}",
        path.display(),
    );

    // Read + hash.
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

    // Deserialize with verify_point_encodings=false: the hash already
    // authenticates the file, so redundant point-encoding checks are skipped.
    bytes
}

/// The directory where Sapling parameter files are located.
///
/// Defaults to `$ZCASH_PARAMS_DIR` or `~/.zcash-params`, matching the
/// standard `fetch-params` location. In a TEE deployment the host mounts
/// the params at a known path and sets the env var.
fn sapling_params_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ZCASH_PARAMS_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".zcash-params")
}

/// Lazily loaded, cached Sapling proving parameters.
///
/// `SpendParameters` and `OutputParameters` implement `SpendProver` and
/// `OutputProver` respectively (blanket impls in `sapling-crypto`), so they
/// are passed directly to upstream `create_proposed_transactions`. The
/// relay path (Ironwood-only spend policy) never invokes them; the Sapling
/// vault sweep does.
static SAPLING_PROVERS: OnceLock<(SpendParameters, OutputParameters)> = OnceLock::new();

/// Returns cached references to the Sapling spend and output proving
/// parameters, loading them from disk on first access.
///
/// The parameter files are verified against the canonical ceremony hashes
/// (BLAKE2b-512) before deserialization. A tampered or missing file panics —
/// the mint cannot operate with wrong params, and the hash check is the
/// attestation that binds the loaded params to the ceremony.
///
/// [`SpendParameters`]: sapling::circuit::SpendParameters
/// [`OutputParameters`]: sapling::circuit::OutputParameters
pub(crate) fn sapling_provers() -> (&'static SpendParameters, &'static OutputParameters) {
    let (spend, output) = SAPLING_PROVERS.get_or_init(|| {
        let dir = sapling_params_dir();
        let spend_path = dir.join("sapling-spend.params");
        let output_path = dir.join("sapling-output.params");

        let spend_bytes =
            read_verified_sapling_params(&spend_path, SAPLING_SPEND_HASH, SAPLING_SPEND_BYTES);
        let output_bytes =
            read_verified_sapling_params(&output_path, SAPLING_OUTPUT_HASH, SAPLING_OUTPUT_BYTES);

        let spend_params = SpendParameters::read(&spend_bytes[..], false)
            .expect("FATAL: failed to deserialize sapling-spend.params");
        let output_params = OutputParameters::read(&output_bytes[..], false)
            .expect("FATAL: failed to deserialize sapling-output.params");

        (spend_params, output_params)
    });
    (spend, output)
}
