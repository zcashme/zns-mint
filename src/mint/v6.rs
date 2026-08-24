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
//! commitment. Sapling is deliberately excluded because a Sapling bundle would
//! require Groth16 prover parameters that are not available inside the attested
//! mint boundary. Orchard bundles are not accepted: NU6.3 disables Orchard
//! cross-address transfers, so users cannot send the Treasury Orchard notes
//! and the mint has no Orchard spend lane.
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

use crate::key::{RegistryKeys, TreasuryKeys};
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
    ironwood_bundle: Option<UnsignedBundle>,
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

    let Some(ref ironwood) = ironwood_bundle else {
        return Err(crate::mint::AssemblyError::BuilderCreation);
    };

    if ironwood.bundle_version() != orchard::bundle::BundleVersion::ironwood_v3() {
        return Err(crate::mint::AssemblyError::WrongVersion);
    }

    // Cache the proving and verifying keys across calls. The circuit version
    // is PostNu6_3 for ironwood_v3 (and orchard_v3), so a single pair serves
    // all transactions at NU6.3 and later.
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    static VK: OnceLock<VerifyingKey> = OnceLock::new();

    let branch_id = BranchId::for_height(network, target_height);
    let expiry_height = BlockHeight::from_u32(
        u32::from(target_height)
            .checked_add(TX_EXPIRY_BUFFER)
            .ok_or(crate::mint::AssemblyError::ValueOverflow)?,
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
        ironwood_bundle.clone(),
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

    let circuit_version = ironwood_bundle
        .as_ref()
        .map(|b| b.circuit_version())
        .ok_or(crate::mint::AssemblyError::BuilderCreation)?;

    let pk = PK.get_or_init(|| ProvingKey::build(circuit_version));
    let vk = VK.get_or_init(|| VerifyingKey::build(circuit_version));
    if pk.circuit_version() != circuit_version || vk.circuit_version() != circuit_version {
        return Err(crate::mint::AssemblyError::CircuitMismatch);
    }

    let authorized_ironwood = ironwood_bundle
        .map(
            |b| -> Result<
                orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
                crate::mint::AssemblyError,
            > {
                let proven = b
                    .create_proof(pk, &mut rng)
                    .map_err(|_| crate::mint::AssemblyError::ProofCreation)?;
                let authorized = proven
                    .apply_signatures(rng, *shielded_sig_commitment.as_ref(), &signing_keys)
                    .map_err(|_| crate::mint::AssemblyError::SigningAuth)?;
                authorized
                    .verify_proof(vk)
                    .map_err(|_| crate::mint::AssemblyError::ProofVerification)?;
                Ok(authorized)
            },
        )
        .transpose()?;

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
        authorized_ironwood,
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
