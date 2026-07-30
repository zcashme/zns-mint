//! Signing and serialization: proves, signs, and serializes V6 shielded
//! bundles into a broadcastable transaction hex string.
//!
//! This module provides two entry points:
//!
//! - [`assemble_and_sign_transaction`] — the original Registry-only path that
//!   takes a single Ironwood bundle and optional transparent outputs.
//! - [`assemble_v6_transaction`] — a crate-private mixed-pool assembler that
//!   requires at least one Orchard-family shielded bundle and can additionally
//!   carry outputs-only transparent components.
//!
//! Both follow the same ordering as [`zcash_primitives::transaction::Builder`]:
//! every effecting bundle is placed into one unauthorized transaction before
//! computing the shared shielded signature hash, then each bundle is proven and
//! signed over that exact commitment. Sapling is deliberately excluded because
//! a Sapling bundle would require Groth16 prover parameters that are not
//! available inside the attested mint boundary.
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
use crate::registry::transaction::TransparentOutput;
use transparent::builder::{TransparentBuilder, TransparentSigningSet};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

/// The expiry height buffer: 20 blocks (~25 minutes at 75s/block).
const TX_EXPIRY_BUFFER: u32 = 20;

/// The common unsigned bundle type used by this module.
type UnsignedBundle = orchard::Bundle<
    orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
    zcash_protocol::value::ZatBalance,
>;

/// Proves, signs, and serializes a mixed V6 transaction containing at least one
/// Orchard or Ironwood bundle and optional outputs-only transparent components.
///
/// This is the shared assembler used by the Registry for Ironwood-only Name
/// Note transactions and by the Treasury for mixed-pool transactions (e.g.
/// Orchard spend + Ironwood refund output). It follows the same sighash
/// ordering as [`zcash_primitives::transaction::Builder`]: every effecting
/// bundle is placed into one unauthorized transaction before computing the
/// shared shielded signature hash, then each bundle is proven and signed over
/// that exact commitment.
///
/// Returns the transaction ID and the serialized transaction as a hex string.
pub fn assemble_v6_transaction<P: Parameters>(
    network: &P,
    orchard_bundle: Option<UnsignedBundle>,
    ironwood_bundle: Option<UnsignedBundle>,
    treasury_signer: Option<&TreasuryKeys>,
    registry_signer: Option<&RegistryKeys>,
    transparent_outputs: Option<&[TransparentOutput]>,
    target_height: BlockHeight,
) -> Result<(TxId, String), crate::mint::AssemblyError> {
    use orchard::circuit::{ProvingKey, VerifyingKey};
    use rand::rngs::OsRng;
    use std::sync::OnceLock;
    use zcash_primitives::transaction::{
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
        Authorized, TransactionData, Unauthorized,
    };
    use zcash_protocol::consensus::BranchId;

    if orchard_bundle.is_none() && ironwood_bundle.is_none() {
        return Err(crate::mint::AssemblyError::BuilderCreation);
    }

    if !network.is_nu_active(NetworkUpgrade::Nu6_3, target_height) {
        return Err(crate::mint::AssemblyError::Nu63NotActive);
    }

    if orchard_bundle.as_ref().is_some_and(|bundle| {
        bundle.bundle_version() != orchard::bundle::BundleVersion::orchard_v3()
    }) {
        return Err(crate::mint::AssemblyError::WrongVersion);
    }
    if ironwood_bundle.as_ref().is_some_and(|bundle| {
        bundle.bundle_version() != orchard::bundle::BundleVersion::ironwood_v3()
    }) {
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
        orchard_bundle.clone(),
        ironwood_bundle.clone(),
    );

    let txid_parts = unauthed_tx.digest(TxIdDigester);
    let shielded_sig_commitment =
        signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

    // --- Prove and sign each shielded bundle ---
    //
    // The pool role is part of the function's type boundary: only Treasury
    // authority can satisfy Orchard spends, and only Registry authority can
    // satisfy Ironwood spends. Output-only bundles need no real spend key and
    // are completed using the builder's retained dummy authorizing keys.
    let treasury_sak = treasury_signer
        .map(|keys| orchard::keys::SpendAuthorizingKey::from(keys.orchard_spending_key()));
    let registry_sak = registry_signer
        .map(|keys| orchard::keys::SpendAuthorizingKey::from(keys.orchard_spending_key()));
    let mut rng = OsRng;

    let circuit_version = orchard_bundle
        .as_ref()
        .map(|b| b.circuit_version())
        .or_else(|| ironwood_bundle.as_ref().map(|b| b.circuit_version()))
        .ok_or(crate::mint::AssemblyError::BuilderCreation)?;

    if let Some(ref ob) = orchard_bundle {
        if ob.circuit_version() != circuit_version {
            return Err(crate::mint::AssemblyError::CircuitMismatch);
        }
    }
    if let Some(ref ib) = ironwood_bundle {
        if ib.circuit_version() != circuit_version {
            return Err(crate::mint::AssemblyError::CircuitMismatch);
        }
    }

    let pk = PK.get_or_init(|| ProvingKey::build(circuit_version));
    let vk = VK.get_or_init(|| VerifyingKey::build(circuit_version));
    if pk.circuit_version() != circuit_version || vk.circuit_version() != circuit_version {
        return Err(crate::mint::AssemblyError::CircuitMismatch);
    }

    let authorized_orchard = orchard_bundle
        .map(
            |b| -> Result<
                orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
                crate::mint::AssemblyError,
            > {
                let proven = b
                    .create_proof(pk, &mut rng)
                    .map_err(|_| crate::mint::AssemblyError::ProofCreation)?;
                let signing_keys: Vec<_> = treasury_sak.iter().cloned().collect();
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

    let authorized_ironwood = ironwood_bundle
        .map(
            |b| -> Result<
                orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
                crate::mint::AssemblyError,
            > {
                let proven = b
                    .create_proof(pk, &mut rng)
                    .map_err(|_| crate::mint::AssemblyError::ProofCreation)?;
                let signing_keys: Vec<_> = registry_sak.iter().cloned().collect();
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
        authorized_orchard,
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
    let txid = tx.txid();
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|_| crate::mint::AssemblyError::Serialize)?;

    Ok((txid, hex::encode(tx_bytes)))
}

/// Proves, signs, and serializes an assembled Ironwood bundle into a broadcastable
/// v6 transaction hex string.
///
/// This is a convenience wrapper around [`assemble_v6_transaction`] that keeps the
/// original Registry-only call signature. It returns only the serialized hex; callers
/// that need the transaction ID should use [`assemble_v6_transaction`] directly.
pub fn assemble_and_sign_transaction<P: Parameters>(
    network: &P,
    unproven_bundle: UnsignedBundle,
    registry_keys: &RegistryKeys,
    transparent_outputs: Option<&[TransparentOutput]>,
    target_height: BlockHeight,
) -> Result<String, crate::mint::AssemblyError> {
    assemble_v6_transaction(
        network,
        None,
        Some(unproven_bundle),
        None,
        Some(registry_keys),
        transparent_outputs,
        target_height,
    )
    .map(|(_, hex)| hex)
}
