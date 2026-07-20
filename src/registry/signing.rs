//! Signing and serialization: proves, signs, and serializes an assembled
//! Ironwood bundle into a broadcastable v6 transaction hex string.
//!
//! Optionally accepts a pre-proven, pre-signed Sapling bundle and/or
//! transparent outputs for cross-pool transactions (e.g. auto-sweep: Ironwood
//! spend + transparent output). The Ironwood bundle is proven and signed here;
//! the Sapling bundle must be proven and signed by the caller (it uses a
//! different proving system — Groth16 — and different signing keys).
//!
//! # Transaction version
//!
//! At NU6.3, transactions are V6 (`TxVersion::V6`). The Ironwood bundle goes
//! in the `ironwood_bundle` field of [`TransactionData`]; the `orchard_bundle`
//! field is `None`. The transaction is assembled via [`from_parts_v6`], which
//! omits `TxVersion` (always V6) and `sprout_bundle` (V6 has no sprout).
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

use crate::registry::transaction::TransparentOutput;
use transparent::builder::{TransparentBuilder, TransparentSigningSet};
use zcash_protocol::consensus::BlockHeight;

/// The expiry height buffer: 20 blocks (~25 minutes at 75s/block).
const TX_EXPIRY_BUFFER: u32 = 20;

/// Proves, signs, and serializes an assembled Ironwood bundle into a broadcastable
/// v6 transaction hex string.
///
/// # Proving key cache
///
/// `ProvingKey::build()` takes ~2 minutes. Both the `ProvingKey` and
/// `VerifyingKey` are cached in `OnceLock` statics so the first call pays the
/// cost and all subsequent calls reuse the cached keys. The circuit version
/// is `PostNu6_3` for both `ironwood_v3` and `orchard_v3` bundles, so a single
/// key pair serves all transactions at NU6.3 and later.
///
/// # Pre-broadcast verification
///
/// After proving and signing, the Ironwood proof is verified against the cached
/// `VerifyingKey` before serialization. This catches a malformed proof (from a
/// builder bug, fork divergence, or hardware fault) before the transaction
/// hits the network.
///
/// # Expiry height
///
/// Per ZIP-225, a non-coinbase transaction's `expiry_height` must be set to a
/// future block height. We use `target_height + 20` (~25 minutes at 75s/block).
pub fn assemble_and_sign_transaction(
    unproven_bundle: orchard::Bundle<
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
        zcash_protocol::value::ZatBalance,
    >,
    orchard_spending_key: &orchard::keys::SpendingKey,
    sapling_bundle: Option<
        sapling::Bundle<sapling::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    >,
    transparent_outputs: Option<&[TransparentOutput]>,
    target_height: BlockHeight,
) -> Result<String, &'static str> {
    use orchard::circuit::{ProvingKey, VerifyingKey};
    use rand::rngs::OsRng;
    use std::sync::OnceLock;
    use zcash_primitives::transaction::{
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
        Authorized, TransactionData, Unauthorized,
    };
    use zcash_protocol::consensus::BranchId;

    // Cache the proving and verifying keys across calls. The circuit version
    // is PostNu6_3 for ironwood_v3 (and orchard_v3), so a single pair serves
    // all transactions at NU6.3 and later.
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    static VK: OnceLock<VerifyingKey> = OnceLock::new();

    let branch_id = BranchId::for_height(&zcash_protocol::consensus::MAIN_NETWORK, target_height);
    let expiry_height = BlockHeight::from_u32(u32::from(target_height) + TX_EXPIRY_BUFFER);

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
    // V6 transaction (`from_parts_v6`). The Ironwood bundle goes in
    // `ironwood_bundle`; `orchard_bundle` is `None`. The Sapling bundle is
    // omitted here — an `Authorized` Sapling bundle cannot be placed in an
    // `Unauthorized` transaction. The shielded sighash does not commit to
    // Sapling authorization data, so omitting it from the unauthed tx is
    // correct.
    let unauthed_tx: TransactionData<Unauthorized> = TransactionData::from_parts_v6(
        branch_id,
        0, // lock_time
        expiry_height,
        transparent_bundle_unauthed,
        None,                          // sapling (see comment above)
        None,                          // orchard (Name Notes are Ironwood)
        Some(unproven_bundle.clone()), // ironwood
    );

    let txid_parts = unauthed_tx.digest(TxIdDigester);
    let shielded_sig_commitment =
        signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

    // --- Ironwood: prove + sign ---
    let circuit_version = unproven_bundle.circuit_version();
    let pk = PK.get_or_init(|| ProvingKey::build(circuit_version));
    let vk = VK.get_or_init(|| VerifyingKey::build(circuit_version));

    let mut rng = OsRng;
    let proven_bundle = unproven_bundle
        .create_proof(pk, &mut rng)
        .map_err(|_| "failed to create ironwood proof")?;

    let sak = orchard::keys::SpendAuthorizingKey::from(orchard_spending_key);

    let authorized_ironwood = proven_bundle
        .apply_signatures(rng, *shielded_sig_commitment.as_ref(), &[sak])
        .map_err(|_| "failed to apply ironwood signatures")?;

    // Pre-broadcast self-verification: verify the Ironwood proof against the
    // verifying key before serialization. Catches a malformed proof (builder
    // bug, fork divergence, hardware fault) before the transaction hits the
    // network.
    authorized_ironwood
        .verify_proof(vk)
        .map_err(|_| "ironwood proof verification failed before broadcast")?;

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
        sapling_bundle,
        None, // orchard (Name Notes are Ironwood)
        Some(authorized_ironwood),
    );

    let tx = final_tx
        .freeze()
        .map_err(|_| "failed to freeze transaction")?;
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|_| "failed to serialize tx")?;

    Ok(hex::encode(tx_bytes))
}
