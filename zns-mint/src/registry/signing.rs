//! Signing and serialization: proves, signs, and serializes an assembled
//! Orchard bundle into a broadcastable v5 transaction hex string.
//!
//! Optionally accepts a pre-proven, pre-signed Sapling bundle and/or
//! transparent outputs for cross-pool transactions (e.g. auto-sweep: Orchard
//! spend + transparent output). The Orchard bundle is proven and signed here;
//! the Sapling bundle must be proven and signed by the caller (it uses a
//! different proving system — Groth16 — and different signing keys).

use crate::registry::transaction::TransparentOutput;
use zcash_protocol::consensus::BlockHeight;

/// The expiry height buffer: 20 blocks (~25 minutes at 75s/block).
const TX_EXPIRY_BUFFER: u32 = 20;

/// Proves, signs, and serializes an assembled Orchard bundle into a broadcastable
/// v5 transaction hex string.
///
/// # Proving key cache
///
/// `ProvingKey::build()` takes ~2 minutes. Both the `ProvingKey` and
/// `VerifyingKey` are cached in `OnceLock` statics so the first call pays the
/// cost and all subsequent calls reuse the cached keys.
///
/// # Pre-broadcast verification
///
/// After proving and signing, the Orchard proof is verified against the cached
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
    use zcash_primitives::transaction::{
        TransactionData, TxVersion, Unauthorized, Authorized,
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
    };
    use zcash_protocol::consensus::BranchId;
    use orchard::circuit::{ProvingKey, VerifyingKey};
    use std::sync::OnceLock;
    use rand::rngs::OsRng;

    // Cache the proving and verifying keys across calls. The circuit version
    // is fixed by the bundle version (orchard_v2), so a single pair serves all
    // transactions.
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    static VK: OnceLock<VerifyingKey> = OnceLock::new();

    let branch_id = BranchId::for_height(&zcash_protocol::consensus::MAIN_NETWORK, target_height);
    let expiry_height =
        BlockHeight::from_u32(u32::from(target_height) + TX_EXPIRY_BUFFER);

    // --- Transparent bundle (outputs only, no inputs today) ---
    //
    // The Treasury UA omits the transparent receiver, so no UTXOs are ever
    // received. Transparent outputs are used for auto-sweep to a cold address.
    let transparent_bundle: Option<
        transparent::Bundle<zcash_primitives::transaction::TransparentAuthorization>,
    > = transparent_outputs.map(|outputs| {
        let txouts: Vec<transparent::TxOut> = outputs
            .iter()
            .map(|o| transparent::TxOut {
                script_pubkey: transparent::Script(o.script_pubkey.as_bytes().to_vec().into()),
                value: o.value,
            })
            .collect();
        transparent::Bundle {
            inputs: vec![],
            outputs: txouts,
            authorization: zcash_primitives::transaction::TransparentAuthorization,
        }
    });

    let unauthed_tx: TransactionData<Unauthorized> = TransactionData::from_parts(
        TxVersion::V5,
        branch_id,
        0, // lock_time
        expiry_height,
        transparent_bundle,
        None, // sprout
        None, // sapling_bundle (cannot put Authorized bundle in unauthed_tx for sighash)
        Some(unproven_bundle.clone()),
    );

    let txid_parts = unauthed_tx.digest(TxIdDigester);
    let shielded_sig_commitment =
        signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

    // --- Orchard: prove + sign ---
    let circuit_version = unproven_bundle.circuit_version();
    let pk = PK.get_or_init(|| ProvingKey::build(circuit_version));
    let vk = VK.get_or_init(|| VerifyingKey::build(circuit_version));

    let mut rng = OsRng;
    let proven_bundle = unproven_bundle
        .create_proof(&pk, &mut rng)
        .map_err(|_| "failed to create orchard proof")?;

    let sak = orchard::keys::SpendAuthorizingKey::from(orchard_spending_key);

    let authorized_orchard = proven_bundle
        .apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), &[sak])
        .map_err(|_| "failed to apply orchard signatures")?;

    // Pre-broadcast self-verification: verify the Orchard proof against the
    // verifying key before serializing. Catches a malformed proof (builder bug,
    // fork divergence, hardware fault) before the transaction hits the network.
    authorized_orchard
        .verify_proof(vk)
        .map_err(|_| "orchard proof verification failed before broadcast")?;

    // --- Assemble the final authorized transaction ---
    let final_tx: TransactionData<Authorized> = TransactionData::from_parts(
        TxVersion::V5,
        branch_id,
        0,
        expiry_height,
        unauthed_tx.transparent_bundle().cloned(),
        None, // sprout
        sapling_bundle,
        Some(authorized_orchard),
    );

    let tx = final_tx
        .freeze()
        .map_err(|_| "failed to freeze transaction")?;
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|_| "failed to serialize tx")?;

    Ok(hex::encode(tx_bytes))
}