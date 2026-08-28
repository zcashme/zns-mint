//! The V6 Ironwood transaction finalizer.

use orchard::builder::{BuildError, UnauthorizedBundle};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::value::ZatBalance;

use crate::key::{RegistryKeys, TreasuryKeys};

// ---------------------------------------------------------------------------
// Transaction assembly
// ---------------------------------------------------------------------------

/// The expiry height buffer: 20 blocks (~25 minutes at 75s/block).
const TX_EXPIRY_BUFFER: u32 = 20;


/// The transaction finalizer for ZNS Name Note issuance: proves, signs, and
/// freezes a V6 transaction containing one Ironwood bundle.
pub fn build_name_note_transaction<P: Parameters>(
    network: &P,
    ironwood_bundle: UnauthorizedBundle<ZatBalance>,
    treasury_keys: &TreasuryKeys,
    registry_keys: &RegistryKeys,
    target_height: BlockHeight,
) -> Result<Transaction, BuildError> {
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

    // Cache the proving and verifying keys across calls.
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    static VK: OnceLock<VerifyingKey> = OnceLock::new();

    let branch_id = BranchId::for_height(network, target_height);
    let expiry_height = BlockHeight::from_u32(
        u32::from(target_height)
            .checked_add(TX_EXPIRY_BUFFER)
            .expect("target_height + TX_EXPIRY_BUFFER fits in u32"),
    );

    // --- Unauthed transaction (for sighash) ---
    let unauthed_tx: TransactionData<Unauthorized> = TransactionData::from_parts_v6(
        branch_id,
        0, // lock_time
        expiry_height,
        None, // transparent (none for Name Note issuance)
        None, // sapling
        None, // orchard
        Some(ironwood_bundle.clone()),
    );

    let txid_parts = unauthed_tx.digest(TxIdDigester);
    let shielded_sig_commitment =
        signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

    // --- Prove and sign the shielded bundle ---
    let signing_keys = vec![
        orchard::keys::SpendAuthorizingKey::from(treasury_keys.orchard_spending_key()),
        orchard::keys::SpendAuthorizingKey::from(registry_keys.orchard_spending_key()),
    ];
    let mut rng = OsRng;

    let circuit_version = ironwood_bundle.circuit_version();

    let pk = PK.get_or_init(|| ProvingKey::build(circuit_version));
    let vk = VK.get_or_init(|| VerifyingKey::build(circuit_version));
    assert_eq!(pk.circuit_version(), circuit_version);
    assert_eq!(vk.circuit_version(), circuit_version);

    let proven = ironwood_bundle
        .create_proof(pk, &mut rng)?;
    let authorized_ironwood = proven
        .apply_signatures(rng, *shielded_sig_commitment.as_ref(), &signing_keys)?;
    authorized_ironwood.verify_proof(vk)?;

    // --- Final authorized transaction ---
    let final_tx: TransactionData<Authorized> = TransactionData::from_parts_v6(
        branch_id,
        0,
        expiry_height,
        None,
        None, // sapling (must match)
        None, // orchard (must match)
        Some(authorized_ironwood),
    );

    // Verify the effecting data committed by the sighash has not changed.
    let final_txid_parts = final_tx.digest(TxIdDigester);
    let tx_digests_match = final_txid_parts.header_digest.as_bytes()
        == txid_parts.header_digest.as_bytes()
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

    // The digest commits to effecting data only, and the authorization
    // pipeline copies effecting data verbatim (Action::try_map,
    // Bundle::try_map_authorization) — the digests cannot legitimately
    // differ. Reaching this line with a mismatch means the assembly
    // pipeline itself is broken.
    assert!(
        tx_digests_match,
        "assembly bug: effecting data changed during authorization"
    );

    let tx = final_tx
        .freeze()
        .expect("V6 transaction freeze is infallible");
    Ok(tx)
}
