//! The V6 Ironwood transaction finalizer.
//!
//! [`assemble_v6_transaction`] proves, signs, and freezes an Ironwood bundle
//! into a V6 [`Transaction`]. This is the equivalent of
//! `zcash_primitives::transaction::builder::Builder::build` for the Ironwood
//! path, extracted because the upstream `Builder` keeps its inner
//! `ironwood_builder` private, preventing callers from reaching
//! `add_zns_spend` / `add_zns_output` (behind `unsafe-zns` on the orchard
//! crate).

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

/// The common unsigned bundle type used by this module.
type UnsignedBundle = orchard::Bundle<
    orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
    ZatBalance,
>;

/// Proves, signs, and freezes a V6 transaction containing one Ironwood
/// bundle.
///
/// This is the transaction finalizer for ZNS Name Note issuance: it takes a
/// pre-built unproven Ironwood bundle (constructed with `add_zns_spend` /
/// `add_zns_output` + standard `add_spend` / `add_output` for Treasury fee
/// notes) and produces an authorized, broadcastable V6 transaction.
///
/// Authority is per-spend: the caller passes exactly the signing keys its
/// spends require. For a Name Note claim (dual authority), both
/// [`TreasuryKeys`] and [`RegistryKeys`] are supplied; the builder's
/// `apply_signatures` matches each action to its key by `ak`.
///
/// This mirrors the Ironwood path of
/// `zcash_primitives::transaction::builder::Builder::build_internal`:
/// construct the unauthed transaction → compute the shared shielded sighash
/// → prove with the in-memory orchard proving key → sign with the supplied
/// keys → verify → freeze.
pub fn assemble_v6_transaction<P: Parameters>(
    network: &P,
    ironwood_bundle: UnsignedBundle,
    treasury_signer: Option<&TreasuryKeys>,
    registry_signer: Option<&RegistryKeys>,
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
    assert_eq!(pk.circuit_version(), circuit_version);
    assert_eq!(vk.circuit_version(), circuit_version);

    let proven = ironwood_bundle
        .create_proof(pk, &mut rng)
        .map_err(|_| crate::mint::AssemblyError::ProofCreation)?;
    let authorized_ironwood = proven
        .apply_signatures(rng, *shielded_sig_commitment.as_ref(), &signing_keys)
        .map_err(|_| crate::mint::AssemblyError::SigningAuth)?;
    authorized_ironwood
        .verify_proof(vk)
        .map_err(|_| crate::mint::AssemblyError::ProofVerification)?;

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
    let tx_digests_match =
        final_txid_parts.header_digest.as_bytes() == txid_parts.header_digest.as_bytes()
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