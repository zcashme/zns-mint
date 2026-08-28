//! Ironwood wallet queries and transaction assembly.
//!
//! Two concerns live here:
//!
//! 1. **Wallet queries** — Ironwood-specific lookups that upstream's generic
//!    traits cannot express: finding an owned note by a ZNS record's `rho`,
//!    and retrieving unspent Ironwood nullifiers.
//! 2. **Transaction assembly** — [`assemble_v6_transaction`] proves, signs,
//!    and freezes an Ironwood bundle into a V6 [`Transaction`]. This is the
//!    equivalent of `zcash_primitives::transaction::builder::Builder::build`
//!    for the Ironwood path, extracted because the upstream `Builder` keeps
//!    its inner `ironwood_builder` private, preventing callers from reaching
//!    `add_zns_spend` / `add_zns_output` (behind `unsafe-zns` on the orchard
//!    crate).

use incrementalmerkletree::{MerklePath, Position};
use zcash_client_backend::data_api::{ScannedBlock, WalletCommitmentTrees};
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::memo::Memo;
use zcash_protocol::value::ZatBalance;
use zip32::AccountId;

use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::REGISTRY_ACCOUNT;

use super::{TreeError, Wallet};

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

// ---------------------------------------------------------------------------
// Wallet queries
// ---------------------------------------------------------------------------

impl Wallet {
    /// Returns every unspent Ironwood note owned by `account`.
    pub fn unspent_ironwood_notes(
        &self,
        account: AccountId,
    ) -> Vec<ReceivedNote<NoteId, orchard::note::Note>> {
        self.ironwood_notes
            .iter()
            .filter(move |(_, output)| *output.account_id() == account)
            .filter(|(note_id, _)| !self.ironwood_note_spends.contains_key(note_id))
            .filter_map(|(note_id, _)| self.ironwood_received_note(*note_id))
            .collect()
    }

    /// Returns one unspent Ironwood note by its LRZ wallet identity.
    pub(crate) fn unspent_ironwood_note(
        &self,
        account: AccountId,
        note_id: NoteId,
    ) -> Option<ReceivedNote<NoteId, orchard::note::Note>> {
        let output = self.ironwood_notes.get(&note_id)?;
        (*output.account_id() == account && !self.ironwood_note_spends.contains_key(&note_id))
            .then(|| self.ironwood_received_note(note_id))
            .flatten()
    }

    /// Finds an unspent owned Ironwood note by the `rho` persisted in a ZNS
    /// record, returning its native LRZ wallet representation.
    pub(crate) fn unspent_ironwood_note_by_rho(
        &self,
        account: AccountId,
        rho: orchard::note::Rho,
    ) -> Option<ReceivedNote<NoteId, orchard::note::Note>> {
        let note_id = self
            .ironwood_notes
            .iter()
            .find(|(_, output)| {
                *output.account_id() == account && output.note().0.rho() == rho
            })
            .map(|(note_id, _)| *note_id)?;
        self.unspent_ironwood_note(account, note_id)
    }

    /// Returns the nullifiers of all unspent Ironwood notes owned by `account`,
    /// including value-0 notes: the Registry's Name Notes are value-0, and
    /// their nullifiers are what identifies a Registry spend in
    /// [`Registry::apply_block`](crate::mint::registry::Registry::apply_block)'s
    /// mint-authority check.
    pub(crate) fn unspent_ironwood_nullifiers(
        &self,
        account: AccountId,
    ) -> Vec<orchard::note::Nullifier> {
        self.ironwood_notes
            .iter()
            .filter(|(note_id, output)| {
                *output.account_id() == account
                    && !self.ironwood_note_spends.contains_key(note_id)
            })
            .filter_map(|(_, output)| output.nf().copied())
            .collect()
    }

    /// The Ironwood witness at `anchor_height` for the note at `position`.
    ///
    /// `Ok(None)` means no witness exists yet at that checkpoint (note not
    /// yet observed under that anchor); errors are tree-structural.
    pub(crate) fn ironwood_witness(
        &mut self,
        position: Position,
        anchor_height: BlockHeight,
    ) -> Result<Option<MerklePath<orchard::tree::MerkleHashOrchard, 32>>, TreeError> {
        // with_ironwood_tree_mut wraps the callback's Ok payload in an
        // outer Option; `?` then flatten collapses both layers.
        let witnessed = self
            .with_ironwood_tree_mut(|tree| {
                tree.witness_at_checkpoint_id_caching(position, &anchor_height)
            })
            .map_err(|e| e)?;
        Ok(witnessed.flatten())
    }

    /// The Ironwood tree root at `anchor_height` as an Orchard-family
    /// anchor for the builder.
    pub(crate) fn ironwood_anchor(
        &mut self,
        anchor_height: BlockHeight,
    ) -> Result<Option<orchard::tree::Anchor>, TreeError> {
        let root = self
            .with_ironwood_tree_mut(|tree| tree.root_at_checkpoint_id(&anchor_height))
            .map_err(|e| e)?;
        Ok(root.flatten().map(Into::into))
    }

    /// Stores one decrypted ZNS Name Note as the Registry account's ordinary
    /// received Ironwood note, at its consensus-derived tree position.
    ///
    /// The standard scanning lane cannot see Name Notes (its domain re-derives
    /// the commitment from rseed and rejects the ZNS-derived cmx), so the
    /// orchestrator's ZNS pass supplies them here. Storage mirrors
    /// `put_blocks`: note table + memo + mined status. `ordinal` is the
    /// action's index in the block's full Ironwood commitment stream.
    pub fn store_name_note(
        &mut self,
        scanned: &ScannedBlock<AccountId>,
        ordinal: usize,
        txid: TxId,
        action_index: usize,
        note: orchard::note::Note,
        ephemeral_key: zcash_note_encryption::EphemeralKeyBytes,
        memo: [u8; 512],
    ) -> Option<()> {
        let fvk = self.ufvks.get(&REGISTRY_ACCOUNT)?.orchard()?.clone();
        let bundles = scanned.ironwood();
        let start_size = bundles
            .final_tree_size()
            .checked_sub(u32::try_from(bundles.commitments().len()).ok()?)?;
        let position = Position::from(u64::from(start_size) + ordinal as u64);
        let note_id = NoteId::new(txid, ShieldedPool::Ironwood, u16::try_from(action_index).ok()?);
        self.ironwood_notes.insert(
            note_id,
            zcash_client_backend::wallet::WalletIronwoodOutput::from_parts(
                action_index,
                ephemeral_key,
                (note.clone(), orchard::ValuePool::Ironwood),
                false,
                position,
                Some(note.nullifier(&fvk)),
                REGISTRY_ACCOUNT,
                Some(zip32::Scope::External),
            ),
        );
        self.ironwood_nullifiers
            .insert(note.nullifier(&fvk), note_id);
        self.memos.insert(
            note_id,
            Memo::Future(
                zcash_protocol::memo::MemoBytes::from_bytes(&memo)
                    .expect("512-byte memo always parses"),
            ),
        );
        self.transaction_statuses
            .insert(txid, zcash_client_backend::data_api::TransactionStatus::Mined(scanned.height()));
        Some(())
    }
}
