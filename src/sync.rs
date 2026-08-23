//! Block scanning for the ZNS mint.

use std::collections::HashMap;
use std::convert::Infallible;

use pasta_curves::group::ff::PrimeField;
use subtle::ConstantTimeEq;
use zcash_client_backend::{
    data_api::{BlockMetadata, ScannedBlock},
    scanning::{
        full::{decrypt_block, scan_block as upstream_scan_block},
        Nullifiers, ScanningKeys,
    },
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::Block as ZcashBlock;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters, TxIndex};
use zip32::AccountId;

use crate::mint::REGISTRY_ACCOUNT;

/// A non-secret scanner failure that prevents atomic block application.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("the Registry UFVK is missing")]
    MissingRegistryUfvk,
    #[error("the Registry UFVK has no Orchard full viewing key")]
    MissingRegistryOrchardFvk,
    #[error("upstream full-block scanning rejected the block")]
    Upstream,
    #[error("Ironwood action position arithmetic overflowed")]
    PositionOverflow,
    #[error("a supplemental Name Note did not match the upstream commitment stream")]
    CommitmentStreamMismatch,
    #[error("one Ironwood action was classified as both standard and ZcashName")]
    AmbiguousIronwoodAction,
}

/// A cryptographically validated Name Note received at the exact Registry address.
///
/// Carries its own `(block_index, txid, action_index)` attribution so the
/// Registry can group Name Notes by transaction without a wrapper type over
/// the upstream scan result.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedNameNote {
    block_index: TxIndex,
    txid: TxId,
    action_index: usize,
    note: orchard::Note,
    payload: crate::mint::note::NameNotePayload,
}

impl ReceivedNameNote {
    pub fn block_index(&self) -> TxIndex {
        self.block_index
    }

    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    pub fn action_index(&self) -> usize {
        self.action_index
    }

    /// The raw decrypted Note — carries recipient, value, rho, rseed.
    pub fn note(&self) -> &orchard::Note {
        &self.note
    }

    /// The decoded ZNS payload from the note's memo.
    pub fn payload(&self) -> &crate::mint::note::NameNotePayload {
        &self.payload
    }
}

impl std::fmt::Debug for ReceivedNameNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedNameNote")
            .field("block_index", &self.block_index)
            .field("txid", &self.txid)
            .field("action_index", &self.action_index)
            .field("payload", &"<redacted>")
            .finish()
    }
}

struct PendingNameNote {
    block_index: TxIndex,
    txid: TxId,
    action_index: usize,
    global_action_ordinal: usize,
    note: orchard::Note,
    payload: crate::mint::note::NameNotePayload,
    cmx: orchard::note::ExtractedNoteCommitment,
}

/// Scans one verified block.
///
/// Returns the upstream [`ScannedBlock`] unmodified — the full commitment
/// streams, the scanner's wallet-relevant transactions, and the block
/// metadata — plus the supplemental [`ReceivedNameNote`] lane. Nullifiers
/// for spend authentication come from `ScannedBlock`'s per-pool
/// `nullifier_map()` (the block-level full stream), and note witnesses
/// depend on the wallet appending the entire commitment streams via
/// `put_blocks`.
pub fn scan_block<P>(
    params: &P,
    prior_metadata: Option<&BlockMetadata>,
    block: ZcashBlock,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    scanning_keys: &ScanningKeys<AccountId, (AccountId, zip32::Scope)>,
) -> Result<(ScannedBlock<AccountId>, Vec<ReceivedNameNote>), ScanError>
where
    P: Parameters + Send + 'static,
{
    let height = block.claimed_height();

    let registry_ufvk = ufvks
        .get(&REGISTRY_ACCOUNT)
        .ok_or(ScanError::MissingRegistryUfvk)?;
    let registry_fvk = registry_ufvk
        .orchard()
        .ok_or(ScanError::MissingRegistryOrchardFvk)?;
    let registry_ivk = registry_fvk
        .to_ivk(orchard::keys::Scope::External)
        .prepare();
    let registry_recipient = registry_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Supplemental ZNS pass: walk raw Ironwood actions in consensus order.
    let mut pending_name_notes = Vec::new();
    let mut global_action_ordinal = 0usize;

    for (tx_index, tx) in block.vtx().iter().enumerate() {
        let tx_index_u16 = u16::try_from(tx_index).map_err(|_| ScanError::PositionOverflow)?;
        let tx_index = TxIndex::from(tx_index_u16);

        if let Some(bundle) = tx.ironwood_bundle() {
            for (action_index, action) in bundle.actions().iter().enumerate() {
                if bundle.bundle_version() == orchard::bundle::BundleVersion::ironwood_v3()
                    && bundle.flags().outputs_enabled()
                {
                    if let Some((note, recipient, memo)) =
                        orchard::note_encryption::ZnsIronwoodDomain::for_action(action).try_decrypt(
                            action,
                            &registry_ivk,
                            |note, memo, cmx| {
                                let payload =
                                    match crate::mint::note::decode_name_note_payload(memo) {
                                        Some(p) => p,
                                        None => return subtle::Choice::from(0),
                                    };
                                let (rcm, psi) = payload.opening();
                                let (g_d, pk_d) = note.recipient().zns_commitment_keys();
                                let rho_bytes = note.rho().to_bytes();
                                let rho =
                                    Option::from(pasta_curves::pallas::Base::from_repr(rho_bytes))
                                        .expect("valid rho");
                                let computed = match crate::mint::note::note_commitment_cmx(
                                    g_d, pk_d, 0, rho, psi, rcm,
                                ) {
                                    Some(c) => c,
                                    None => return subtle::Choice::from(0),
                                };
                                computed.to_repr().ct_eq(&cmx.to_bytes())
                            },
                        )
                    {
                        if note.value() == orchard::value::NoteValue::ZERO
                            && recipient == registry_recipient
                        {
                            let payload = crate::mint::note::decode_name_note_payload(&memo)
                                .expect("memo was validated in callback");
                            pending_name_notes.push(PendingNameNote {
                                block_index: tx_index,
                                txid: tx.txid(),
                                action_index,
                                global_action_ordinal,
                                note,
                                payload,
                                cmx: *action.cmx(),
                            });
                        }
                    }
                }

                global_action_ordinal = global_action_ordinal
                    .checked_add(1)
                    .ok_or(ScanError::PositionOverflow)?;
            }
        }
    }

    // Upstream decrypt + scan with an empty nullifier set: every public
    // nullifier arrives via the per-pool `nullifier_map()`, and the wallet
    // resolves spends against its own rewindable indexes.
    let (header, batch_results) = decrypt_block(params, block, scanning_keys);
    let nullifiers = Nullifiers::empty();
    let scanned = upstream_scan_block(
        params,
        height,
        &header,
        batch_results,
        scanning_keys,
        &nullifiers,
        prior_metadata,
        // The published Treasury UA omits a transparent receiver (shielded-only,
        // see docs/protocol.md §2–3), so no transparent output
        // is ever attributed to a wallet account. The closure permanently
        // returns `Ok(None)`; this is not a stub awaiting wiring.
        |_| {
            Ok::<Option<(AccountId, Option<transparent::keys::TransparentKeyScope>)>, Infallible>(
                None,
            )
        },
    )
    .map_err(|_| ScanError::Upstream)?;

    // Cross-check every supplemental Name Note against the upstream
    // commitment stream and the standard wallet lane.
    let ironwood_commitments = scanned.ironwood().commitments();
    if global_action_ordinal != ironwood_commitments.len() {
        return Err(ScanError::CommitmentStreamMismatch);
    }

    let mut name_notes = Vec::new();
    for pending in pending_name_notes {
        let Some((commitment, _retention)) =
            ironwood_commitments.get(pending.global_action_ordinal)
        else {
            return Err(ScanError::CommitmentStreamMismatch);
        };
        if *commitment != orchard::tree::MerkleHashOrchard::from_cmx(&pending.cmx) {
            return Err(ScanError::CommitmentStreamMismatch);
        }
        if scanned.transactions().iter().any(|wtx| {
            wtx.txid() == pending.txid
                && wtx
                    .ironwood_outputs()
                    .iter()
                    .any(|out| out.index() == pending.action_index)
        }) {
            return Err(ScanError::AmbiguousIronwoodAction);
        }

        name_notes.push(ReceivedNameNote {
            block_index: pending.block_index,
            txid: pending.txid,
            action_index: pending.action_index,
            note: pending.note,
            payload: pending.payload,
        });
    }

    Ok((scanned, name_notes))
}
