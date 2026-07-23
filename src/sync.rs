use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;

use incrementalmerkletree::{Marking, Position, Retention};
use zcash_client_backend::{
    data_api::BlockMetadata,
    decrypt_transaction,
    scanning::{
        full::{decrypt_block, scan_block as upstream_scan_block},
        Nullifiers, ScanningKeys,
    },
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::{Block as ZcashBlock, BlockHash};
use zcash_primitives::transaction::Transaction;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters, TxIndex};
use zip32::AccountId;

use crate::mint::{decode_name_note_payload, Memo, NameNotePayload, REGISTRY_ACCOUNT};

/// A non-secret scanner failure that prevents atomic block application.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("the Registry UFVK is missing")]
    MissingRegistryUfvk,
    #[error("the Registry UFVK has no Orchard full viewing key")]
    MissingRegistryOrchardFvk,
    #[error("a validated candidate was not owned by the Registry viewing key")]
    RegistryOwnershipMismatch,
    #[error("upstream full-block scanning rejected the block")]
    Upstream,
    #[error("Ironwood action position arithmetic overflowed")]
    PositionOverflow,
    #[error("upstream Ironwood tree-size metadata is missing or inconsistent")]
    InvalidIronwoodTreeSize,
    #[error("a supplemental Name Note did not match the upstream commitment stream")]
    CommitmentStreamMismatch,
    #[error("one Ironwood action was classified as both standard and ZcashName")]
    AmbiguousIronwoodAction,
    #[error("scanner transaction identity did not match the source block")]
    TransactionIdentityMismatch,
}

/// Per-pool memo maps from `decrypt_transaction`.
///
/// Separate maps per pool because output indices are per-bundle — Orchard
/// output 0 and Sapling output 0 in the same tx would collide in a single
/// `HashMap<(TxId, usize), Memo>`.
struct BlockMemos {
    orchard: HashMap<(TxId, usize), Memo>,
    sapling: HashMap<(TxId, usize), Memo>,
    ironwood: HashMap<(TxId, usize), Memo>,
}

/// The result of scanning a single block.
///
/// Two concerns, both necessary:
/// - `transactions`: every transaction with an Ironwood bundle, plus any
///   transaction relevant to the standard Orchard or Sapling wallet lanes.
///   Retaining every Ironwood nullifier is required to authenticate spends of
///   supplemental validated Name Notes.
/// - the commitment vectors: the *full ordered
///   commitment stream* for the block — every action's `cmx` and every
///   output's `cmu`, wallet-relevant or not. The wallet's `ShardTree` must
///   append all of them to stay in sync with the chain's tree; skipping
///   non-wallet actions would break every Merkle witness we compute.
pub struct BlockOutput {
    /// Upstream scanner continuity metadata for this fully scanned block.
    ///
    /// The mint promotes this into its [`crate::mint::ChainCursor`] only after
    /// the wallet and Registry have both accepted the block.
    metadata: BlockMetadata,
    height: BlockHeight,
    transactions: Vec<TxOutput>,
    orchard_commitments: Vec<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>,
    sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
    ironwood_commitments: Vec<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>,
}

impl BlockOutput {
    pub fn metadata(&self) -> &BlockMetadata {
        &self.metadata
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn transactions(&self) -> &[TxOutput] {
        &self.transactions
    }

    pub(crate) fn orchard_commitments(
        &self,
    ) -> &[(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)] {
        &self.orchard_commitments
    }

    pub(crate) fn sapling_commitments(&self) -> &[(sapling::Node, Retention<BlockHeight>)] {
        &self.sapling_commitments
    }

    pub(crate) fn ironwood_commitments(
        &self,
    ) -> &[(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)] {
        &self.ironwood_commitments
    }
}

/// A transaction in the block that is wallet-relevant.
///
/// Groups received notes (with memo + position) and spent nullifiers (without
/// original note — the wallet resolves NF → original note via its own nullifier
/// index during `apply`). One `TxOutput` = one `TxId` = one transaction.
pub struct TxOutput {
    txid: TxId,
    block_index: TxIndex,
    received_orchard: Vec<ReceivedOrchard>,
    received_sapling: Vec<ReceivedSapling>,
    received_ironwood: Vec<ReceivedIronwood>,
    received_name_notes: Vec<ReceivedNameNote>,
    spent_orchard: Vec<SpentOrchard>,
    spent_sapling: Vec<SpentSapling>,
    spent_ironwood: Vec<SpentIronwood>,
    /// Every public Orchard action nullifier. The wallet resolves these
    /// against its rewindable local index instead of an ephemeral scan cache.
    orchard_nullifiers: Vec<orchard::note::Nullifier>,
    /// Every public Sapling spend nullifier.
    sapling_nullifiers: Vec<sapling::Nullifier>,
    /// Every public Ironwood action nullifier, including spends not recognized
    /// by upstream's standard-domain wallet scanner.
    ironwood_nullifiers: Vec<orchard::note::Nullifier>,
}

impl TxOutput {
    fn empty(txid: TxId, block_index: TxIndex) -> Self {
        Self {
            txid,
            block_index,
            received_orchard: Vec::new(),
            received_sapling: Vec::new(),
            received_ironwood: Vec::new(),
            received_name_notes: Vec::new(),
            spent_orchard: Vec::new(),
            spent_sapling: Vec::new(),
            spent_ironwood: Vec::new(),
            orchard_nullifiers: Vec::new(),
            sapling_nullifiers: Vec::new(),
            ironwood_nullifiers: Vec::new(),
        }
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn received_orchard(&self) -> &[ReceivedOrchard] {
        &self.received_orchard
    }

    pub(crate) fn received_sapling(&self) -> &[ReceivedSapling] {
        &self.received_sapling
    }

    pub(crate) fn received_ironwood(&self) -> &[ReceivedIronwood] {
        &self.received_ironwood
    }

    pub(crate) fn received_name_notes(&self) -> &[ReceivedNameNote] {
        &self.received_name_notes
    }

    pub(crate) fn orchard_nullifiers(&self) -> &[orchard::note::Nullifier] {
        &self.orchard_nullifiers
    }

    pub(crate) fn sapling_nullifiers(&self) -> &[sapling::Nullifier] {
        &self.sapling_nullifiers
    }

    pub(crate) fn ironwood_nullifiers(&self) -> &[orchard::note::Nullifier] {
        &self.ironwood_nullifiers
    }
}

/// An Orchard note we received, with its decrypted memo and tree position.
pub struct ReceivedOrchard {
    pub account_id: AccountId,
    pub note: orchard::note::Note,
    /// Scanner-derived from the note, its position, and the account FVK.
    /// Required to detect a later spend of this exact note.
    pub nullifier: orchard::note::Nullifier,
    pub memo: Memo,
    pub position: incrementalmerkletree::Position,
}

/// A Sapling note we received, with its decrypted memo and tree position.
pub struct ReceivedSapling {
    pub account_id: AccountId,
    pub note: sapling::Note,
    /// Scanner-derived from the note, its position, and the account FVK.
    /// Required to detect a later spend of this exact note.
    pub nullifier: sapling::Nullifier,
    pub memo: Memo,
    pub position: incrementalmerkletree::Position,
}

/// An Orchard nullifier we recognize — the wallet resolves this to the
/// original note via its nullifier index during `apply`.
pub struct SpentOrchard {
    pub account_id: AccountId,
    pub nullifier: orchard::note::Nullifier,
}

/// A Sapling nullifier we recognize.
pub struct SpentSapling {
    pub account_id: AccountId,
    pub nullifier: sapling::Nullifier,
}

/// An Ironwood (NU6.3) note we received, with its decrypted memo and tree position.
pub struct ReceivedIronwood {
    pub account_id: AccountId,
    pub action_index: usize,
    pub note: orchard::note::Note,
    /// Scanner-derived from the note, its position, and the account FVK.
    /// Required to detect a later spend of this exact note.
    pub nullifier: orchard::note::Nullifier,
    pub memo: Memo,
    pub position: incrementalmerkletree::Position,
}

/// The canonical location of a validated Name Note on one best-chain branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameNoteLocator {
    pub block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub block_index: TxIndex,
    pub txid: TxId,
    pub action_index: usize,
    pub position: Position,
}

/// A cryptographically validated Name Note received at the exact Registry address.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedNameNote {
    locator: NameNoteLocator,
    nullifier: orchard::note::Nullifier,
    validated: orchard::note_encryption::ValidatedZnsNote<NameNotePayload>,
}

impl ReceivedNameNote {
    pub fn locator(&self) -> NameNoteLocator {
        self.locator
    }

    pub fn nullifier(&self) -> orchard::note::Nullifier {
        self.nullifier
    }

    pub fn validated(&self) -> &orchard::note_encryption::ValidatedZnsNote<NameNotePayload> {
        &self.validated
    }

    pub fn payload(&self) -> &NameNotePayload {
        self.validated.payload()
    }
}

impl std::fmt::Debug for ReceivedNameNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedNameNote")
            .field("locator", &self.locator)
            .field("payload", &"<redacted>")
            .finish()
    }
}

struct PendingNameNote {
    block_index: TxIndex,
    txid: TxId,
    action_index: usize,
    global_action_ordinal: usize,
    nullifier: orchard::note::Nullifier,
    validated: orchard::note_encryption::ValidatedZnsNote<NameNotePayload>,
}

/// An Ironwood nullifier we recognize — same type as Orchard but tracked
/// separately to avoid cross-pool collision in the nullifier index.
pub struct SpentIronwood {
    pub account_id: AccountId,
    pub nullifier: orchard::note::Nullifier,
}

/// Scans one verified block and returns the wallet-relevant subset plus the
/// full commitment stream for tree integrity.
pub fn scan_block<P>(
    params: &P,
    prior_metadata: Option<&BlockMetadata>,
    block: ZcashBlock,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    scanning_keys: &ScanningKeys<AccountId, (AccountId, zip32::Scope)>,
) -> Result<BlockOutput, ScanError>
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

    let mut pending_name_notes = Vec::new();
    let mut raw_shielded_transactions = BTreeMap::new();
    let mut global_action_ordinal = 0usize;

    for (tx_index, tx) in block.vtx().iter().enumerate() {
        let tx_index_u16 = u16::try_from(tx_index).map_err(|_| ScanError::PositionOverflow)?;
        let tx_index = TxIndex::from(tx_index_u16);
        let orchard_nullifiers: Vec<orchard::note::Nullifier> = tx
            .orchard_bundle()
            .map(|bundle| {
                bundle
                    .actions()
                    .iter()
                    .map(|action| *action.nullifier())
                    .collect()
            })
            .unwrap_or_default();
        let sapling_nullifiers: Vec<sapling::Nullifier> = tx
            .sapling_bundle()
            .map(|bundle| {
                bundle
                    .shielded_spends()
                    .iter()
                    .map(|spend| *spend.nullifier())
                    .collect()
            })
            .unwrap_or_default();
        let mut ironwood_nullifiers = Vec::new();

        if let Some(bundle) = tx.ironwood_bundle() {
            ironwood_nullifiers.reserve(bundle.actions().len());
            for (action_index, action) in bundle.actions().iter().enumerate() {
                ironwood_nullifiers.push(*action.nullifier());

                if bundle.bundle_version() == orchard::bundle::BundleVersion::ironwood_v3()
                    && bundle.flags().outputs_enabled()
                {
                    if let Some(validated) = orchard::note_encryption::try_zns_note_decryption(
                        action,
                        &registry_ivk,
                        |memo| {
                            let payload = decode_name_note_payload(memo)?;
                            let (rcm, psi) = payload.opening();
                            Some((rcm, psi, payload))
                        },
                    ) {
                        if validated.value() == orchard::value::NoteValue::ZERO
                            && validated.recipient() == registry_recipient
                        {
                            let nullifier = validated
                                .nullifier(registry_fvk)
                                .ok_or(ScanError::RegistryOwnershipMismatch)?;
                            pending_name_notes.push(PendingNameNote {
                                block_index: tx_index,
                                txid: tx.txid(),
                                action_index,
                                global_action_ordinal,
                                nullifier,
                                validated,
                            });
                        }
                    }
                }

                global_action_ordinal = global_action_ordinal
                    .checked_add(1)
                    .ok_or(ScanError::PositionOverflow)?;
            }
        }

        if !orchard_nullifiers.is_empty()
            || !sapling_nullifiers.is_empty()
            || !ironwood_nullifiers.is_empty()
        {
            raw_shielded_transactions.insert(
                tx_index_u16,
                (
                    tx.txid(),
                    orchard_nullifiers,
                    sapling_nullifiers,
                    ironwood_nullifiers,
                ),
            );
        }
    }

    // 1. Decrypt memos + notes per tx via the public memo path. We borrow
    //    `vtx` here; the block moves into `decrypt_block` next. Keyed by
    //    `(txid, output_idx)` → `Memo` so the join in step 3 is a lookup.
    let memos = decrypt_block_memos(params, block.vtx(), ufvks, height);

    // 2. Upstream decrypt + scan for positions, spends, and the full
    //    commitment stream.
    let (header, batch_results) = decrypt_block(params, block, scanning_keys);
    let upstream_nullifiers = Nullifiers::empty();
    let scanned = upstream_scan_block(
        params,
        height,
        &header,
        batch_results,
        scanning_keys,
        &upstream_nullifiers,
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

    // 3. Walk the scanned transactions, join memos back, build TxOutputs.
    let mut transactions: BTreeMap<u16, TxOutput> = raw_shielded_transactions
        .into_iter()
        .map(|(index, (txid, orchard, sapling, ironwood))| {
            let mut tx = TxOutput::empty(txid, TxIndex::from(index));
            tx.orchard_nullifiers = orchard;
            tx.sapling_nullifiers = sapling;
            tx.ironwood_nullifiers = ironwood;
            (index, tx)
        })
        .collect();
    for wtx in scanned.transactions() {
        let txid = wtx.txid();
        let block_index = wtx.block_index();
        let index = u16::from(block_index);
        let tx_output = transactions
            .entry(index)
            .or_insert_with(|| TxOutput::empty(txid, block_index));
        if tx_output.txid != txid {
            return Err(ScanError::TransactionIdentityMismatch);
        }

        let mut received_orchard = Vec::new();
        for out in wtx.orchard_outputs() {
            if let Some(memo) = memos.orchard.get(&(txid, out.index())) {
                received_orchard.push(ReceivedOrchard {
                    account_id: *out.account_id(),
                    // out.note() returns &(Note, ValuePool) — clone just the Note.
                    note: out.note().0,
                    // `ScanningKeys::from_account_ufvks` always supplies an nk,
                    // so a wallet output must carry a nullifier.
                    nullifier: *out.nf().expect("wallet output missing nullifier"),
                    memo: memo.clone(),
                    position: out.note_commitment_tree_position(),
                });
            }
        }

        let mut received_sapling = Vec::new();
        for out in wtx.sapling_outputs() {
            if let Some(memo) = memos.sapling.get(&(txid, out.index())) {
                received_sapling.push(ReceivedSapling {
                    account_id: *out.account_id(),
                    note: out.note().clone(),
                    // See the Orchard equivalent above.
                    nullifier: *out.nf().expect("wallet output missing nullifier"),
                    memo: memo.clone(),
                    position: out.note_commitment_tree_position(),
                });
            }
        }

        let mut received_ironwood = Vec::new();
        for out in wtx.ironwood_outputs() {
            if let Some(memo) = memos.ironwood.get(&(txid, out.index())) {
                received_ironwood.push(ReceivedIronwood {
                    account_id: *out.account_id(),
                    action_index: out.index(),
                    note: out.note().0,
                    // See the Orchard equivalent above.
                    nullifier: *out.nf().expect("wallet output missing nullifier"),
                    memo: memo.clone(),
                    position: out.note_commitment_tree_position(),
                });
            }
        }

        let spent_orchard = wtx
            .orchard_spends()
            .iter()
            .map(|s| SpentOrchard {
                account_id: *s.account_id(),
                nullifier: *s.nf(),
            })
            .collect();

        let spent_sapling = wtx
            .sapling_spends()
            .iter()
            .map(|s| SpentSapling {
                account_id: *s.account_id(),
                nullifier: *s.nf(),
            })
            .collect();

        let spent_ironwood = wtx
            .ironwood_spends()
            .iter()
            .map(|s| SpentIronwood {
                account_id: *s.account_id(),
                nullifier: *s.nf(),
            })
            .collect();

        tx_output.received_orchard = received_orchard;
        tx_output.received_sapling = received_sapling;
        tx_output.received_ironwood = received_ironwood;
        tx_output.spent_orchard = spent_orchard;
        tx_output.spent_sapling = spent_sapling;
        tx_output.spent_ironwood = spent_ironwood;
    }

    // 4. Block-level commitments: every action's cmx / every output's cmu, in
    //    order, for ShardTree integrity.
    let metadata = scanned.to_block_metadata();

    let commitments = scanned.into_commitments();
    let orchard_commitments = commitments.orchard;
    let sapling_commitments = commitments.sapling;
    let mut ironwood_commitments = commitments.ironwood;

    if global_action_ordinal != ironwood_commitments.len() {
        return Err(ScanError::CommitmentStreamMismatch);
    }

    let final_ironwood_size = metadata
        .ironwood_tree_size()
        .ok_or(ScanError::InvalidIronwoodTreeSize)?;
    let block_action_count =
        u32::try_from(ironwood_commitments.len()).map_err(|_| ScanError::PositionOverflow)?;
    let block_start = final_ironwood_size
        .checked_sub(block_action_count)
        .ok_or(ScanError::InvalidIronwoodTreeSize)?;

    for pending in pending_name_notes {
        let commitment = ironwood_commitments
            .get_mut(pending.global_action_ordinal)
            .ok_or(ScanError::CommitmentStreamMismatch)?;
        if commitment.0 != orchard::tree::MerkleHashOrchard::from_cmx(&pending.validated.cmx()) {
            return Err(ScanError::CommitmentStreamMismatch);
        }
        commitment.1 = match commitment.1 {
            Retention::Checkpoint { id, .. } => Retention::Checkpoint {
                id,
                marking: Marking::Marked,
            },
            _ => Retention::Marked,
        };

        let ordinal = u32::try_from(pending.global_action_ordinal)
            .map_err(|_| ScanError::PositionOverflow)?;
        let position = Position::from(u64::from(
            block_start
                .checked_add(ordinal)
                .ok_or(ScanError::PositionOverflow)?,
        ));
        let index = u16::from(pending.block_index);
        let tx_output = transactions
            .entry(index)
            .or_insert_with(|| TxOutput::empty(pending.txid, pending.block_index));
        if tx_output.txid != pending.txid {
            return Err(ScanError::TransactionIdentityMismatch);
        }
        if tx_output
            .received_ironwood
            .iter()
            .any(|note| note.action_index == pending.action_index)
            || tx_output
                .received_name_notes
                .iter()
                .any(|note| note.locator.action_index == pending.action_index)
        {
            return Err(ScanError::AmbiguousIronwoodAction);
        }

        tx_output.received_name_notes.push(ReceivedNameNote {
            locator: NameNoteLocator {
                block_hash: metadata.block_hash(),
                block_height: height,
                block_index: pending.block_index,
                txid: pending.txid,
                action_index: pending.action_index,
                position,
            },
            nullifier: pending.nullifier,
            validated: pending.validated,
        });
    }

    let transactions = transactions.into_values().collect();

    Ok(BlockOutput {
        metadata,
        height,
        transactions,
        orchard_commitments,
        sapling_commitments,
        ironwood_commitments,
    })
}

/// Per-tx decryption for memos + notes via `decrypt_transaction`.
fn decrypt_block_memos<'a, P>(
    params: &P,
    vtx: impl IntoIterator<Item = &'a Transaction>,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    height: BlockHeight,
) -> BlockMemos
where
    P: Parameters,
{
    let mut memos = BlockMemos {
        orchard: HashMap::new(),
        sapling: HashMap::new(),
        ironwood: HashMap::new(),
    };

    for tx in vtx {
        let decrypted = decrypt_transaction(params, Some(height), None, tx, ufvks);

        for out in decrypted.orchard_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos
                    .orchard
                    .insert((decrypted.tx().txid(), out.index()), memo);
            }
        }

        for out in decrypted.sapling_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos
                    .sapling
                    .insert((decrypted.tx().txid(), out.index()), memo);
            }
        }

        for out in decrypted.ironwood_outputs() {
            let memo_bytes = out.memo();
            if let Ok(memo) = Memo::from_bytes(memo_bytes.as_array()) {
                memos
                    .ironwood
                    .insert((decrypted.tx().txid(), out.index()), memo);
            }
        }
    }

    memos
}
