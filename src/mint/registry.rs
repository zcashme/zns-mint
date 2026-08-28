//! Registry: the ZNS name-chain state machine and transition authorization.
//!
//! The Registry tracks the current state of every name (the [`NameRecord`] for
//! each name chain) and authorizes transitions against that state
//! ([`authorize_claim`], [`authorize_update`], [`authorize_release`]), each
//! producing the typed [`NameNote`] transition for the settle path to
//! commit — memo, opening, and predecessor all derive from the one value.
//! The transaction-assembly path — building the Ironwood bundle, funding
//! the fee, signing — is the caller's job, not the Registry's. The OTP
//! challenges that update/release requests authorize with live in
//! [`crate::mint::otp`].

use crate::mint::otp::OtpQueue;
use crate::mint::{
    Action, Expiry, Name, NameCommitment, NameNote, UnifiedAddress, REGISTRY_ACCOUNT,
};
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use time::Timestamp;
use zcash_client_backend::data_api::ScannedBlock;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::consensus::Parameters;
use zip32::AccountId;

/// Reads the current record of the name chain for `name`.
pub fn current_record(registry: &Registry, name: &Name) -> Option<NameRecord> {
    registry.record(name).cloned()
}

/// Authorizes a claim, producing the typed [`NameNote`] transition to commit.
///
/// The Treasury layer must have already verified that the claim payment was
/// made. This function verifies that the name is available (either no record,
/// or record is `Release`). Until term-request plumbing exists in the intake
/// path, claims register without fixed expiration.
pub fn authorize_claim(
    registry: &Registry,
    name: Name,
    ua: UnifiedAddress,
) -> Option<NameNote> {
    match current_record(registry, &name) {
        None | Some(NameRecord {
            action: Action::Release,
            ..
        }) => Some(NameNote::Claim {
            name,
            ua,
            expires_at: Expiry::Never,
        }),
        Some(_) => None, // Name is already live
    }
}

/// Authorizes an update, producing the typed [`NameNote`] transition to
/// commit.
///
/// Verifies the name is live and consumes an OTP bound to its exact current
/// predecessor commitment, which becomes the transition's `prev` — the
/// settle path therefore cannot bind a predecessor other than the live
/// tip's.
pub fn authorize_update(
    registry: &Registry,
    otp_queue: &mut OtpQueue,
    mtp: Timestamp,
    name: Name,
    new_ua: UnifiedAddress,
    otp: &[u8; 6],
) -> Option<NameNote> {
    let record = current_record(registry, &name)?;
    if record.action == Action::Release {
        return None;
    }

    if !otp_queue.verify_and_burn(&name, Action::Update, &new_ua, otp, mtp) {
        return None;
    }

    Some(NameNote::Update {
        name,
        ua: new_ua,
        // §4.5.3: an ordinary update MUST NOT change the registration
        // period; the expiry is carried forward from the live record.
        expires_at: record.expires_at,
        prev: record.commitment,
    })
}

/// Authorizes a release, producing the typed [`NameNote`] transition to
/// commit.
///
/// Verifies the name is live, that the requester holds the live binding, and
/// consumes an OTP bound to its exact current predecessor commitment.
pub fn authorize_release(
    registry: &Registry,
    otp_queue: &mut OtpQueue,
    mtp: Timestamp,
    name: Name,
    current_ua: UnifiedAddress,
    otp: &[u8; 6],
) -> Option<NameNote> {
    let record = current_record(registry, &name)?;
    if record.action == Action::Release {
        return None;
    }

    let Some(controller) = &record.ua else {
        return None;
    };
    if controller != &current_ua {
        return None;
    }
    if !otp_queue.verify_and_burn(&name, Action::Release, &current_ua, otp, mtp) {
        return None;
    }

    Some(NameNote::Release {
        name,
        ua: current_ua,
        prev: record.commitment,
    })
}



// ---------------------------------------------------------------------------
// ReceivedNameNote — scanner evidence for one Name Note
// ---------------------------------------------------------------------------

/// A cryptographically validated Name Note received at the exact Registry address.
///
/// Produced by the orchestrator's ZNS decryption pass over an applied block
/// (each candidate's ZNS-derived cmx is checked against the action's actual
/// cmx before the note is exposed) and consumed by [`Registry::apply_block`].
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedNameNote {
    txid: TxId,
    action_index: usize,
    note: orchard::note::Note,
    payload: NameNote,
}

impl ReceivedNameNote {
    pub fn new(
        txid: TxId,
        action_index: usize,
        note: orchard::note::Note,
        payload: NameNote,
    ) -> Self {
        Self {
            txid,
            action_index,
            note,
            payload,
        }
    }

    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    pub fn action_index(&self) -> usize {
        self.action_index
    }

    /// The raw decrypted note — carries recipient, value, rho, rseed.
    pub fn note(&self) -> &orchard::note::Note {
        &self.note
    }

    /// The decoded typed transition from the note's memo.
    pub fn payload(&self) -> &NameNote {
        &self.payload
    }
}

impl std::fmt::Debug for ReceivedNameNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedNameNote")
            .field("txid", &self.txid)
            .field("action_index", &self.action_index)
            .field("payload", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// NameRecord — the current state of a name chain
// ---------------------------------------------------------------------------

/// The current state of a name in the registry.
///
/// Each name has a chain of Name Notes on-chain. This struct holds the
/// most recent confirmed note's derived state: what action created it,
/// what UA it points to, its cryptographic commitment, and when it was
/// confirmed. The `rho` field links to the actual shielded note in the
/// wallet — the wallet indexes notes by `rho`, so one lookup retrieves
/// everything needed to spend it (the note, its Merkle position, and its
/// memo for psi recomputation).
#[derive(Clone, PartialEq, Eq)]
pub struct NameRecord {
    pub action: Action,
    /// The binding UA. A release retains the address it terminated so the
    /// on-chain transition remains historically complete.
    pub ua: Option<UnifiedAddress>,
    /// The committed expiration (§4.5); absent for the post-release state.
    pub expires_at: Expiry,
    pub commitment: NameCommitment,
    /// The block height at which this Name Note was confirmed.
    pub confirmed_height: BlockHeight,
    /// The note's unique identity — links to the shielded note in the wallet.
    pub rho: orchard::note::Rho,
}

impl NameRecord {
    fn from_received<P: Parameters>(
        params: &P,
        received: ReceivedNameNote,
        confirmed_height: BlockHeight,
    ) -> Self {
        let note = received.payload();
        let rcm = note.rcm(params);
        Self {
            action: note.action(),
            ua: note.ua().cloned(),
            expires_at: note.expires_at().unwrap_or(Expiry::Never),
            commitment: NameCommitment::from_inner(orchard::note::NoteCommitTrapdoor::from_inner(
                rcm,
            )),
            confirmed_height,
            rho: received.note().rho(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        action: Action,
        ua: Option<UnifiedAddress>,
        expires_at: Expiry,
        commitment: NameCommitment,
        confirmed_height: BlockHeight,
        rho: orchard::note::Rho,
    ) -> Self {
        Self {
            action,
            ua,
            expires_at,
            commitment,
            confirmed_height,
            rho,
        }
    }
}

impl std::fmt::Debug for NameRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameRecord")
            .field("action", &self.action)
            .field("ua", &self.ua)
            .field("commitment", &self.commitment)
            .field("confirmed_height", &self.confirmed_height)
            .field("rho", &self.rho)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Registry — name-chain state with reorg undo
// ---------------------------------------------------------------------------

/// An undo-log entry: records what the record was before a `set_record` so a
/// reorg can rewind the registry to a prior height.
#[derive(Debug, Clone)]
pub struct RegistryHistoryRecord {
    pub height: BlockHeight,
    pub name: Name,
    pub prev_record: Option<NameRecord>,
}

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed record for that name, plus an undo log for reorgs.
#[derive(Clone)]
pub struct Registry {
    records: BTreeMap<Name, NameRecord>,
    history: Vec<RegistryHistoryRecord>,
}

impl Registry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            history: Vec::new(),
        }
    }

    /// Read the current record of a ZNS name chain.
    pub fn record(&self, name: &Name) -> Option<&NameRecord> {
        self.records.get(name)
    }

    /// Applies every Registry transition in block order.
    ///
    /// Takes the upstream [`ScannedBlock`] directly, plus the supplemental
    /// [`ReceivedNameNote`] lane from the orchestrator's ZNS decryption pass;
    /// per-transaction grouping (spent nullifiers, ordinary received Ironwood
    /// notes) is read from the scanner's own structures — `nullifier_map` and
    /// `WalletTx::ironwood_outputs`, whose nullifiers the scanner already
    /// derived. Callers cannot supply a detached authorship boolean or
    /// nullifier list.
    ///
    /// All ZNS invariant checks are assertions — only the mint can create or
    /// spend Name Notes, and its assembly code prevents every violation by
    /// construction. If an assertion fires, it's a bug in the assembly path.
    pub fn apply_block<P: Parameters>(
        &self,
        params: &P,
        wallet: &Wallet,
        scanned: &ScannedBlock<AccountId>,
        name_notes: &[ReceivedNameNote],
    ) -> Self {
        let mut next = self.clone();
        let height = scanned.height();
        let mut available_registry_fees = wallet.unspent_ironwood_nullifiers(REGISTRY_ACCOUNT);

        // Group the supplemental Name Note lane and the scanner's spent
        // nullifiers by txid, in one pass each.
        let mut name_notes_by_tx: BTreeMap<TxId, Vec<&ReceivedNameNote>> = BTreeMap::new();
        for note in name_notes {
            name_notes_by_tx.entry(*note.txid()).or_default().push(note);
        }
        let mut nullifiers_by_tx: BTreeMap<TxId, Vec<orchard::note::Nullifier>> = BTreeMap::new();
        for (_index, txid, nullifiers) in scanned.ironwood().nullifier_map() {
            nullifiers_by_tx
                .entry(*txid)
                .or_default()
                .extend(nullifiers.iter().copied());
        }

        for wtx in scanned.transactions() {
            let txid = wtx.txid();
            let ironwood_nullifiers: &[orchard::note::Nullifier] = nullifiers_by_tx
                .get(&txid)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let received_name_notes: &[&ReceivedNameNote] = name_notes_by_tx
                .get(&txid)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let received_ironwood = wtx.ironwood_outputs();

            let has_registry_fee_spend = ironwood_nullifiers
                .iter()
                .any(|nullifier| available_registry_fees.contains(nullifier));
            let spent_record_names: Vec<_> = next
                .records
                .iter()
                .filter_map(|(name, record)| {
                    // A record is spent when a new Name Note in this tx extends
                    // its chain — i.e., the new note's prev_rcm matches this
                    // record's commitment. This replaces nullifier matching.
                    let record_commitment = record.commitment;
                    received_name_notes
                        .iter()
                        .any(|new_note| new_note.payload().prev_rcm() == Some(record_commitment))
                        .then(|| name.clone())
                })
                .collect();

            match received_name_notes {
                [] => {
                    debug_assert!(
                        spent_record_names.is_empty(),
                        "record commitment matched a prev_rcm but no Name Notes were received \
                         — impossible: spent_record_names is derived from received_name_notes \
                         which is empty"
                    );
                }
                notes if notes.len() > 1 => {
                    // Public output construction is not Registry authorship.
                    // Ignore attacker-created ambiguity unless this transaction
                    // also spends Registry authority.
                    if has_registry_fee_spend || !spent_record_names.is_empty() {
                        panic!(
                            "mint produced multiple Name Notes in one transaction \
                                — assembly creates exactly one"
                        );
                    }
                }
                [note] => {
                    // An unauthenticated output candidate has no namespace
                    // effect and must not make canonical block following fail.
                    if !has_registry_fee_spend && spent_record_names.is_empty() {
                        Self::advance_fee_set(
                            &mut available_registry_fees,
                            ironwood_nullifiers,
                            received_ironwood,
                        );
                        continue;
                    }
                    assert!(
                        has_registry_fee_spend,
                        "mint transition transaction missing Registry fee-note spend \
                         — assembly always includes fee funding"
                    );

                    let payload = note.payload();
                    let name = payload.name();
                    match payload.action() {
                        Action::Claim => {
                            assert!(
                                spent_record_names.is_empty(),
                                "claim transaction spent a record — assembly never \
                                 spends a Name Note when claiming"
                            );
                            assert!(
                                next.record(name)
                                    .is_none_or(|r| r.action == Action::Release),
                                "claim attempted to replace live name {name:?} \
                                 — authorize_claim checks availability"
                            );
                        }
                        Action::Update | Action::Release => {
                            let record = next
                                .record(name)
                                .filter(|record| record.action != Action::Release)
                                .expect(
                                    "update/release has no live predecessor \
                                        — assembly checks liveness before transitioning",
                                );
                            assert!(
                                payload.prev_rcm() == Some(record.commitment),
                                "predecessor mismatch — assembly reads commitment \
                                 from the same registry"
                            );
                            assert!(
                                spent_record_names.as_slice() == [name.clone()],
                                "update/release did not spend the exact current Name Note \
                                 — assembly spends the exact current note"
                            );
                        }
                    }

                    next.set_record(
                        name.clone(),
                        NameRecord::from_received(params, (*note).clone(), height),
                        height,
                    );
                }
                _ => unreachable!("slice cardinality was handled above"),
            }

            Self::advance_fee_set(
                &mut available_registry_fees,
                ironwood_nullifiers,
                received_ironwood,
            );
        }

        next
    }

    fn advance_fee_set(
        available: &mut Vec<orchard::note::Nullifier>,
        spent: &[orchard::note::Nullifier],
        received: &[zcash_client_backend::wallet::WalletIronwoodOutput<AccountId>],
    ) {
        available.retain(|nullifier| !spent.contains(nullifier));
        available.extend(
            received
                .iter()
                .filter(|output| {
                    *output.account_id() == REGISTRY_ACCOUNT && output.note().0.value().inner() > 0
                })
                .filter_map(|output| output.nf().copied()),
        );
    }

    fn set_record(&mut self, name: Name, record: NameRecord, height: BlockHeight) {
        let prev_record = self.records.insert(name.clone(), record);
        self.history.push(RegistryHistoryRecord {
            height,
            name,
            prev_record,
        });
    }

    /// Read-only iterator over all known name records. Used for diagnostics.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &NameRecord)> {
        self.records.iter()
    }

    /// Rewinds the registry state back to the specified height (linear undo).
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        while let Some(entry) = self.history.last() {
            if entry.height <= height {
                break;
            }
            let entry = self.history.pop().unwrap();
            match entry.prev_record {
                Some(old_record) => {
                    self.records.insert(entry.name, old_record);
                }
                None => {
                    self.records.remove(&entry.name);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn set_record_for_test(
        &mut self,
        name: Name,
        action: Action,
        ua: Option<UnifiedAddress>,
        expires_at: Expiry,
        commitment: NameCommitment,
        height: BlockHeight,
        rho: orchard::note::Rho,
    ) {
        self.set_record(
            name,
            NameRecord::for_test(action, ua, expires_at, commitment, height, rho),
            height,
        );
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::otp::{encode_otp_relay_memo, OtpCode, OtpQueue, OtpRequest};
    use crate::mint::NameCommitment;
    use time::{Duration, Timestamp};

    fn mock_registry() -> Registry {
        Registry::new()
    }

    fn dummy_commitment() -> NameCommitment {
        let mut b = [0u8; 32];
        b[0] = 1;
        NameCommitment::from_bytes(&b).unwrap()
    }

    fn mock_otp_queue() -> OtpQueue {
        OtpQueue::new()
    }

    fn mock_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(&MAIN_NETWORK, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::consensus::MAIN_NETWORK;

    fn dummy_rho() -> orchard::note::Rho {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        orchard::note::Rho::from_bytes(&bytes)
            .into_option()
            .unwrap()
    }

    #[test]
    fn claim_fits_unseen_or_released_name() {
        let mut reg = mock_registry();
        let name = Name::parse("alice").unwrap();
        let ua = mock_ua();
        let height = BlockHeight::from_u32(100);

        // Unseen name is claimable
        let req = authorize_claim(&reg, name.clone(), ua.clone()).unwrap();
        assert_eq!(req.action(), Action::Claim);

        // Released name is claimable
        reg.set_record_for_test(
            name.clone(),
            Action::Release,
            None,
            crate::mint::Expiry::Never,
            dummy_commitment(),
            height,
            dummy_rho(),
        );
        let req2 = authorize_claim(&reg, name.clone(), ua.clone()).unwrap();
        assert_eq!(req2.action(), Action::Claim);

        // Live name is NOT claimable
        reg.set_record_for_test(
            name.clone(),
            Action::Claim,
            Some(ua.clone()),
            crate::mint::Expiry::Never,
            dummy_commitment(),
            height,
            dummy_rho(),
        );
        assert!(authorize_claim(&reg, name, ua).is_none());
    }

    #[test]
    fn update_release_need_live_record() {
        let mut reg = mock_registry();
        let mut otps = mock_otp_queue();
        let name = Name::parse("bob").unwrap();
        let ua = mock_ua();
        let now = Timestamp::now();

        let dummy_otp = *b"000000";
        // Unseen name cannot be updated/released
        assert!(
            authorize_update(&reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp).is_none()
        );
        assert!(
            authorize_release(&reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp).is_none()
        );

        // Released name cannot be updated/released
        reg.set_record_for_test(
            name.clone(),
            Action::Release,
            None,
            crate::mint::Expiry::Never,
            dummy_commitment(),
            BlockHeight::from_u32(100),
            dummy_rho(),
        );
        assert!(
            authorize_update(&reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp).is_none()
        );
        assert!(
            authorize_release(&reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp).is_none()
        );
    }

    #[test]
    fn update_extends_update_tip_with_valid_otp() {
        let mut reg = mock_registry();
        let mut otps = mock_otp_queue();
        let name = Name::parse("carol").unwrap();
        let ua = mock_ua();
        let now = Timestamp::now();

        reg.set_record_for_test(
            name.clone(),
            Action::Update,
            Some(ua.clone()),
            crate::mint::Expiry::Never,
            dummy_commitment(),
            BlockHeight::from_u32(100),
            dummy_rho(),
        );

        // Invalid OTP fails
        let mut bad_otp = *b"000000";
        bad_otp[0] = b'X';
        assert!(
            authorize_update(&reg, &mut otps, now, name.clone(), ua.clone(), &bad_otp).is_none()
        );

        // Issue real OTP and it succeeds
        let issued_otp = OtpCode::generate();
        let real_otp = issued_otp.expose_for_test();
        otps.push(OtpRequest {
            name: Name::parse("carol").unwrap(),
            action: Action::Update,
            ua: mock_ua(),
            code: OtpCode::for_test(real_otp),
            expires_at: now + Duration::seconds(crate::mint::otp::D_OTP),
        });
        let req = authorize_update(&reg, &mut otps, now, name.clone(), ua, &real_otp).unwrap();
        assert_eq!(req.action(), Action::Update);
    }

    #[test]
    fn release_preserves_the_current_binding_in_the_name_note() {
        let mut reg = mock_registry();
        let mut otps = mock_otp_queue();
        let name = Name::parse("dave").unwrap();
        let ua = mock_ua();
        let now = Timestamp::now();

        reg.set_record_for_test(
            name.clone(),
            Action::Claim,
            Some(ua.clone()),
            crate::mint::Expiry::Never,
            dummy_commitment(),
            BlockHeight::from_u32(100),
            dummy_rho(),
        );
        otps.push(OtpRequest {
            name: name.clone(),
            action: Action::Release,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: now + Duration::seconds(crate::mint::otp::D_OTP),
        });

        let transition = authorize_release(&reg, &mut otps, now, name, ua.clone(), b"004206")
            .expect("valid OTP authorizes release");
        match transition {
            NameNote::Release { ua: bound, .. } => assert_eq!(bound, ua),
            other => panic!("expected release transition, got {}", other.action().as_str()),
        }
    }

    #[test]
    fn relay_memo_is_not_a_request_memo() {
        // OTP relay memos use verb "otp", which is not a valid request verb.
        // parse_request must reject them.
        let name = Name::parse("alice").unwrap();
        let ua = mock_ua();
        let otp = OtpCode::for_test(*b"123456");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp).unwrap();
        let result = crate::mint::treasury::parse_request(&MAIN_NETWORK, &memo);
        assert!(
            result.is_none(),
            "relay memo must not parse as a request memo"
        );
    }
}
