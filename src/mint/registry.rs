//! Registry: the ZNS name-chain state machine and transition authorization.
//!

use crate::mint::otp::OtpQueue;
use crate::mint::{
    Action, Expiry, LIVENESS_INTERVAL, MAX_TERM_YEARS, Name, NameCommitment, NameNote, Request,
    Term, UnifiedAddress, REGISTRY_ACCOUNT,
};
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use time::Timestamp;
use zcash_client_backend::data_api::ScannedBlock;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::consensus::Parameters;
use zip32::AccountId;

/// Reads the current record of the name chain for `name`.
pub fn current_record(registry: &Registry, name: &Name) -> Option<NameRecord> {
    registry.record(name).cloned()
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
    pub ua: UnifiedAddress,
    /// The committed expiration (§4.5); absent for the post-release state.
    pub expires_at: Expiry,
    pub commitment: NameCommitment,
    /// The block height at which this Name Note was confirmed.
    pub confirmed_height: BlockHeight,
    /// The MTP by which an accepted update must re-prove control of the
    /// bound address; past it, the Mint releases the name (§4.5.4).
    pub release_deadline: Timestamp,
    /// The note's unique identity — links to the shielded note in the wallet.
    pub rho: orchard::note::Rho,
}

impl NameRecord {
    fn from_received<P: Parameters>(
        params: &P,
        received: ReceivedNameNote,
        confirmed_height: BlockHeight,
        mtp: Timestamp,
    ) -> Self {
        let note = received.payload();
        let rcm = note.rcm(params);
        Self {
            action: note.action(),
            ua: note.ua().clone(),
            expires_at: note.expires_at().unwrap_or(Expiry::Never),
            commitment: NameCommitment::from_inner(orchard::note::NoteCommitTrapdoor::from_inner(
                rcm,
            )),
            confirmed_height,
            release_deadline: Timestamp::from_seconds(
                mtp.as_seconds() + crate::mint::LIVENESS_INTERVAL,
            )
            .expect("liveness deadline fits Timestamp"),
            rho: received.note().rho(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        action: Action,
        ua: UnifiedAddress,
        expires_at: Expiry,
        release_deadline: Timestamp,
        commitment: NameCommitment,
        confirmed_height: BlockHeight,
        rho: orchard::note::Rho,
    ) -> Self {
        Self {
            action,
            ua,
            expires_at,
            release_deadline,
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

    /// The transition law: is this request lawful against the current
    /// registry state, and what NameNote does it produce?
    ///
    /// `None` means unlawful. Claims keep their payment — retained in full,
    /// by policy; the payer may re-request. Echoes that fail verification
    /// are dropped: the name was simply not renewed.
    pub fn authorize(
        &self,
        otp_queue: &mut OtpQueue,
        request: Request,
        otp: Option<&[u8; 6]>,
        mtp: Timestamp,
    ) -> Option<NameNote> {
        match request {
            Request::Claim { name, ua, term } => {
                // Availability: unseen, or the tip is a release.
                match current_record(self, &name) {
                    None | Some(NameRecord { action: Action::Release, .. }) => {}
                    Some(_) => return None, // live
                }
                let expires_at = match term {
                    Term::Forever => Expiry::Never,
                    Term::Years(years) => {
                        let seconds = years.checked_mul(LIVENESS_INTERVAL as u64)? as i64;
                        let at = mtp.as_seconds().checked_add(seconds)?;
                        Expiry::At(Timestamp::from_seconds(at).ok()?)
                    }
                };
                Some(NameNote::Claim { name, ua, expires_at })
            }
            Request::Update { name, ua, extend_years } => {
                let record = current_record(self, &name)?;
                if record.action == Action::Release {
                    return None;
                }
                // §4.5.3: no update is accepted once expiry is reached —
                // the Mint's lifecycle release owns that moment.
                if record.expires_at.expired(mtp) {
                    return None;
                }
                let otp = otp?;
                if !otp_queue.verify_and_burn(&name, Action::Update, &ua, otp, mtp) {
                    return None;
                }
                // §4.5.3: an ordinary update carries the current expiry
                // forward; an extension adds whole years to it — never
                // past the ninety-nine-year fence measured from now.
                let expires_at = match (record.expires_at, extend_years) {
                    (Expiry::Never, _) | (_, None) => record.expires_at,
                    (Expiry::At(current), Some(years)) => {
                        let extension = years.checked_mul(LIVENESS_INTERVAL as u64)? as i64;
                        let extended = current.as_seconds().checked_add(extension)?;
                        let fence = mtp
                            .as_seconds()
                            .checked_add((MAX_TERM_YEARS as i64).checked_mul(LIVENESS_INTERVAL)?)?;
                        if extended > fence {
                            return None;
                        }
                        Expiry::At(Timestamp::from_seconds(extended).ok()?)
                    }
                };
                Some(NameNote::Update {
                    name,
                    ua,
                    expires_at,
                    prev: record.commitment,
                })
            }
            Request::Release { name, ua } => {
                let record = current_record(self, &name)?;
                if record.action == Action::Release {
                    return None;
                }
                if record.ua != ua {
                    return None;
                }
                let otp = otp?;
                if !otp_queue.verify_and_burn(&name, Action::Release, &ua, otp, mtp) {
                    return None;
                }
                Some(NameNote::Release {
                    name,
                    ua,
                    prev: record.commitment,
                })
            }
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
        mtp: Timestamp,
    ) -> Self {
        let mut next = self.clone();
        let height = scanned.height();
        let mut available_registry_fees =
            wallet.unspent_ironwood_nullifiers(REGISTRY_ACCOUNT, TargetHeight::from(height));

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
                        NameRecord::from_received(params, (*note).clone(), height, mtp),
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
        ua: UnifiedAddress,
        expires_at: Expiry,
        release_deadline: Timestamp,
        commitment: NameCommitment,
        height: BlockHeight,
        rho: orchard::note::Rho,
    ) {
        self.set_record(
            name,
            NameRecord::for_test(
                action,
                ua,
                expires_at,
                release_deadline,
                commitment,
                height,
                rho,
            ),
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
    use crate::mint::otp::{OtpCode, OtpQueue, OtpRequest};
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
        let mut otps = mock_otp_queue();
        let name = Name::parse("alice").unwrap();
        let ua = mock_ua();
        let height = BlockHeight::from_u32(100);
        let mtp = Timestamp::from_seconds(1_000_000).unwrap();
        let forever = |name: &Name, ua: &UnifiedAddress| Request::Claim {
            name: name.clone(),
            ua: ua.clone(),
            term: crate::mint::Term::Forever,
        };

        // Unseen name is claimable
        let req = reg.authorize(&mut otps, forever(&name, &ua), None, mtp).unwrap();
        assert_eq!(req.action(), Action::Claim);

        // Released name is claimable
        reg.set_record_for_test(
            name.clone(),
            Action::Release,
            ua.clone(),
            crate::mint::Expiry::Never,
            Timestamp::from_seconds(0).unwrap(),
            dummy_commitment(),
            height,
            dummy_rho(),
        );
        let req2 = reg.authorize(&mut otps, forever(&name, &ua), None, mtp).unwrap();
        assert_eq!(req2.action(), Action::Claim);

        // Live name is NOT claimable
        reg.set_record_for_test(
            name.clone(),
            Action::Claim,
            ua.clone(),
            crate::mint::Expiry::Never,
            Timestamp::from_seconds(0).unwrap(),
            dummy_commitment(),
            height,
            dummy_rho(),
        );
        assert!(reg.authorize(&mut otps, forever(&name, &ua), None, mtp).is_none());
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
        assert!(reg
            .authorize(
                &mut otps,
                Request::Update { name: name.clone(), ua: ua.clone(), extend_years: None },
                Some(&dummy_otp),
                now
            )
            .is_none());
        assert!(reg
            .authorize(
                &mut otps,
                Request::Release { name: name.clone(), ua: ua.clone() },
                Some(&dummy_otp),
                now
            )
            .is_none());

        // Released name cannot be updated/released
        reg.set_record_for_test(
            name.clone(),
            Action::Release,
            ua.clone(),
            crate::mint::Expiry::Never,
            Timestamp::from_seconds(0).unwrap(),
            dummy_commitment(),
            BlockHeight::from_u32(100),
            dummy_rho(),
        );
        assert!(reg
            .authorize(
                &mut otps,
                Request::Update { name: name.clone(), ua: ua.clone(), extend_years: None },
                Some(&dummy_otp),
                now
            )
            .is_none());
        assert!(reg
            .authorize(
                &mut otps,
                Request::Release { name: name.clone(), ua: ua.clone() },
                Some(&dummy_otp),
                now
            )
            .is_none());
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
            ua.clone(),
            crate::mint::Expiry::Never,
            Timestamp::from_seconds(0).unwrap(),
            dummy_commitment(),
            BlockHeight::from_u32(100),
            dummy_rho(),
        );

        // Invalid OTP fails
        let mut bad_otp = *b"000000";
        bad_otp[0] = b'X';
        assert!(reg
            .authorize(
                &mut otps,
                Request::Update { name: name.clone(), ua: ua.clone(), extend_years: None },
                Some(&bad_otp),
                now
            )
            .is_none());

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
        let req = reg
            .authorize(
                &mut otps,
                Request::Update { name: name.clone(), ua, extend_years: None },
                Some(&real_otp),
                now,
            )
            .unwrap();
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
            ua.clone(),
            crate::mint::Expiry::Never,
            Timestamp::from_seconds(0).unwrap(),
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

        let transition = reg
            .authorize(
                &mut otps,
                Request::Release { name, ua: ua.clone() },
                Some(b"004206"),
                now,
            )
            .expect("valid OTP authorizes release");
        match transition {
            NameNote::Release { ua: bound, .. } => assert_eq!(bound, ua),
            other => panic!("expected release transition, got {}", other.action().as_str()),
        }
    }

    /// §4.5.4: an accepted update re-proves liveness; the extension may not
    /// push `expires_at` past the ninety-nine-year fence measured from now.
    #[test]
    fn update_extension_respects_the_release_fence() {
        let mut reg = mock_registry();
        let mut otps = mock_otp_queue();
        let name = Name::parse("fence").unwrap();
        let ua = mock_ua();
        let now = Timestamp::from_seconds(1_000_000).unwrap();

        reg.set_record_for_test(
            name.clone(),
            Action::Claim,
            ua.clone(),
            crate::mint::Expiry::At(Timestamp::from_seconds(1_100_000).unwrap()),
            Timestamp::from_seconds(0).unwrap(),
            dummy_commitment(),
            BlockHeight::from_u32(100),
            dummy_rho(),
        );

        let push = |otps: &mut OtpQueue, name: &Name, ua: &UnifiedAddress| {
            otps.push(OtpRequest {
                name: name.clone(),
                action: Action::Update,
                ua: ua.clone(),
                code: OtpCode::for_test(*b"004206"),
                expires_at: now + Duration::seconds(crate::mint::otp::D_OTP),
            });
        };

        // +1y inside the fence: new expiry = 1,100,000 + 31,557,600.
        push(&mut otps, &name, &ua);
        let req = reg
            .authorize(
                &mut otps,
                Request::Update {
                    name: name.clone(),
                    ua: ua.clone(),
                    extend_years: Some(1),
                },
                Some(b"004206"),
                now,
            )
            .unwrap();
        match req {
            NameNote::Update { expires_at, .. } => assert_eq!(
                expires_at,
                crate::mint::Expiry::At(Timestamp::from_seconds(1_131_557_600).unwrap())
            ),
            _ => panic!("expected update"),
        }

        // +99y would land at 3,125,302,400 — past the fence (3,125,202,400).
        push(&mut otps, &name, &ua);
        assert!(reg
            .authorize(
                &mut otps,
                Request::Update {
                    name: name.clone(),
                    ua: ua.clone(),
                    extend_years: Some(99),
                },
                Some(b"004206"),
                now,
            )
            .is_none());
    }

    /// §4.5.3: once expiry is reached, the Mint owns the name's ending —
    /// no update is accepted, echoed OTP or not.
    #[test]
    fn expired_names_reject_updates() {
        let mut reg = mock_registry();
        let mut otps = mock_otp_queue();
        let name = Name::parse("gone").unwrap();
        let ua = mock_ua();
        let now = Timestamp::from_seconds(1_000_000).unwrap();

        reg.set_record_for_test(
            name.clone(),
            Action::Claim,
            ua.clone(),
            crate::mint::Expiry::At(Timestamp::from_seconds(999_999).unwrap()),
            Timestamp::from_seconds(0).unwrap(),
            dummy_commitment(),
            BlockHeight::from_u32(100),
            dummy_rho(),
        );
        otps.push(OtpRequest {
            name: name.clone(),
            action: Action::Update,
            ua: ua.clone(),
            code: OtpCode::for_test(*b"004206"),
            expires_at: now + Duration::seconds(crate::mint::otp::D_OTP),
        });

        assert!(reg
            .authorize(
                &mut otps,
                Request::Update { name: name.clone(), ua: ua.clone(), extend_years: Some(1) },
                Some(b"004206"),
                now,
            )
            .is_none());
    }
}
