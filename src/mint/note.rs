//! Name Notes: the transition types, its memo codec, and the ZNS commitment
//! derivation.
//!

use time::Timestamp;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};

pub mod assemble;

use crate::key::RegistryKeys;
use crate::mint::{Action, Name, NameCommitment, LIVENESS_INTERVAL};

/// A Name transition (§3.2), typed so every action carries exactly its
/// legal fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameNote {
    /// Bind `name` to `ua` for `expires_at`; no predecessor exists.
    Claim {
        name: Name,
        ua: UnifiedAddress,
        expires_at: Expiry,
    },
    /// Rebind and/or extend an existing registration. `expires_at` is the
    /// carried-forward (§4.5.3) or extension-resulting expiration.
    Update {
        name: Name,
        ua: UnifiedAddress,
        expires_at: Expiry,
        prev: NameCommitment,
    },
    /// Terminate the registration, retaining the address that was released.
    /// Releases always encode the exact expiry field `none`.
    Release {
        name: Name,
        ua: UnifiedAddress,
        prev: NameCommitment,
    },
}

impl NameNote {
    pub fn name(&self) -> &Name {
        match self {
            NameNote::Claim { name, .. }
            | NameNote::Update { name, .. }
            | NameNote::Release { name, .. } => name,
        }
    }

    pub fn action(&self) -> Action {
        match self {
            NameNote::Claim { .. } => Action::Claim,
            NameNote::Update { .. } => Action::Update,
            NameNote::Release { .. } => Action::Release,
        }
    }

    /// The bound Unified Address, including the address retained by a release.
    pub fn ua(&self) -> &UnifiedAddress {
        match self {
            NameNote::Claim { ua, .. }
            | NameNote::Update { ua, .. }
            | NameNote::Release { ua, .. } => ua,
        }
    }

    /// The committed expiration; absent only for a release.
    pub fn expires_at(&self) -> Option<Expiry> {
        match self {
            NameNote::Claim { expires_at, .. } | NameNote::Update { expires_at, .. } => {
                Some(*expires_at)
            }
            NameNote::Release { .. } => None,
        }
    }

    /// The predecessor chain commitment, absent only for a claim.
    pub fn prev_rcm(&self) -> Option<NameCommitment> {
        match self {
            NameNote::Claim { .. } => None,
            NameNote::Update { prev, .. } | NameNote::Release { prev, .. } => Some(*prev),
        }
    }

    /// The rcm component of the ZNS note commitment, derived from the
    /// transition tuple with derivation tag `rcm`.
    pub fn rcm<P: Parameters>(&self, params: &P) -> pasta_curves::pallas::Scalar {
        let verb = self.action().as_str().as_bytes();
        let name = self.name().as_str().as_bytes();
        let ua = self.ua().encode(params);
        let expiry = self.expires_at().unwrap_or(Expiry::Never).field_bytes();
        let prev = self.prev_rcm().map(|r| r.to_bytes()).unwrap_or([0u8; 32]);
        zns_rcm(verb, name, ua.as_bytes(), &expiry, &prev)
    }

    /// The ψ component of the ZNS note commitment, derived from the
    /// transition tuple with derivation tag `psi`.
    pub fn psi<P: Parameters>(&self, params: &P) -> pasta_curves::pallas::Base {
        let verb = self.action().as_str().as_bytes();
        let name = self.name().as_str().as_bytes();
        let ua = self.ua().encode(params);
        let expiry = self.expires_at().unwrap_or(Expiry::Never).field_bytes();
        let prev = self.prev_rcm().map(|r| r.to_bytes()).unwrap_or([0u8; 32]);
        zns_psi(verb, name, ua.as_bytes(), &expiry, &prev)
    }

    /// Encodes into the canonical zero-padded 512-byte memo under `params`.
    ///
    /// Total over valid `NameNote`s — the memo always fits, because every
    /// field is validated at construction: `Name::parse` bounds the name,
    /// `decode_controller_ua` bounds the address to known receivers, and
    /// the time crate bounds the expiry.
    pub fn encode<P: Parameters>(&self, params: &P) -> [u8; 512] {
        let ua_field = self.ua().encode(params);
        let verb = self.action().as_str();
        let hex_rcm = hex::encode(self.prev_rcm().map(|r| r.to_bytes()).unwrap_or([0u8; 32]));
        let expires_field = self.expires_at().unwrap_or(Expiry::Never).field_bytes();
        let memo_string = format!(
            "ZNS:{}:{}:{}:{}:{}",
            verb,
            self.name().as_str(),
            ua_field,
            // `b"none"` or canonical ASCII digits — always UTF-8.
            String::from_utf8(expires_field).unwrap(),
            hex_rcm,
        );
        let mut memo = [0u8; 512];
        let bytes = memo_string.as_bytes();
        memo[..bytes.len()].copy_from_slice(bytes);
        memo
    }
}

/// The `expires_at` field of a transition: a fixed Unix instant, or the
/// exact ASCII value `none` for a registration without fixed expiration.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Expiry {
    /// The exact ASCII bytes `none`.
    Never,
    /// A Unix timestamp in whole seconds.
    At(Timestamp),
}

impl Expiry {
    /// The canonical memo-field bytes.
    pub fn field_bytes(&self) -> Vec<u8> {
        match self {
            Expiry::Never => b"none".to_vec(),
            Expiry::At(t) => t.as_seconds().to_string().into_bytes(),
        }
    }

    /// Parses the memo field: canonical decimal, or exactly `none`.
    ///
    /// Canonical means digits only — no sign, no leading zeroes (except `0`
    /// itself). Non-canonical spellings are rejected because the raw field
    /// bytes are hashed into σ: `1` and `01` are different transitions with
    /// different commitments.
    pub fn parse(field: &str) -> Option<Self> {
        match field {
            "none" => Some(Expiry::Never),
            digits => {
                if digits.is_empty()
                    || digits.len() > 20
                    || !digits.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                if digits.len() > 1 && digits.starts_with('0') {
                    return None;
                }
                let seconds: i64 = digits.parse().ok()?;
                Timestamp::from_seconds(seconds).ok().map(Expiry::At)
            }
        }
    }

    /// The §4.5.2 expiration test against canonical-chain MTP.
    /// `Never` never expires (liveness still applies; §4.5.4).
    pub fn expired(self, mtp: Timestamp) -> bool {
        match self {
            Expiry::Never => false,
            Expiry::At(t) => mtp >= t,
        }
    }

    /// Successor expiry for an update (§4.5.3).
    ///
    /// `None` leaves the period unchanged. `Some(years)` banks from the
    /// current expiry. `Some(Forever)` is the upgrade: a fixed-term
    /// registration converts to no fixed expiration — the arm precedes
    /// the banking arm because `Term::Forever::duration` is zero, so the
    /// banking arm would silently no-op it. A forever name has no
    /// runway: `Never` plus a term — banking or a second upgrade — is
    /// refused. The banking result must sit no more than `MAX_TERM_YEARS`
    /// ahead of `mtp`.
    pub fn extend(self, term: Option<Term>, mtp: Timestamp) -> Option<Self> {
        let extended = match (self, term) {
            (expiry, None) => expiry,
            (Expiry::Never, Some(_)) => return None,
            // The upgrade: At + forever converts the registration kind. This arm MUST precede the banking arm below —
            // `Term::Forever::duration` is zero, so the banking arm would
            // silently no-op the upgrade (At + 0 = At).
            (Expiry::At(_), Some(Term::Forever)) => Expiry::Never,
            (Expiry::At(t), Some(term)) => t.checked_add(term.duration()).map(Expiry::At)?,
        };
        let horizon = mtp
            .checked_add(time::Duration::seconds(
                MAX_TERM_YEARS as i64 * LIVENESS_INTERVAL,
            ))
            .expect("the expiry horizon always fits Timestamp");
        match extended {
            Expiry::At(t) if t > horizon => None,
            expiry => Some(expiry),
        }
    }
}

/// A request term: `forever` or whole Julian years, 1–99. Requests speak
/// durations — seconds never appear on the request wire; the mint
/// converts years to seconds at authorization.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Term {
    /// No fixed expiration — held while liveness passes.
    Forever,
    /// A term of N whole Julian years (the liveness interval).
    Years(u64),
}

/// The longest single term.
pub const MAX_TERM_YEARS: u64 = 99;

impl Term {
    /// Parses a term field: `forever` or `<N>y` — N is 1–99, digits only,
    /// no leading zero. `5` (missing y), `100y` (over the cap), `0y`,
    /// `01y` are invalid on sight.
    pub fn parse(field: &str) -> Option<Self> {
        if field == "forever" {
            return Some(Self::Forever);
        }
        let years = field.strip_suffix('y')?;
        if years.is_empty() || years.starts_with('0') || !years.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let n: u64 = years.parse().ok()?;
        (1..=MAX_TERM_YEARS).contains(&n).then_some(Self::Years(n))
    }

    /// The term as a `time` duration; one year is `LIVENESS_INTERVAL`.
    pub fn duration(self) -> time::Duration {
        match self {
            Self::Forever => time::Duration::ZERO, // claim_expiry never reads it
            Self::Years(n) => time::Duration::seconds(n as i64 * LIVENESS_INTERVAL),
        }
    }

    /// Claim expiry: forever is `Expiry::Never`; years extend MTP (§4.5).
    pub fn claim_expiry(self, mtp: Timestamp) -> Option<Expiry> {
        match self {
            Self::Forever => Some(Expiry::Never),
            Self::Years(_) => mtp.checked_add(self.duration()).map(Expiry::At),
        }
    }
}

/// Derives the ZNS note-commitment randomness `rcm` for a transition (§3.3):
/// BLAKE2b-512 over the length-prefixed fields with derivation tag `rcm`,
/// wide-reduced into the Pallas scalar field.
fn zns_rcm(
    verb: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    prev_rcm_bytes: &[u8; 32],
) -> pasta_curves::pallas::Scalar {
    use pasta_curves::group::ff::FromUniformBytes;
    pasta_curves::pallas::Scalar::from_uniform_bytes(&tagged_zns_hash(
        b"rcm",
        verb,
        name,
        ua,
        expires_at,
        prev_rcm_bytes,
    ))
}

/// Derives the ZNS note-commitment psi `ψ` for a transition (§3.3):
/// BLAKE2b-512 over the length-prefixed fields with derivation tag `psi`,
/// wide-reduced into the Pallas base field.
fn zns_psi(
    verb: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    prev_rcm_bytes: &[u8; 32],
) -> pasta_curves::pallas::Base {
    use pasta_curves::group::ff::FromUniformBytes;
    pasta_curves::pallas::Base::from_uniform_bytes(&tagged_zns_hash(
        b"psi",
        verb,
        name,
        ua,
        expires_at,
        prev_rcm_bytes,
    ))
}

/// The domain-tagged, length-prefixed BLAKE2b-512 of σ (§3.3).
/// Field order: `LP(T) || LP(t) || LP(α) || LP(n) || LP(u) || LP(e) || p`.
fn tagged_zns_hash(
    field_tag: &[u8],
    verb: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    prev_rcm: &[u8; 32],
) -> [u8; 64] {
    let mut h = blake2b_simd::Params::new().hash_length(64).to_state();
    let mut absorb = |b: &[u8]| {
        h.update(&(b.len() as u32).to_le_bytes());
        h.update(b);
    };
    absorb(b"ZcashName/v1");
    absorb(field_tag);
    absorb(verb);
    absorb(name);
    absorb(ua);
    absorb(expires_at);
    h.update(prev_rcm);

    let mut out = [0u8; 64];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

impl NameNote {
    /// Decodes a 512-byte memo into a typed [`NameNote`].
    ///
    /// Accepts exactly the canonical encoding: trailing-zero stripping, the
    /// six-field grammar, canonical decimal or `none` expiry, 64-char lowercase
    /// hex predecessor, action-consistent fields (release: a valid UA and `none`
    /// expiry; claim: zero predecessor; update/release: nonzero predecessor),
    /// and a re-encode that reproduces the input byte-for-byte.
    pub fn decode<P: Parameters>(params: &P, memo: &[u8; 512]) -> Option<Self> {
        let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
        if memo[end..].iter().any(|&b| b != 0) {
            return None;
        }
        let memo_str = std::str::from_utf8(&memo[..end]).ok()?;

        let parts: Vec<&str> = memo_str.split(':').collect();
        if parts.len() != 6 || parts[0] != "ZNS" {
            return None;
        }

        let name = Name::parse(parts[2])?;
        // The single UA validation boundary: a memo whose ua field is not a
        // valid ZIP 316 Unified Address for this network decodes to no note.
        let ua_str = parts[3];
        let ua = match zcash_keys::address::Address::decode(params, ua_str)? {
            zcash_keys::address::Address::Unified(ua) => ua,
            _ => return None,
        };
        let expires_at = Expiry::parse(parts[4])?;

        let mut prev_rcm_bytes = [0u8; 32];
        if parts[5].len() != 64
            || !parts[5]
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return None;
        }
        hex::decode_to_slice(parts[5], &mut prev_rcm_bytes).ok()?;

        let note = match Action::parse(parts[1])? {
            Action::Claim => {
                if prev_rcm_bytes != [0u8; 32] || ua_str.is_empty() {
                    return None;
                }
                NameNote::Claim {
                    name,
                    ua,
                    expires_at,
                }
            }
            Action::Update => {
                if prev_rcm_bytes == [0u8; 32] || ua_str.is_empty() {
                    return None;
                }
                NameNote::Update {
                    name,
                    ua,
                    expires_at,
                    prev: NameCommitment::from_bytes(&prev_rcm_bytes)?,
                }
            }
            // A release MUST retain the released UA and encode the exact value
            // `none` for its expiry.
            Action::Release => {
                if ua_str.is_empty() || expires_at != Expiry::Never || prev_rcm_bytes == [0u8; 32] {
                    return None;
                }
                NameNote::Release {
                    name,
                    ua,
                    prev: NameCommitment::from_bytes(&prev_rcm_bytes)?,
                }
            }
        };

        (note.encode(params).as_slice() == memo).then_some(note)
    }
}

// ---------------------------------------------------------------------------
// Block scan: ZNS trial-decryption pass
// ---------------------------------------------------------------------------

use subtle::ConstantTimeEq as _;
use zcash_primitives::block::Block;

/// One decrypted Name Note from the ZNS scan pass, with the facts the wallet
/// store and the Registry evidence need.
pub struct DecryptedNameNote {
    pub txid: TxId,
    pub action_index: usize,
    /// The action's index in the block's full Ironwood commitment stream —
    /// fixes the note's tree position.
    pub ordinal: usize,
    /// The action's published note commitment — marked at the wallet
    /// commit so the note stays witnessable.
    pub cmx: orchard::note::ExtractedNoteCommitment,
    pub note: orchard::note::Note,
    /// The nullifier this ZNS-bound note reveals when spent. It must be
    /// derived from the same authenticated `(rcm, psi)` pair as `cmx`; the
    /// ordinary rseed-derived nullifier is not the Name Note's nullifier.
    pub nullifier: orchard::note::Nullifier,
    /// The epk bytes directly — the `ShieldedOutput` trait method is
    /// ambiguous across the three Ironwood-family domains.
    pub ephemeral_key: zcash_note_encryption::EphemeralKeyBytes,
    pub memo: [u8; 512],
    pub payload: NameNote,
}

/// Trial-decrypts the block's Ironwood actions under the ZNS domain.
///
/// Derives the Registry's published identity from the capability — the
/// external-scope address at diversifier index 0 — and its prepared ivk,
/// in exactly one ivk derivation per call.
///
/// A candidate is exposed only if its memo parses as a Name Note and the
/// payload-derived ZNS commitment reproduces the action's actual cmx — the
/// cryptographic authorship check. Value must be zero and the recipient must
/// be the exact Registry address; anything else is not a Name Note.
pub fn decrypt_name_notes<P: Parameters>(
    network: &P,
    block: &Block,
    registry_keys: &RegistryKeys,
) -> Vec<DecryptedNameNote> {
    let registry_fvk = registry_keys.orchard_fvk();
    let registry_ivk = registry_fvk.to_ivk(orchard::keys::Scope::External);
    let registry_recipient = registry_ivk.address_at(0u32);
    let registry_ivk = registry_ivk.prepare();

    let mut candidates = Vec::new();
    let mut ordinal = 0usize;
    for tx in block.vtx() {
        let Some(bundle) = tx.ironwood_bundle() else {
            continue;
        };
        let zns_capable = bundle.bundle_version() == orchard::bundle::BundleVersion::ironwood_v3()
            && bundle.flags().outputs_enabled();
        for (action_index, action) in bundle.actions().iter().enumerate() {
            if zns_capable {
                if let Some((candidate, recipient, memo)) =
                    orchard::note_encryption::ZnsIronwoodDomain::for_action(action)
                        .try_decrypt(action, &registry_ivk)
                {
                    if let Some(payload) = NameNote::decode(network, &memo) {
                        // The authorship check, caller-side: the memo's transition,
                        // hashed under the ZNS binding, must reproduce the action's
                        // published cmx.
                        let note = *candidate.note();
                        let rcm =
                            orchard::note::NoteCommitTrapdoor::from_inner(payload.rcm(network));
                        let psi = payload.psi(network);
                        let authored = match note.zns_cmx(rcm, psi) {
                            Some(computed) => computed.ct_eq(candidate.cmx()),
                            None => subtle::Choice::from(0),
                        };

                        if authored.into()
                            && note.value() == orchard::value::NoteValue::ZERO
                            && recipient == registry_recipient
                        {
                            let nullifier = note
                                .zns_nullifier(&registry_fvk, rcm, psi)
                                .expect("authenticated Name Note commitment is not identity");
                            candidates.push(DecryptedNameNote {
                                txid: tx.txid(),
                                action_index,
                                ordinal,
                                cmx: *candidate.cmx(),
                                note,
                                nullifier,
                                ephemeral_key: zcash_note_encryption::EphemeralKeyBytes(
                                    action.encrypted_note().epk_bytes,
                                ),
                                memo,
                                payload,
                            });
                        }
                    }
                }
            }
            ordinal += 1;
        }
    }
    candidates
}

/// Trial-decrypts the block's Ironwood actions sent to the Treasury's
/// external address, exposing each `(txid, action index, memo)`. The
/// upstream scanner deliberately drops note plaintexts; request memos
/// arrive through this pass instead.
pub fn decrypt_treasury_memos(
    block: &Block,
    treasury_keys: &crate::key::TreasuryKeys,
) -> Vec<(
    zcash_primitives::transaction::TxId,
    usize,
    zcash_protocol::value::Zatoshis,
    zcash_protocol::memo::MemoBytes,
)> {
    let mut memos = Vec::new();
    for tx in block.vtx() {
        for (action_index, paid, memo) in decrypt_treasury_tx(tx, &treasury_keys.orchard_fvk()) {
            memos.push((tx.txid(), action_index, paid, memo));
        }
    }
    memos
}

/// Trial-decrypts one transaction's Ironwood actions sent to the
/// Treasury's external address, exposing each `(action index, value,
/// memo)` — the per-transaction core [`decrypt_treasury_memos`] has
/// always embedded, callable on a mempool fetch. The viewing key is the
/// reader's whole need: this pass decrypts, it never signs.
pub fn decrypt_treasury_tx(
    tx: &zcash_primitives::transaction::Transaction,
    treasury_fvk: &orchard::keys::FullViewingKey,
) -> Vec<(
    usize,
    zcash_protocol::value::Zatoshis,
    zcash_protocol::memo::MemoBytes,
)> {
    let ivk = treasury_fvk
        .to_ivk(orchard::keys::Scope::External)
        .prepare();

    let mut memos = Vec::new();
    let Some(bundle) = tx.ironwood_bundle() else {
        return memos;
    };
    if bundle.bundle_version() != orchard::bundle::BundleVersion::ironwood_v3() {
        return memos;
    }
    for (action_index, action) in bundle.actions().iter().enumerate() {
        let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
        if let Some((note, _recipient, memo)) =
            zcash_note_encryption::try_note_decryption(&domain, &ivk, action)
        {
            let paid = zcash_protocol::value::Zatoshis::from_u64(note.value().inner())
                .expect("note values are consensus-bounded");
            let memo = zcash_protocol::memo::MemoBytes::from_bytes(&memo)
                .expect("a decrypted memo is 512 bytes");
            memos.push((action_index, paid, memo));
        }
    }
    memos
}

// ---------------------------------------------------------------------------
// NameNoteQueue — authorized Name Notes awaiting the chain
// ---------------------------------------------------------------------------

/// Authorized Name Notes awaiting a mined transaction. Each entry is
/// the note, the height whose evidence authorized it, and the txid of
/// the broadcast still in flight. The drain removes an order when that
/// transaction is mined, or when the world overtakes it. Acceptance
/// into the mempool keeps the order. A reorg truncates it. The queue
/// is memory: a restart empties it.
#[derive(Clone, Debug, Default)]
pub struct NameNoteQueue {
    authorized: Vec<(NameNote, BlockHeight, Option<TxId>)>,
}

impl NameNoteQueue {
    /// Records a decision. Idempotent: a note already authorized keeps its
    /// original origin.
    pub fn admit(&mut self, origin: BlockHeight, note: NameNote) {
        if !self.authorized.iter().any(|(n, _, _)| *n == note) {
            self.authorized.push((note, origin, None));
        }
    }

    pub fn len(&self) -> usize {
        self.authorized.len()
    }

    pub fn is_empty(&self) -> bool {
        self.authorized.is_empty()
    }

    /// The entry at `index`, in admission order — the drain cursor reads.
    pub fn entry(&self, index: usize) -> (&NameNote, BlockHeight) {
        let (note, origin, _) = &self.authorized[index];
        (note, *origin)
    }

    /// The broadcast still in flight for this order, if one has been built.
    pub fn pending_txid(&self, index: usize) -> Option<TxId> {
        self.authorized[index].2
    }

    /// Records the transaction built for this order. Later tips resubmit
    /// these bytes until the node reports it mined or the wallet's expiry
    /// releases the inputs.
    pub fn mark_submitted(&mut self, index: usize, txid: TxId) {
        self.authorized[index].2 = Some(txid);
    }

    /// Drops the in-flight txid so the drain may build a successor.
    /// The order itself stays.
    pub fn clear_submission(&mut self, index: usize) {
        self.authorized[index].2 = None;
    }

    /// The order is resolved — enacted, or overtaken by the world. The
    /// only removal besides reorg truncation.
    pub fn remove(&mut self, index: usize) {
        self.authorized.remove(index);
    }

    /// Reorg: drop origins above the common ancestor.
    pub fn truncate_to(&mut self, ancestor: BlockHeight) {
        self.authorized.retain(|(_, origin, _)| *origin <= ancestor);
    }

    /// The one-open-claim guard.
    pub fn claim_pending(&self, name: &Name) -> bool {
        self.authorized
            .iter()
            .any(|(n, _, _)| n.action().is_claim() && n.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MAIN_NETWORK;

    /// A real mainnet UA with every known receiver kind — Orchard,
    /// Sapling, and P2PKH: parses, round-trips byte-exact, and carries
    /// orchard().
    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn test_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(&MAIN_NETWORK, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    fn test_name() -> Name {
        Name::parse("alice").unwrap()
    }

    /// The memo round-trip: encode → decode must preserve every field of
    /// every action, including the expiry.
    #[test]
    fn memo_round_trip_all_actions() {
        let name = test_name();
        let ua = test_ua();
        let prev = NameCommitment::from_bytes(&[1u8; 32]).unwrap();

        let claim = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::Never,
        };
        assert_eq!(
            NameNote::decode(&MAIN_NETWORK, &claim.encode(&MAIN_NETWORK)).as_ref(),
            Some(&claim)
        );

        let t = Timestamp::from_seconds(1_775_000_000).unwrap();
        let claim_t = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::At(t),
        };
        assert_eq!(
            NameNote::decode(&MAIN_NETWORK, &claim_t.encode(&MAIN_NETWORK)).as_ref(),
            Some(&claim_t)
        );

        let update = NameNote::Update {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::At(t),
            prev,
        };
        assert_eq!(
            NameNote::decode(&MAIN_NETWORK, &update.encode(&MAIN_NETWORK)).as_ref(),
            Some(&update)
        );

        let release = NameNote::Release { name, ua, prev };
        assert_eq!(
            NameNote::decode(&MAIN_NETWORK, &release.encode(&MAIN_NETWORK)).as_ref(),
            Some(&release)
        );
    }

    /// §3.5: a memo whose UA is not a valid ZIP 316 address decodes to no
    /// note. `u1xxx` is the whitepaper's own example.
    #[test]
    fn invalid_ua_is_rejected() {
        let name = test_name();
        let forged = format!(
            "ZNS:claim:{}:u1xxx:none:{}",
            name.as_str(),
            hex::encode([0u8; 32])
        );
        let mut m = [0u8; 512];
        m[..forged.len()].copy_from_slice(forged.as_bytes());
        assert!(NameNote::decode(&MAIN_NETWORK, &m).is_none());
        assert!(zcash_keys::address::Address::decode(&MAIN_NETWORK, "u1xxx").is_none());
    }

    /// The chain rule: claim/update/release openings all differ, and the
    /// expiry is cryptographically bound (changing only `e` changes both
    /// field elements).
    #[test]
    fn openings_bind_expiry_and_chain() {
        let name = test_name();
        let ua = test_ua();
        let prev = NameCommitment::from_bytes(&[1u8; 32]).unwrap();
        let t = Timestamp::from_seconds(1_000).unwrap();

        let claim_never = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::Never,
        };
        let rcm_never = claim_never.rcm(&MAIN_NETWORK);
        let psi_never = claim_never.psi(&MAIN_NETWORK);
        let claim_at = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::At(t),
        };
        let rcm_at = claim_at.rcm(&MAIN_NETWORK);
        let psi_at = claim_at.psi(&MAIN_NETWORK);
        assert_ne!(rcm_never, rcm_at);
        assert_ne!(psi_never, psi_at);

        let rcm_upd = NameNote::Update {
            name,
            ua,
            expires_at: Expiry::At(t),
            prev,
        }
        .rcm(&MAIN_NETWORK);
        assert_ne!(rcm_at, rcm_upd);
    }

    /// Canonical-decimal strictness: `e` bytes are hashed into σ, so
    /// non-canonical spellings must be rejected by the parser rather than
    /// silently accepted as the same value.
    #[test]
    fn expiry_parsing_is_canonical() {
        assert_eq!(
            Expiry::parse("0"),
            Some(Expiry::At(Timestamp::from_seconds(0).unwrap()))
        );
        assert_eq!(
            Expiry::parse("1"),
            Some(Expiry::At(Timestamp::from_seconds(1).unwrap()))
        );
        assert_eq!(Expiry::parse("01"), None);
        assert_eq!(Expiry::parse("+1"), None);
        assert_eq!(Expiry::parse(""), None);
        assert_eq!(Expiry::parse("1a"), None);

        assert_eq!(Expiry::parse("none"), Some(Expiry::Never));
        assert_eq!(Expiry::parse("None"), None);
        assert_eq!(
            Expiry::parse("1000"),
            Some(Expiry::At(Timestamp::from_seconds(1000).unwrap()))
        );
    }

    /// A release must encode its released UA and exactly `none`; a claim must
    /// use the zero predecessor; an update must have a nonzero one.
    #[test]
    fn grammar_rejects_inconsistent_fields() {
        let name = Name::parse("bob").unwrap();
        let ua = test_ua();
        let prev = NameCommitment::from_bytes(&[1u8; 32]).unwrap();
        let t = Expiry::At(Timestamp::from_seconds(5).unwrap());

        let mut m = NameNote::Release {
            name: name.clone(),
            ua: ua.clone(),
            prev,
        }
        .encode(&MAIN_NETWORK);
        assert!(NameNote::decode(&MAIN_NETWORK, &m).is_some());
        // Releases must use the literal expiry `none`.
        let forged = format!(
            "ZNS:release:{}:{}:1000:{}",
            name.as_str(),
            TEST_UA,
            hex::encode([1u8; 32])
        );
        m[..forged.len()].copy_from_slice(forged.as_bytes());
        assert!(NameNote::decode(&MAIN_NETWORK, &m).is_none());

        // The released UA is mandatory.
        let forged = format!(
            "ZNS:release:{}::none:{}",
            name.as_str(),
            hex::encode([1u8; 32])
        );
        m.fill(0);
        m[..forged.len()].copy_from_slice(forged.as_bytes());
        assert!(NameNote::decode(&MAIN_NETWORK, &m).is_none());

        // Claim with a nonzero predecessor is not a claim.
        let mut m2 = NameNote::Claim {
            name,
            ua,
            expires_at: t,
        }
        .encode(&MAIN_NETWORK);
        let forged = format!("ZNS:claim:bob:{}:none:{}", TEST_UA, hex::encode([1u8; 32]));
        m2[..forged.len()].copy_from_slice(forged.as_bytes());
        assert!(NameNote::decode(&MAIN_NETWORK, &m2).is_none());
    }

    #[test]
    fn expiry_test_semantics() {
        let t = Timestamp::from_seconds(1_000).unwrap();
        assert!(Expiry::At(t).expired(Timestamp::from_seconds(1_000).unwrap())); // mtp >= expires_at
        assert!(Expiry::At(t).expired(Timestamp::from_seconds(1_001).unwrap()));
        assert!(!Expiry::At(t).expired(Timestamp::from_seconds(999).unwrap()));
        assert!(!Expiry::Never.expired(Timestamp::MAX));
    }

    #[test]
    fn term_parse_is_strict() {
        assert_eq!(Term::parse("forever"), Some(Term::Forever));
        assert_eq!(Term::parse("1y"), Some(Term::Years(1)));
        assert_eq!(Term::parse("12y"), Some(Term::Years(12)));
        assert_eq!(Term::parse("99y"), Some(Term::Years(99)));
        // Missing y, over the cap, zero, leading zero, seconds, empty.
        assert_eq!(Term::parse("5"), None);
        assert_eq!(Term::parse("100y"), None);
        assert_eq!(Term::parse("0y"), None);
        assert_eq!(Term::parse("01y"), None);
        assert_eq!(Term::parse("31536000"), None);
        assert_eq!(Term::parse(""), None);
        assert_eq!(Term::parse("none"), None);
    }

    #[test]
    fn claim_expiry_maps_forever_to_never() {
        let mtp = Timestamp::from_seconds(1_000).unwrap();
        assert_eq!(
            Term::parse("forever").unwrap().claim_expiry(mtp),
            Some(Expiry::Never)
        );
        assert_eq!(
            Term::parse("2y").unwrap().claim_expiry(mtp),
            Some(Expiry::At(Timestamp::from_seconds(63_116_200).unwrap()))
        );
    }

    #[test]
    fn update_extend_banks_from_the_current_expiry() {
        let mtp = Timestamp::from_seconds(1_000).unwrap();
        let term = Term::parse("5y").unwrap();
        // Banking: 5 years from the current expiry, not from now.
        assert_eq!(
            Expiry::At(mtp).extend(Some(term), mtp),
            Some(Expiry::At(mtp.checked_add(term.duration()).unwrap()))
        );
        // Forever has no end date, so years cannot be added to it.
        assert_eq!(Expiry::Never.extend(Some(term), mtp), None);
        assert_eq!(Expiry::Never.extend(None, mtp), Some(Expiry::Never));
        assert_eq!(Expiry::At(mtp).extend(None, mtp), Some(Expiry::At(mtp)));
    }

    #[test]
    fn update_extend_forever_upgrades_at_records() {
        let mtp = Timestamp::from_seconds(1_000).unwrap();
        // The upgrade: At + forever converts the registration kind.
        assert_eq!(
            Expiry::At(mtp).extend(Some(Term::Forever), mtp),
            Some(Expiry::Never)
        );
        // Second upgrade / banking on forever: still refused — the tier
        // is terminal in both directions.
        assert_eq!(Expiry::Never.extend(Some(Term::Forever), mtp), None);
    }

    #[test]
    fn update_extend_never_banks_past_the_horizon() {
        // The fence: the resulting expiry never sits more than 99 years
        // ahead of MTP. 98 banked + 5 more crosses it; 96 + 3 lands on it.
        let mtp = Timestamp::from_seconds(0).unwrap();
        let at = |n: i64| {
            Expiry::At(
                mtp.checked_add(time::Duration::seconds(n * LIVENESS_INTERVAL))
                    .unwrap(),
            )
        };

        assert_eq!(at(98).extend(Some(Term::parse("5y").unwrap()), mtp), None);
        assert_eq!(
            at(96).extend(Some(Term::parse("3y").unwrap()), mtp),
            Some(at(99))
        );
        assert_eq!(
            at(50).extend(Some(Term::parse("3y").unwrap()), mtp),
            Some(at(53))
        );
    }

    #[test]
    fn queue_admit_is_idempotent_and_removes() {
        let claim = NameNote::Claim {
            name: test_name(),
            ua: test_ua(),
            expires_at: Expiry::Never,
        };
        let h = |n: u32| BlockHeight::from_u32(n);

        let mut queue = NameNoteQueue::default();
        assert!(!queue.claim_pending(claim.name()));

        queue.admit(h(10), claim.clone());
        // A re-derived decision keeps its original origin.
        queue.admit(h(12), claim.clone());
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.entry(0).1, h(10));
        assert!(queue.claim_pending(claim.name()));

        // The drain resolved the order — enacted, or overtaken: the
        // queue forgets the decision.
        queue.remove(0);
        assert!(queue.is_empty());
        assert!(!queue.claim_pending(claim.name()));

        // Re-derivation may re-admit what still stands (releases).
        queue.admit(h(12), claim);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn queue_remove_shifts_neighbors() {
        let prev = NameCommitment::from_bytes(&[1u8; 32]).unwrap();
        let claim = |name: &str| NameNote::Claim {
            name: Name::parse(name).unwrap(),
            ua: test_ua(),
            expires_at: Expiry::Never,
        };
        let update = NameNote::Update {
            name: test_name(),
            ua: test_ua(),
            expires_at: Expiry::Never,
            prev,
        };
        let h = |n: u32| BlockHeight::from_u32(n);

        let mut queue = NameNoteQueue::default();
        queue.admit(h(100), claim("alice"));
        queue.admit(h(101), claim("bob"));
        queue.admit(h(102), update);

        // Removing the entry the cursor resolved shifts its neighbors:
        // the update lands under the cursor's index, admission order
        // otherwise intact.
        queue.remove(1);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.entry(1).0.action(), Action::Update);
        assert_eq!(queue.entry(1).1, h(102));
        assert_eq!(queue.entry(0).0.name().as_str(), "alice");
    }

    #[test]
    fn queue_truncate_drops_only_orphaned_origins() {
        let prev = NameCommitment::from_bytes(&[1u8; 32]).unwrap();
        let claim = NameNote::Claim {
            name: test_name(),
            ua: test_ua(),
            expires_at: Expiry::Never,
        };
        let update = NameNote::Update {
            name: test_name(),
            ua: test_ua(),
            expires_at: Expiry::Never,
            prev,
        };
        let h = |n: u32| BlockHeight::from_u32(n);

        let mut queue = NameNoteQueue::default();
        queue.admit(h(100), claim);
        queue.admit(h(150), update);

        // A reorg to height 120 orphans only the later decision.
        queue.truncate_to(h(120));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.entry(0).0.action(), Action::Claim);
    }

    #[test]
    fn queue_claim_guard_scopes_by_name() {
        let prev = NameCommitment::from_bytes(&[1u8; 32]).unwrap();
        let bob = Name::parse("bob").unwrap();
        let h = |n: u32| BlockHeight::from_u32(n);

        let mut queue = NameNoteQueue::default();
        // An open update is not an open claim.
        queue.admit(
            h(10),
            NameNote::Update {
                name: bob.clone(),
                ua: test_ua(),
                expires_at: Expiry::Never,
                prev,
            },
        );
        assert!(!queue.claim_pending(&bob));

        queue.admit(
            h(11),
            NameNote::Claim {
                name: bob.clone(),
                ua: test_ua(),
                expires_at: Expiry::Never,
            },
        );
        assert!(queue.claim_pending(&bob));
        // Other names are unblocked.
        assert!(!queue.claim_pending(&test_name()));
    }
}
