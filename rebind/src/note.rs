//! The live mint's Name Notes, copied from zns-mint `46f61f9`
//! (`src/mint.rs`, `src/mint/note.rs`): the format zns-rebind reads and
//! moves. Do not change this law; it is mainnet's.
//!
//! In this format a note sets its rcm and ψ directly from its memo
//! (`zns_rcm`, `zns_psi`), and `prev` holds the predecessor's **rcm**, not
//! its cmx. [`NameRcm`] is that rcm. It is not `zns_mint::mint::NameRcm`,
//! which on master is a cmx.
//!
//! The copy is verbatim apart from imports, that rename, and what cannot
//! compile without the rest of the old mint (`Term`, `Expiry::extend`).
//! zns-rebind does not call every item it keeps.
#![allow(dead_code, clippy::wrong_self_convention)]

use orchard::note::Psi;
use subtle::ConstantTimeEq as _;
use zcash_address::unified::Encoding;
use zcash_primitives::block::Block;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::Parameters;
use zns_mint::mint::Timestamp;
use zns_mint::mint::UnifiedAddress;
use zns_mint::RegistryKeys;

/// The liveness interval: one Julian year (365.25 days), in seconds.
pub const LIVENESS_INTERVAL: i64 = 31_557_600;

/// The longest name a memo accepts.
pub const MAX_NAME_LEN: usize = 63;

/// ZNS action kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Point a name to an address
    Claim,
    /// Rebinds a name to a new address
    Update,
    /// Terminates a name's linkage to an address
    Release,
}

impl Action {
    /// Returns the canonical ASCII verb for this action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Claim => "claim",
            Action::Update => "update",
            Action::Release => "release",
        }
    }

    /// Parses the canonical ASCII verb — the inverse of [`Self::as_str`].
    pub fn parse(verb: &str) -> Option<Self> {
        match verb {
            "claim" => Some(Action::Claim),
            "update" => Some(Action::Update),
            "release" => Some(Action::Release),
            _ => None,
        }
    }

    /// True when this action terminates a registration.
    pub const fn is_release(self) -> bool {
        matches!(self, Action::Release)
    }

    /// True when this action creates a fresh registration (spends an
    /// anchor, not a predecessor).
    pub const fn is_claim(self) -> bool {
        matches!(self, Action::Claim)
    }

    /// True when this action rebinds an existing registration to a new
    /// address or term.
    pub const fn is_update(self) -> bool {
        matches!(self, Action::Update)
    }

    /// True when this action spends the registration's current note as
    /// its authority; a claim spends an anchor instead.
    pub const fn needs_predecessor(self) -> bool {
        matches!(self, Action::Update | Action::Release)
    }
}

/// A ZNS name-chain commitment — the trapdoor that links consecutive Name Notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameRcm(orchard::note::NoteCommitTrapdoor);

impl NameRcm {
    /// Wraps a `NoteCommitTrapdoor` derived via [`NameNote::rcm`].
    pub fn from_inner(inner: orchard::note::NoteCommitTrapdoor) -> Self {
        Self(inner)
    }

    /// Unwraps back to the upstream type for the `unsafe-zns` builder surface.
    pub fn into_inner(self) -> orchard::note::NoteCommitTrapdoor {
        self.0
    }

    /// Deserializes from the canonical 32-byte little-endian representation.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        orchard::note::NoteCommitTrapdoor::from_bytes(bytes)
            .into_option()
            .map(Self)
    }

    /// Serializes to the canonical 32-byte little-endian representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A ZcashName
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// Attempts to parse a string into a valid ZNS name.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return None;
        }
        if bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9')) {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
        prev: NameRcm,
    },
    /// Terminate the registration, retaining the address that was released.
    /// Releases always encode the exact expiry field `none`.
    Release {
        name: Name,
        ua: UnifiedAddress,
        prev: NameRcm,
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
    pub fn prev_rcm(&self) -> Option<NameRcm> {
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

    /// The note's ZNS commitment: the rcm wrapped as the chain's
    /// identity.
    pub fn commitment<P: Parameters>(&self, params: &P) -> NameRcm {
        NameRcm::from_inner(orchard::note::NoteCommitTrapdoor::from_inner(
            self.rcm(params),
        ))
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
    let mut h = blake2b_simd::State::new();
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
    *h.finalize().as_array()
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
        let ua_str = parts[3];
        let ua = {
            let (net, revision, container) =
                zcash_address::unified::Address::decode(ua_str).ok()?;
            if net != params.network_type() || revision != zcash_address::unified::Revision::R0 {
                return None;
            }
            UnifiedAddress::try_from(container).ok()?
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
                    prev: NameRcm::from_bytes(&prev_rcm_bytes)?,
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
                    prev: NameRcm::from_bytes(&prev_rcm_bytes)?,
                }
            }
        };

        (note.encode(params).as_slice() == memo).then_some(note)
    }
}

// ---------------------------------------------------------------------------
// Block scan: ZNS trial-decryption pass
// ---------------------------------------------------------------------------

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
                        let psi = Psi::from_inner(payload.psi(network));
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
