//! Name Notes: the typed transition, its memo codec, and the ZNS commitment
//! derivation.
//!
//! A [`NameNote`] is one name transition as the whitepaper defines it — a
//! variant enum in which illegal field combinations are unrepresentable
//! (a claim has no predecessor; a release retains the released address and
//! always has the `none` expiry).
//! The 512-byte memo grammar and the σ-hash are functions *over* the type,
//! not constructors of it.

use time::Timestamp;
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::Parameters;

use crate::mint::{Action, Name, NameCommitment};

/// Parses canonical ASCII decimal into a [`Timestamp`]: digits only, no
/// sign, no leading zeroes (except `0` itself). Non-canonical spellings
/// are rejected because the raw field bytes are hashed into σ — `1` and
/// `01` are different transitions with different commitments.
pub fn parse_timestamp_canonical(s: &str) -> Option<Timestamp> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    let seconds: i64 = s.parse().ok()?;
    Timestamp::from_seconds(seconds).ok()
}

/// A duration in whole seconds — what a user requests as a registration
/// term or extension (§4.5.3). Never an instant; never compared to MTP.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TermSeconds(pub u64);

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
    pub fn parse(field: &str) -> Option<Self> {
        match field {
            "none" => Some(Expiry::Never),
            digits => parse_timestamp_canonical(digits).map(Expiry::At),
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

/// One name transition (§3.2), typed so every action carries exactly its
/// legal fields.
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for NameNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameNote(<redacted>)")
    }
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
    pub fn ua(&self) -> Option<&UnifiedAddress> {
        match self {
            NameNote::Claim { ua, .. }
            | NameNote::Update { ua, .. }
            | NameNote::Release { ua, .. } => Some(ua),
        }
    }

    /// Parses a UA string into the typed upstream form for this network.
    /// The single validation boundary: ZIP 316 grammar, receiver order, and
    /// network prefix are all enforced here (§3.5 — invalid UAs must fail
    /// validation before a transition affects registry state).
    pub fn parse_ua<P: Parameters>(params: &P, s: &str) -> Option<UnifiedAddress> {
        let zaddr: zcash_address::ZcashAddress = s.parse().ok()?;
        match zaddr.convert_if_network(params.network_type()).ok()? {
            zcash_keys::address::Address::Unified(ua) => Some(ua),
            _ => None,
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

    /// The ZNS commitment opening bound to this exact transition. The UA
    /// field's canonical encoding (network prefix included) is hashed into
    /// σ, so the opening is parameter-dependent.
    pub fn opening<P: Parameters>(
        &self,
        params: &P,
    ) -> (pasta_curves::pallas::Scalar, pasta_curves::pallas::Base) {
        let verb: &[u8] = match self {
            NameNote::Claim { .. } => b"claim",
            NameNote::Update { .. } => b"update",
            NameNote::Release { .. } => b"release",
        };
        let name = self.name().as_str().as_bytes();
        let ua_owned = self.ua().map(|ua| ua.encode(params));
        let ua = ua_owned.as_deref().unwrap_or("").as_bytes();
        let expiry = self.expires_field_bytes();
        let prev = self.prev_rcm().map(|r| r.to_bytes()).unwrap_or([0u8; 32]);
        zns_psi_rcm_raw(verb, name, ua, &expiry, &prev)
    }

    /// The `expires_at` field bytes as the memo and σ encode them: `none`
    /// for a release (§3.1: a release MUST encode `none`).
    fn expires_field_bytes(&self) -> Vec<u8> {
        self.expires_at().unwrap_or(Expiry::Never).field_bytes()
    }

    /// The `ua` field string: the canonical encoding for every action.
    fn ua_field_string<P: Parameters>(&self, params: &P) -> Option<String> {
        match self.ua() {
            Some(ua) => Some(ua.encode(params)),
            None => None,
        }
    }

    /// Encodes into the canonical zero-padded 512-byte memo under `params`.
    ///
    /// `None` when the fields overflow 512 bytes. The UA field is the
    /// canonical ZIP 316 encoding (bech32m: ASCII, no colon, no NUL), empty
    /// for a release.
    pub fn encode<P: Parameters>(&self, params: &P) -> Option<[u8; 512]> {
        let ua_field = self.ua_field_string(params)?;
        let verb = self.action().as_str();
        let hex_rcm = hex::encode(self.prev_rcm().map(|r| r.to_bytes()).unwrap_or([0u8; 32]));
        let expires_field = self.expires_field_bytes();
        let memo_string = format!(
            "ZNS:{}:{}:{}:{}:{}",
            verb,
            self.name().as_str(),
            ua_field,
            String::from_utf8(expires_field).ok()?,
            hex_rcm,
        );
        let bytes = memo_string.as_bytes();
        if bytes.len() > 512 {
            return None;
        }
        let mut memo = [0u8; 512];
        memo[..bytes.len()].copy_from_slice(bytes);
        Some(memo)
    }
}

/// Derives the ZNS commitment inputs `(rcm, ψ)` for a transition (§3.3):
/// BLAKE2b-512 over the length-prefixed fields with tag `rcm` / `psi`,
/// wide-reduced into the Pallas scalar and base fields respectively.
pub fn zns_psi_rcm_raw(
    verb: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    prev_rcm_bytes: &[u8; 32],
) -> (pasta_curves::pallas::Scalar, pasta_curves::pallas::Base) {
    use pasta_curves::group::ff::FromUniformBytes;

    let psi = pasta_curves::pallas::Base::from_uniform_bytes(&tagged_zns_hash(
        b"psi",
        verb,
        name,
        ua,
        expires_at,
        prev_rcm_bytes,
    ));
    let rcm = pasta_curves::pallas::Scalar::from_uniform_bytes(&tagged_zns_hash(
        b"rcm",
        verb,
        name,
        ua,
        expires_at,
        prev_rcm_bytes,
    ));

    (rcm, psi)
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

/// Decodes a 512-byte memo into a typed [`NameNote`].
///
/// Accepts exactly the canonical encoding: trailing-zero stripping, the
/// six-field grammar, canonical decimal or `none` expiry, 64-char lowercase
/// hex predecessor, action-consistent fields (release: a valid UA and `none`
/// expiry; claim: zero predecessor; update/release: nonzero predecessor),
/// and a re-encode that reproduces the input byte-for-byte.
pub fn decode_name_note<P: Parameters>(params: &P, memo: &[u8; 512]) -> Option<NameNote> {
    let end = memo.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let memo_str = std::str::from_utf8(&memo[..end]).ok()?;

    let parts: Vec<&str> = memo_str.split(':').collect();
    if parts.len() != 6 || parts[0] != "ZNS" {
        return None;
    }

    let name = Name::parse(parts[2])?;
    // The single UA validation boundary: a memo whose ua field is not a
    // valid ZIP 316 Unified Address for this network decodes to no note.
    let ua_str = parts[3];
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

    let note = match parts[1] {
        "claim" => {
            if prev_rcm_bytes != [0u8; 32] || ua_str.is_empty() {
                return None;
            }
            NameNote::Claim {
                name,
                ua: NameNote::parse_ua(params, ua_str)?,
                expires_at,
            }
        }
        "update" => {
            if prev_rcm_bytes == [0u8; 32] || ua_str.is_empty() {
                return None;
            }
            NameNote::Update {
                name,
                ua: NameNote::parse_ua(params, ua_str)?,
                expires_at,
                prev: NameCommitment::from_bytes(&prev_rcm_bytes)?,
            }
        }
        // A release MUST retain the released UA and encode the exact value
        // `none` for its expiry.
        "release" => {
            if ua_str.is_empty() || expires_at != Expiry::Never || prev_rcm_bytes == [0u8; 32] {
                return None;
            }
            NameNote::Release {
                name,
                ua: NameNote::parse_ua(params, ua_str)?,
                prev: NameCommitment::from_bytes(&prev_rcm_bytes)?,
            }
        }
        _ => return None,
    };

    (note.encode(params)?.as_slice() == memo).then_some(note)
}

/// Compatibility wrapper preserving the tuple-returning call sites.
pub fn decode_name_note_tuple<P: Parameters>(
    params: &P,
    memo: &[u8; 512],
) -> Option<(Name, Action, String, Expiry, Option<NameCommitment>)> {
    let note = decode_name_note(params, memo)?;
    Some((
        note.name().clone(),
        note.action(),
        note.ua().map(|ua| ua.encode(params)).unwrap_or_default(),
        note.expires_at().unwrap_or(Expiry::Never),
        note.prev_rcm(),
    ))
}

// ---------------------------------------------------------------------------
// Block scan: ZNS trial-decryption pass
// ---------------------------------------------------------------------------

use subtle::ConstantTimeEq as _;
use zcash_primitives::block::Block;
use zcash_primitives::transaction::TxId;

/// One decrypted Name Note from the ZNS scan pass, with the facts the wallet
/// store and the Registry evidence need.
pub struct DecryptedNameNote {
    pub txid: TxId,
    pub action_index: usize,
    /// The action's index in the block's full Ironwood commitment stream —
    /// fixes the note's tree position.
    pub ordinal: usize,
    pub note: orchard::note::Note,
    /// The epk bytes directly — the `ShieldedOutput` trait method is
    /// ambiguous across the three Ironwood-family domains.
    pub ephemeral_key: zcash_note_encryption::EphemeralKeyBytes,
    pub memo: [u8; 512],
    pub payload: NameNote,
}

/// Trial-decrypts the block's Ironwood actions under the ZNS domain.
///
/// A candidate is exposed only if its memo parses as a Name Note and the
/// payload-derived ZNS commitment reproduces the action's actual cmx — the
/// cryptographic authorship check. Value must be zero and the recipient must
/// be the exact Registry address; anything else is not a Name Note.
pub fn decrypt_name_notes<P: Parameters>(
    network: &P,
    block: &Block,
    registry_ivk: &orchard::keys::PreparedIncomingViewingKey,
    registry_recipient: orchard::Address,
) -> Vec<DecryptedNameNote> {
    use pasta_curves::group::ff::PrimeField as _;

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
                if let Some((note, recipient, memo)) =
                    orchard::note_encryption::ZnsIronwoodDomain::for_action(action).try_decrypt(
                        action,
                        registry_ivk,
                        |note, memo, cmx| {
                            let payload = match decode_name_note(network, memo) {
                                Some(p) => p,
                                None => return subtle::Choice::from(0),
                            };
                            let (rcm, psi) = payload.opening(network);
                            let (g_d, pk_d) = note.recipient().zns_commitment_keys();
                            let rho = Option::from(pasta_curves::pallas::Base::from_repr(
                                note.rho().to_bytes(),
                            ))
                            .expect("valid rho");
                            let computed = match note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm) {
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
                        let payload = decode_name_note(network, &memo)
                            .expect("memo was validated in callback");
                        candidates.push(DecryptedNameNote {
                            txid: tx.txid(),
                            action_index,
                            ordinal,
                            note,
                            ephemeral_key: zcash_note_encryption::EphemeralKeyBytes(
                                action.encrypted_note().epk_bytes,
                            ),
                            memo,
                            payload,
                        });
                    }
                }
            }
            ordinal += 1;
        }
    }
    candidates
}

// ---------------------------------------------------------------------------
// cmx helper — copied from zns-verify (standalone Sinsemilla, no orchard dep)
// ---------------------------------------------------------------------------

use pasta_curves::group::ff::PrimeField;
use sinsemilla::CommitDomain;

/// Sinsemilla personalization tag for Orchard note commitments.
const NOTE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-NoteCommit";

/// Number of bits taken from each Pallas base-field input (rho, psi).
const L_ORCHARD_BASE: usize = 255;

fn le_bytes_lsb0(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .copied()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 != 0))
}

/// Computes cmx from raw note components plus caller-supplied (ψ, rcm).
/// Used by the scanner to validate a decrypted Name Note's ZNS-derived
/// commitment against the on-chain cmx.
pub fn note_commitment_cmx(
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: pasta_curves::pallas::Base,
    psi: pasta_curves::pallas::Base,
    rcm: pasta_curves::pallas::Scalar,
) -> Option<pasta_curves::pallas::Base> {
    let domain = CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
    let value_bytes = value.to_le_bytes();
    let rho_bytes = rho.to_repr();
    let psi_bytes = psi.to_repr();

    let bits = le_bytes_lsb0(&g_d)
        .chain(le_bytes_lsb0(&pk_d))
        .chain(le_bytes_lsb0(&value_bytes))
        .chain(le_bytes_lsb0(rho_bytes.as_ref()).take(L_ORCHARD_BASE))
        .chain(le_bytes_lsb0(psi_bytes.as_ref()).take(L_ORCHARD_BASE));

    Option::<pasta_curves::pallas::Base>::from(domain.short_commit(bits, &rcm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MAIN_NETWORK;

    /// A valid mainnet ZIP-316 UA with an Orchard receiver (zcash_address
    /// test vector): parses, round-trips byte-exact, and carries orchard().
    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    fn test_ua() -> UnifiedAddress {
        NameNote::parse_ua(&MAIN_NETWORK, TEST_UA).expect("vector UA parses")
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
            decode_name_note(&MAIN_NETWORK, &claim.encode(&MAIN_NETWORK).unwrap()).as_ref(),
            Some(&claim)
        );

        let t = Timestamp::from_seconds(1_775_000_000).unwrap();
        let claim_t = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::At(t),
        };
        assert_eq!(
            decode_name_note(&MAIN_NETWORK, &claim_t.encode(&MAIN_NETWORK).unwrap()).as_ref(),
            Some(&claim_t)
        );

        let update = NameNote::Update {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::At(t),
            prev,
        };
        assert_eq!(
            decode_name_note(&MAIN_NETWORK, &update.encode(&MAIN_NETWORK).unwrap()).as_ref(),
            Some(&update)
        );

        let release = NameNote::Release { name, ua, prev };
        assert_eq!(
            decode_name_note(&MAIN_NETWORK, &release.encode(&MAIN_NETWORK).unwrap()).as_ref(),
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
        assert!(decode_name_note(&MAIN_NETWORK, &m).is_none());
        assert!(NameNote::parse_ua(&MAIN_NETWORK, "u1xxx").is_none());
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

        let (rcm_never, psi_never) = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::Never,
        }
        .opening(&MAIN_NETWORK);
        let (rcm_at, psi_at) = NameNote::Claim {
            name: name.clone(),
            ua: ua.clone(),
            expires_at: Expiry::At(t),
        }
        .opening(&MAIN_NETWORK);
        assert_ne!(rcm_never.to_repr(), rcm_at.to_repr());
        assert_ne!(psi_never, psi_at);

        let (rcm_upd, _) = NameNote::Update {
            name,
            ua,
            expires_at: Expiry::At(t),
            prev,
        }
        .opening(&MAIN_NETWORK);
        assert_ne!(rcm_at.to_repr(), rcm_upd.to_repr());
    }

    /// Canonical-decimal strictness: `e` bytes are hashed into σ, so
    /// non-canonical spellings must be rejected by the parser rather than
    /// silently accepted as the same value.
    #[test]
    fn expiry_parsing_is_canonical() {
        assert_eq!(
            parse_timestamp_canonical("0"),
            Some(Timestamp::from_seconds(0).unwrap())
        );
        assert_eq!(
            parse_timestamp_canonical("1"),
            Some(Timestamp::from_seconds(1).unwrap())
        );
        assert_eq!(parse_timestamp_canonical("01"), None);
        assert_eq!(parse_timestamp_canonical("+1"), None);
        assert_eq!(parse_timestamp_canonical(""), None);
        assert_eq!(parse_timestamp_canonical("1a"), None);

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
        .encode(&MAIN_NETWORK)
        .unwrap();
        assert!(decode_name_note(&MAIN_NETWORK, &m).is_some());
        // Releases must use the literal expiry `none`.
        let forged = format!(
            "ZNS:release:{}:{}:1000:{}",
            name.as_str(),
            TEST_UA,
            hex::encode([1u8; 32])
        );
        m[..forged.len()].copy_from_slice(forged.as_bytes());
        assert!(decode_name_note(&MAIN_NETWORK, &m).is_none());

        // The released UA is mandatory.
        let forged = format!(
            "ZNS:release:{}::none:{}",
            name.as_str(),
            hex::encode([1u8; 32])
        );
        m.fill(0);
        m[..forged.len()].copy_from_slice(forged.as_bytes());
        assert!(decode_name_note(&MAIN_NETWORK, &m).is_none());

        // Claim with a nonzero predecessor is not a claim.
        let mut m2 = NameNote::Claim {
            name,
            ua,
            expires_at: t,
        }
        .encode(&MAIN_NETWORK)
        .unwrap();
        let forged = format!("ZNS:claim:bob:{}:none:{}", TEST_UA, hex::encode([1u8; 32]));
        m2[..forged.len()].copy_from_slice(forged.as_bytes());
        assert!(decode_name_note(&MAIN_NETWORK, &m2).is_none());
    }

    #[test]
    fn expiry_test_semantics() {
        let t = Timestamp::from_seconds(1_000).unwrap();
        assert!(Expiry::At(t).expired(Timestamp::from_seconds(1_000).unwrap())); // mtp >= expires_at
        assert!(Expiry::At(t).expired(Timestamp::from_seconds(1_001).unwrap()));
        assert!(!Expiry::At(t).expired(Timestamp::from_seconds(999).unwrap()));
        assert!(!Expiry::Never.expired(Timestamp::MAX));
    }
}
