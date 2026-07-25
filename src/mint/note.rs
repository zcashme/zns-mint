//! Name Note derivation and memo codec.
//!
//! This module houses the cryptographic scalar derivation ([`zns_psi_rcm`])
//! and the 512-byte memo encode/decode pair ([`encode_name_note`],
//! [`decode_name_note`]) that together define the Name Note's on-chain
//! representation.

use super::{Action, Name, NameCommitment, UnifiedAddress};

/// A canonical parsed Name Note memo payload.
#[derive(Clone, PartialEq, Eq)]
pub struct NameNotePayload {
    name: Name,
    action: Action,
    ua: UnifiedAddress,
    prev_rcm: Option<NameCommitment>,
}

impl std::fmt::Debug for NameNotePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameNotePayload(<redacted>)")
    }
}

impl NameNotePayload {
    /// Constructs a canonical action-consistent Name Note payload.
    pub fn new(
        name: Name,
        action: Action,
        ua: UnifiedAddress,
        prev_rcm: Option<NameCommitment>,
    ) -> Option<Self> {
        let ua_bytes = ua.as_str().as_bytes();
        if !ua_bytes.is_ascii() || ua_bytes.contains(&b':') || ua_bytes.contains(&0) {
            return None;
        }

        let fields_match_action = match action {
            Action::Claim => !ua.is_empty() && prev_rcm.is_none(),
            Action::Update => !ua.is_empty() && prev_rcm.is_some(),
            Action::Release => ua.is_empty() && prev_rcm.is_some(),
        };
        fields_match_action.then_some(Self {
            name,
            action,
            ua,
            prev_rcm,
        })
    }

    /// Returns the canonical name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Returns the lifecycle action.
    pub fn action(&self) -> Action {
        self.action
    }

    /// Returns the bound Unified Address string.
    pub fn ua(&self) -> &UnifiedAddress {
        &self.ua
    }

    /// Returns the predecessor chain commitment, absent only for claims.
    pub fn prev_rcm(&self) -> Option<NameCommitment> {
        self.prev_rcm
    }

    /// Derives the commitment opening bound to this exact parsed payload.
    pub fn opening(&self) -> (pasta_curves::pallas::Scalar, pasta_curves::pallas::Base) {
        zns_psi_rcm(&self.name, self.action, self.ua.as_str(), self.prev_rcm)
    }

    /// Encodes this payload into its canonical zero-padded memo form.
    pub fn encode(&self) -> Option<[u8; 512]> {
        encode_name_note_fields(&self.name, self.action, self.ua.as_str(), self.prev_rcm)
    }
}

/// Derives the ZNS payload scalars `(rcm, psi)` for the Orchard `unsafe-zns` circuit.
///
/// Hashes the ZNS properties (name, action, unified address, and previous commitment)
/// using BLAKE2b-512, wide-reduced into Pallas field elements.
pub fn zns_psi_rcm(
    name: &Name,
    action: Action,
    ua: &str,
    prev_rcm: Option<NameCommitment>,
) -> (pasta_curves::pallas::Scalar, pasta_curves::pallas::Base) {
    let prev_rcm_bytes = prev_rcm.map(|r| r.to_bytes()).unwrap_or([0u8; 32]);
    zns_psi_rcm_raw(name, action, ua, &prev_rcm_bytes)
}

/// A raw byte-level variant of `zns_psi_rcm` for cross-language test vectors
/// that may use out-of-field byte arrays for testing the Sinsemilla construction.
pub fn zns_psi_rcm_raw(
    name: &Name,
    action: Action,
    ua: &str,
    prev_rcm_bytes: &[u8; 32],
) -> (pasta_curves::pallas::Scalar, pasta_curves::pallas::Base) {
    use pasta_curves::group::ff::FromUniformBytes;

    let action_bytes: &[u8] = match action {
        Action::Claim => b"claim",
        Action::Update => b"update",
        Action::Release => b"release",
    };

    // Release action forces an empty UA
    let ua_bytes = if action == Action::Release {
        b""
    } else {
        ua.as_bytes()
    };
    let name_bytes = name.as_str().as_bytes();

    let psi = pasta_curves::pallas::Base::from_uniform_bytes(&tagged_zns_hash(
        b"psi",
        action_bytes,
        name_bytes,
        ua_bytes,
        prev_rcm_bytes,
    ));
    let rcm = pasta_curves::pallas::Scalar::from_uniform_bytes(&tagged_zns_hash(
        b"rcm",
        action_bytes,
        name_bytes,
        ua_bytes,
        prev_rcm_bytes,
    ));

    (rcm, psi)
}

/// Compute the domain-tagged, length-prefixed BLAKE2b-512 hash.
fn tagged_zns_hash(
    field_tag: &[u8],
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
) -> [u8; 64] {
    let mut h = blake2b_simd::Params::new().hash_length(64).to_state();
    let mut absorb = |b: &[u8]| {
        h.update(&(b.len() as u32).to_le_bytes());
        h.update(b);
    };
    absorb(b"ZcashName/v1");
    absorb(field_tag);
    absorb(action);
    absorb(name);
    absorb(ua);
    h.update(prev_rcm);

    let mut out = [0u8; 64];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Encodes the ZNS properties into a 512-byte array to be stored in the Orchard memo field.
///
/// Follows the strict `zns-verify` protocol spec:
/// `ZNS:action:name:ua:prev_rcm` (zero-padded to 512 bytes).
pub fn encode_name_note(
    name: &Name,
    action: Action,
    ua: &str,
    prev_rcm: Option<NameCommitment>,
) -> Option<[u8; 512]> {
    let payload = NameNotePayload::new(
        name.clone(),
        action,
        UnifiedAddress::from_string(ua.to_string()),
        prev_rcm,
    )?;
    payload.encode()
}

fn encode_name_note_fields(
    name: &Name,
    action: Action,
    ua: &str,
    prev_rcm: Option<NameCommitment>,
) -> Option<[u8; 512]> {
    let action_str = match action {
        Action::Claim => "claim",
        Action::Update => "update",
        Action::Release => "release",
    };

    // A release note explicitly has an empty UA
    let ua_str = if action == Action::Release { "" } else { ua };
    let prev_rcm_bytes = prev_rcm.map(|r| r.to_bytes()).unwrap_or([0u8; 32]);
    let hex_rcm = hex::encode(prev_rcm_bytes);

    let memo_string = format!(
        "ZNS:{}:{}:{}:{}",
        action_str,
        name.as_str(),
        ua_str,
        hex_rcm
    );
    let bytes = memo_string.as_bytes();

    if bytes.len() > 512 {
        return None;
    }

    let mut memo = [0u8; 512];
    memo[..bytes.len()].copy_from_slice(bytes);
    Some(memo)
}

/// Decodes a 512-byte Orchard memo back into ZNS properties.
///
/// Strips trailing zeros and parses the colon-separated fields.
pub fn decode_name_note(
    memo: &[u8; 512],
) -> Option<(Name, Action, String, Option<NameCommitment>)> {
    let payload = decode_name_note_payload(memo)?;
    Some((
        payload.name,
        payload.action,
        payload.ua.into_string(),
        payload.prev_rcm,
    ))
}

/// Decodes a canonical 512-byte Name Note memo into a typed payload.
pub fn decode_name_note_payload(memo: &[u8; 512]) -> Option<NameNotePayload> {
    // Strip trailing zeros
    let end = memo.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let memo_str = std::str::from_utf8(&memo[..end]).ok()?;

    let parts: Vec<&str> = memo_str.split(':').collect();
    if parts.len() != 5 || parts[0] != "ZNS" {
        return None;
    }

    let action = match parts[1] {
        "claim" => Action::Claim,
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    let name = Name::parse(parts[2])?;

    // Releases must have an explicitly empty UA field
    if action == Action::Release && !parts[3].is_empty() {
        return None;
    }
    let ua = parts[3].to_string();

    let mut prev_rcm_bytes = [0u8; 32];
    if parts[4].len() != 64 {
        return None;
    }
    if !parts[4]
        .as_bytes()
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    hex::decode_to_slice(parts[4], &mut prev_rcm_bytes).ok()?;

    let prev_rcm = if prev_rcm_bytes == [0u8; 32] {
        None
    } else {
        Some(NameCommitment::from_bytes(&prev_rcm_bytes)?)
    };

    let payload = NameNotePayload::new(name, action, UnifiedAddress::from_string(ua), prev_rcm)?;

    (payload.encode()?.as_slice() == memo).then_some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Action, Name, NameCommitment};
    use pasta_curves::group::ff::PrimeField;

    /// The ZNS memo round-trip: encode → decode must preserve all fields.
    #[test]
    fn name_note_memo_round_trip() {
        let name = Name::parse("alice").unwrap();
        let ua = "u1abc123";

        // Claim: prev_rcm = None (zero bytes)
        let memo = encode_name_note(&name, Action::Claim, ua, None).unwrap();
        let (n, a, u, p) = decode_name_note(&memo).unwrap();
        assert_eq!(n, name);
        assert_eq!(a, Action::Claim);
        assert_eq!(u, ua);
        assert_eq!(p, None);

        // Update with a prev_rcm
        let prev_rcm_bytes = [1u8; 32];
        let prev_rcm = NameCommitment::from_bytes(&prev_rcm_bytes).unwrap();
        let memo = encode_name_note(&name, Action::Update, ua, Some(prev_rcm)).unwrap();
        let (n, a, u, p) = decode_name_note(&memo).unwrap();
        assert_eq!(n, name);
        assert_eq!(a, Action::Update);
        assert_eq!(u, ua);
        assert_eq!(p, Some(prev_rcm));

        // Release: UA must be empty
        let memo = encode_name_note(&name, Action::Release, "", Some(prev_rcm)).unwrap();
        let (n, a, u, p) = decode_name_note(&memo).unwrap();
        assert_eq!(n, name);
        assert_eq!(a, Action::Release);
        assert_eq!(u, "");
        assert_eq!(p, Some(prev_rcm));
    }

    /// The chain rule: a claim's rcm must differ from an update's rcm, and
    /// the update's rcm must depend on the claim's rcm (via prev_rcm).
    #[test]
    fn zns_psi_rcm_chain_rule() {
        let name = Name::parse("bob").unwrap();
        let ua = "u1def456";

        // Claim: no prev_rcm
        let (claim_rcm, claim_psi) = zns_psi_rcm(&name, Action::Claim, ua, None);

        // Update: prev_rcm = claim's rcm (encoded as NameCommitment)
        let claim_commitment = NameCommitment::from_inner(
            orchard::note::NoteCommitTrapdoor::from_bytes(&{
                let mut bytes = [0u8; 32];
                let rcm_bytes = claim_rcm.to_repr();
                bytes.copy_from_slice(rcm_bytes.as_ref());
                bytes
            })
            .into_option()
            .unwrap(),
        );
        let (update_rcm, update_psi) =
            zns_psi_rcm(&name, Action::Update, ua, Some(claim_commitment));

        // The chain: claim and update must produce different (rcm, psi)
        assert_ne!(
            claim_rcm.to_repr(),
            update_rcm.to_repr(),
            "claim and update rcm must differ"
        );
        assert_ne!(claim_psi, update_psi, "claim and update psi must differ");

        // Release from update: prev_rcm = update's rcm
        let update_commitment = NameCommitment::from_inner(
            orchard::note::NoteCommitTrapdoor::from_bytes(&{
                let mut bytes = [0u8; 32];
                let rcm_bytes = update_rcm.to_repr();
                bytes.copy_from_slice(rcm_bytes.as_ref());
                bytes
            })
            .into_option()
            .unwrap(),
        );
        let (release_rcm, release_psi) =
            zns_psi_rcm(&name, Action::Release, "", Some(update_commitment));

        assert_ne!(update_rcm.to_repr(), release_rcm.to_repr());
        assert_ne!(update_psi, release_psi);
    }

    /// A release must force empty UA in the memo and in the psi/rcm derivation.
    #[test]
    fn release_forces_empty_ua() {
        let name = Name::parse("carol").unwrap();
        let prev_rcm = NameCommitment::from_bytes(&[1u8; 32]).unwrap();

        // Release with a non-empty UA string — the function should ignore it
        // for the derivation (same result as empty UA).
        let (rcm_with_ua, psi_with_ua) =
            zns_psi_rcm(&name, Action::Release, "u1shouldbeignored", Some(prev_rcm));
        let (rcm_empty, psi_empty) = zns_psi_rcm(&name, Action::Release, "", Some(prev_rcm));

        assert_eq!(rcm_with_ua.to_repr(), rcm_empty.to_repr());
        assert_eq!(psi_with_ua, psi_empty);
    }
}
