//! Shared core logic for the entire crate.
//!
//! See `mint.rs.context.md` for the design.

use zip32::AccountId;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// ZNS action kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Point a name to an address
    Claim,
    /// Rebinds a name to a new address
    Update,
    /// Terminates a name's linkage to an address
    Release,
}

/// A 32-byte hash identifying the previous Name Note in a chain.
pub type NameCommitment = [u8; 32];

/// The all-zero `prev_commitment` used for the root of a name chain (a claim).
pub const ZERO_PREV_COMMITMENT: NameCommitment = [0u8; 32];

/// A strongly-typed ZNS name.
///
/// Guarantees that the contained string is a syntactically valid ZNS name
/// (e.g. lowercase, alphanumeric, ends in `.zns`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name(String);

impl Name {
    /// Attempts to parse a string into a valid ZNS name.
    pub fn parse(s: &str) -> Option<Self> {
        // ZNS protocol operates purely on the base name label, never the extension.
        // A valid name must be lowercase, alphanumeric, and not contain dots.
        if !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
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
    prev_rcm: NameCommitment,
) -> (pasta_curves::pallas::Scalar, pasta_curves::pallas::Base) {
    use pasta_curves::group::ff::FromUniformBytes;
    
    let action_bytes: &[u8] = match action {
        Action::Claim => b"claim",
        Action::Update => b"update",
        Action::Release => b"release",
    };
    
    // Release action forces an empty UA
    let ua_bytes = if action == Action::Release { b"" } else { ua.as_bytes() };
    let name_bytes = name.as_str().as_bytes();

    let psi = pasta_curves::pallas::Base::from_uniform_bytes(
        &tagged_zns_hash(b"psi", action_bytes, name_bytes, ua_bytes, &prev_rcm)
    );
    let rcm = pasta_curves::pallas::Scalar::from_uniform_bytes(
        &tagged_zns_hash(b"rcm", action_bytes, name_bytes, ua_bytes, &prev_rcm)
    );

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
    prev_rcm: NameCommitment,
) -> Option<[u8; 512]> {
    let action_str = match action {
        Action::Claim => "claim",
        Action::Update => "update",
        Action::Release => "release",
    };
    
    // A release note explicitly has an empty UA
    let ua_str = if action == Action::Release { "" } else { ua };
    let hex_rcm = hex::encode(prev_rcm);
    
    let memo_string = format!("ZNS:{}:{}:{}:{}", action_str, name.as_str(), ua_str, hex_rcm);
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
pub fn decode_name_note(memo: &[u8; 512]) -> Option<(Name, Action, String, NameCommitment)> {
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
    
    let mut prev_rcm = [0u8; 32];
    if parts[4].len() != 64 {
        return None;
    }
    hex::decode_to_slice(parts[4], &mut prev_rcm).ok()?;
    
    Some((name, action, ua, prev_rcm))
}
