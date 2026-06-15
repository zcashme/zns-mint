//! The ZNS `(ψ, rcm)` derivation — consumer-side copy.
//!
//! Independent of `zns-signer`'s producer implementation so the two can
//! cross-check each other. Must match the published conformance vectors
//! byte-for-byte.

use blake2b_simd::Params;
use pasta_curves::{group::ff::FromUniformBytes, pallas};

/// Domain separation tag — must never change.
pub const ZNS_DOMAIN_TAG: &[u8] = b"ZcashName/v1";

const TAG_PSI: &[u8] = b"psi";
const TAG_RCM: &[u8] = b"rcm";

/// Derive `(ψ, rcm)` from a ZNS registration tuple.
pub fn zns_psi_rcm(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
) -> (pallas::Base, pallas::Scalar) {
    let psi =
        pallas::Base::from_uniform_bytes(&tagged_zns_hash(TAG_PSI, action, name, ua, prev_rcm));
    let rcm =
        pallas::Scalar::from_uniform_bytes(&tagged_zns_hash(TAG_RCM, action, name, ua, prev_rcm));
    (psi, rcm)
}

fn tagged_zns_hash(
    field_tag: &[u8],
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
) -> [u8; 64] {
    let mut h = Params::new().hash_length(64).to_state();
    let mut absorb_with_length_prefix = |b: &[u8]| {
        h.update(&(b.len() as u32).to_le_bytes());
        h.update(b);
    };
    absorb_with_length_prefix(ZNS_DOMAIN_TAG);
    absorb_with_length_prefix(field_tag);
    absorb_with_length_prefix(action);
    absorb_with_length_prefix(name);
    absorb_with_length_prefix(ua);
    h.update(prev_rcm);
    let mut out = [0u8; 64];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}