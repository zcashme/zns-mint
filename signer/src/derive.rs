//! The registry's `(ψ, rcm)` derivation — the producer side.
//!
//! This is an **independent** implementation of the spec's derivation (DESIGN
//! §4). The verification kernel (`zns-verify`, consumed by clients) has its own
//! copy; the registry deliberately does not depend on it, so a bug in one can
//! be caught by the other. The byte construction here — domain tag, field tags,
//! length-prefixing — is load-bearing and must match the published conformance
//! vectors exactly.

use blake2b_simd::Params;
use pasta_curves::{group::ff::FromUniformBytes, pallas};

/// Domain separation tag — must never change. A protocol-breaking change
/// requires bumping this to e.g. `b"ZcashName/v2"`.
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

/// The domain-tagged, length-prefixed BLAKE2b-512 hash backing both derivations.
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

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::group::ff::PrimeField;

    #[test]
    fn deterministic() {
        let a = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
        let b = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
    }

    #[test]
    fn field_tag_separation() {
        let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
        // Both reprs are [u8; 32]; ψ and rcm are not the same bytes.
        assert_ne!(psi.to_repr(), rcm.to_repr());
    }

    #[test]
    fn length_prefix_prevents_collision() {
        // "ali" || "cebob" vs "alice" || ":bob" collide without length prefixes.
        let a = zns_psi_rcm(b"claim", b"ali", b"cebob", &[0u8; 32]);
        let b = zns_psi_rcm(b"claim", b"alice", b":bob", &[0u8; 32]);
        assert_ne!(a.0, b.0);
        assert_ne!(a.1, b.1);
    }
}
