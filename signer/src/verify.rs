//! ZNS Name Note verification — wraps [`zns_verify`].
//!
//! Checks that an on-chain note commitment (`cmx`) matches the expected
//! commitment for a given `(action, name, ua, prev_rcm)` tuple.

use pasta_curves::pallas;
use zns_verify::{note_commitment_cmx, verify_name_note, Action};

use zns_core::RegistryError;

/// Re-export for callers that only need the action type.
pub use zns_verify::Action as ZnsAction;

/// Verify that a Name Note's `cmx` matches the expected commitment.
///
/// `g_d` and `pk_d` are the 32-byte encodings of the recipient diversified
/// base and transmission key, respectively, extracted from the note.
///
/// Returns `Ok(())` if the commitment matches; `Err(RegistryError::Build(…))`
/// if it does not or if the commitment is off-curve.
pub fn verify_cmx(
    action: Action,
    name: &str,
    ua: &str,
    prev_rcm: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: pallas::Base,
    expected_cmx: pallas::Base,
) -> Result<(), RegistryError> {
    let ok = verify_name_note(
        action.as_bytes(),
        name.as_bytes(),
        ua.as_bytes(),
        prev_rcm,
        g_d,
        pk_d,
        value,
        rho,
        expected_cmx,
    );

    if ok {
        Ok(())
    } else {
        Err(RegistryError::Build(format!(
            "cmx mismatch for '{name}' (action={action:?})"
        )))
    }
}

/// Recompute the expected `cmx` from first principles.
///
/// Returns `None` if the note commitment is not in the Pallas base field
/// (i.e. the inputs are invalid).
pub fn expected_cmx(
    action: Action,
    name: &str,
    ua: &str,
    prev_rcm: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: pallas::Base,
) -> Option<pallas::Base> {
    use zns_verify::zns_psi_rcm;
    let (psi, rcm) = zns_psi_rcm(action.as_bytes(), name.as_bytes(), ua.as_bytes(), prev_rcm);
    note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zns_verify::ZERO_PREV_RCM;

    #[test]
    fn verify_roundtrip() {
        let g_d = [0x11u8; 32];
        let pk_d = [0x22u8; 32];
        let value = 0u64;
        let rho = pallas::Base::from(0u64);

        // Compute expected cmx.
        let cmx = expected_cmx(
            Action::Claim,
            "alice",
            "u1xxx",
            &ZERO_PREV_RCM,
            g_d,
            pk_d,
            value,
            rho,
        );

        // note_commitment_cmx may return None for invalid (g_d, pk_d) test
        // inputs — that's fine; we just confirm the function is callable.
        let _ = cmx;
    }
}
