//! Name Note binding verification — recompute `cmx` and compare on-chain.

use group::ff::PrimeField;
use orchard::Note;
use pasta_curves::pallas;

use super::{commit::note_commitment_cmx, hash::zns_psi_rcm};

/// Verify that parsed Name Note fields reproduce the on-chain `cmx`.
#[allow(clippy::too_many_arguments)]
pub fn verify_name_note(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: pallas::Base,
    expected_cmx: pallas::Base,
) -> bool {
    let (psi, rcm) = zns_psi_rcm(action, name, ua, prev_rcm);
    match note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm) {
        Some(cmx) => cmx == expected_cmx,
        None => false,
    }
}

/// Verify a decrypted note against the on-chain commitment and parsed memo fields.
pub fn verify_name_note_decrypted(
    note: &Note,
    on_chain_cmx: [u8; 32],
    action: &[u8],
    name: &str,
    ua: &str,
    prev_rcm: &[u8; 32],
) -> bool {
    let (g_d, pk_d) = note.recipient().zns_commitment_keys();
    let rho = match pallas::Base::from_repr(note.rho().to_bytes()).into_option() {
        Some(rho) => rho,
        None => return false,
    };
    let expected_cmx = match pallas::Base::from_repr(on_chain_cmx).into_option() {
        Some(cmx) => cmx,
        None => return false,
    };
    verify_name_note(
        action,
        name.as_bytes(),
        ua.as_bytes(),
        prev_rcm,
        g_d,
        pk_d,
        note.value().inner(),
        rho,
        expected_cmx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::group::ff::PrimeField;

    const G_D: [u8; 32] = [0x11u8; 32];
    const PK_D: [u8; 32] = [0x22u8; 32];
    const PINNED_CMX_HEX: &str =
        "53accd0df1c569731e8ad4fc8bcb483b953e3713ecc7a95202442daa026c4a02";

    fn rho() -> pallas::Base {
        pallas::Base::from_repr([0x33u8; 32]).unwrap()
    }

    fn pinned_cmx() -> pallas::Base {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(PINNED_CMX_HEX, &mut bytes).unwrap();
        pallas::Base::from_repr(bytes).unwrap()
    }

    #[test]
    fn matches_pinned_vector() {
        assert!(verify_name_note(
            b"claim",
            b"alice",
            b"u1xxx",
            &[0u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            pinned_cmx()
        ));
    }

    #[test]
    fn rejects_tampered_ua() {
        assert!(!verify_name_note(
            b"claim",
            b"alice",
            b"u1evil",
            &[0u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            pinned_cmx()
        ));
    }
}