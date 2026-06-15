//! Note commitment derivation — consumer-side Sinsemilla `cmx`.

use bitvec::{array::BitArray, order::Lsb0, view::BitView};
use group::ff::PrimeFieldBits;
use pasta_curves::pallas;
use sinsemilla::CommitDomain;

const NOTE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-NoteCommit";
const L_ORCHARD_BASE: usize = 255;

/// Computes `cmx`, the x-coordinate of the Sinsemilla note commitment.
pub fn note_commitment_cmx(
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: pallas::Base,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<pallas::Base> {
    let domain = CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
    let value_bytes = value.to_le_bytes();
    let g_d_bits = BitArray::<_, Lsb0>::new(g_d);
    let pk_d_bits = BitArray::<_, Lsb0>::new(pk_d);
    let rho_bits = rho.to_le_bits();
    let psi_bits = psi.to_le_bits();
    let bits = g_d_bits
        .iter()
        .by_vals()
        .chain(pk_d_bits.iter().by_vals())
        .chain(value_bytes.view_bits::<Lsb0>().iter().by_vals())
        .chain(rho_bits.iter().by_vals().take(L_ORCHARD_BASE))
        .chain(psi_bits.iter().by_vals().take(L_ORCHARD_BASE));
    Option::<pallas::Base>::from(domain.short_commit(bits, &rcm))
}