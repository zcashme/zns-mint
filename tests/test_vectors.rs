use serde::Deserialize;
use std::fs;
use zns_mint::mint::{Action, Name};
use pasta_curves::group::ff::PrimeField;

#[derive(Deserialize)]
struct Vector {
    label: String,
    action: String,
    name: String,
    ua: String,
    prev_rcm: String,
    expected_psi_hex: String,
    expected_rcm_hex: String,
}

#[test]
fn test_zns_psi_rcm_vectors() {
    let vectors_json = fs::read_to_string("test_vectors/zns_psi_rcm.json")
        .expect("Failed to read test_vectors/zns_psi_rcm.json");
    let vectors: Vec<Vector> =
        serde_json::from_str(&vectors_json).expect("Failed to parse vectors JSON");

    for v in vectors {
        let action = match v.action.as_str() {
            "claim" => Action::Claim,
            "update" => Action::Update,
            "release" => Action::Release,
            _ => panic!("Unknown action: {}", v.action),
        };

        let mut prev_rcm_bytes = [0u8; 32];
        hex::decode_to_slice(&v.prev_rcm, &mut prev_rcm_bytes)
            .expect("Failed to decode prev_rcm hex");

        let name = Name::parse(&v.name).expect("Invalid Name");

        let (rcm, psi) = zns_mint::mint::zns_psi_rcm_raw(
            &name,
            action,
            &v.ua,
            &prev_rcm_bytes,
        );

        assert_eq!(
            hex::encode(psi.to_repr()),
            v.expected_psi_hex,
            "psi mismatch for vector {:?}",
            v.label
        );
        assert_eq!(
            hex::encode(rcm.to_repr()),
            v.expected_rcm_hex,
            "rcm mismatch for vector {:?}",
            v.label
        );
    }
}
