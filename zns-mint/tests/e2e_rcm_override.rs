use pasta_curves::{group::ff::Field, pallas};
use rand::{rngs::OsRng, RngCore};
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags},
    keys::{SpendingKey, FullViewingKey},
    value::NoteValue,
    circuit::OrchardCircuitVersion,
};

#[test]
fn test_zns_rcm_override_mainnet_verification() {
    let mut rng = OsRng;

    // 1. Generate keys
    let sk = SpendingKey::random(&mut rng);
    let fvk: FullViewingKey = (&sk).into();
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);

    // 2. Define custom ZNS payload (custom rcm and psi)
    let custom_rcm = pallas::Scalar::random(&mut rng);
    let custom_psi = pallas::Base::random(&mut rng);

    // 3. Build a bundle with the custom rcm and psi using the ZNS fork method
    let bundle_version = BundleVersion::orchard_v3(); // V3 bundle version for NU6.3
    let flags = bundle_version.default_flags();
    let mut builder = Builder::new(
        BundleType::DEFAULT,
        bundle_version,
        flags,
        orchard::tree::Anchor::empty_tree(),
    );

    // Add our custom ZNS Name Note output
    builder
        .add_zns_output(
            None,
            recipient,
            NoteValue::ZERO,
            orchard::note::NoteVersion::V2,
            [0u8; 512],
            custom_rcm,
            custom_psi,
        )
        .expect("Failed to add ZNS output");

    // Add a dummy spend to balance the transaction and satisfy the minimum actions rule
    builder
        .add_spend(fvk.clone(), orchard::note::Note::dummy(&mut rng, None, orchard::note::NoteVersion::V2).2, orchard::tree::MerklePath::dummy(&mut rng))
        .expect("Failed to add spend");

    // 4. Generate the zk-SNARK proof using the standard mainnet Proving Key (PK) for NU6.3
    let pk = orchard::circuit::ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = orchard::circuit::VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);

    let (unauthorized_bundle, _) = builder
        .build(&mut rng)
        .expect("Failed to build unauthorized bundle")
        .unwrap();

    let sighash = [0u8; 32];
    let authorized_bundle = unauthorized_bundle
        .prove_and_sign(&pk, &mut rng)
        .expect("Failed to generate zk-SNARK proof and sign bundle");

    // 5. VERIFICATION
    let verification_result = authorized_bundle.verify(
        &vk,
        bundle_version,
        &sighash,
    );

    assert!(
        verification_result.is_ok(),
        "Mainnet validation rejected the proof! (This should not happen)"
    );
}
