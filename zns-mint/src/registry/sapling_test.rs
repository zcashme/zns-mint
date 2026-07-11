#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use sapling::builder::{Builder, BundleType};
    use sapling::note_encryption::Zip212Enforcement;
    use sapling::prover::mock::{MockOutputProver, MockSpendProver};
    use sapling::zip32::{ExtendedSpendingKey, ExtendedFullViewingKey};
    use sapling::keys::SpendAuthorizingKey;
    use sapling::{Note, Node};
    use incrementalmerkletree::{Hashable, Position};

    #[test]
    fn test_sapling_sweep_with_mock_prover() {
        let mut rng = OsRng;

        // 1. Setup mock keys
        let seed = [0u8; 32];
        let extsk = ExtendedSpendingKey::master(&seed);
        let extfvk = ExtendedFullViewingKey::from(extsk.clone());
        let fvk = extfvk.fvk;
        let ask = SpendAuthorizingKey::from(extsk.clone());
        
        let (_, payment_address) = extfvk.default_address();

        // 2. Setup mock Sapling Note (e.g. 10 ZEC)
        let note_value = 10_00_000_000;
        let note = Note::from_parts(
            payment_address,
            sapling::value::NoteValue::from_raw(note_value),
            sapling::Rseed::AfterZip212([0u8; 32]),
        );

        // Setup a mock Merkle path for the note
        let merkle_path = sapling::MerklePath::from_parts(
            vec![
                Node::empty_root(0.into()),
                Node::empty_root(1.into()),
                Node::empty_root(2.into()),
                // (shortened for test, normally depth is 32, but sapling-crypto MerklePath length is generic or fixed)
            ],
            Position::from(0)
        ).unwrap_or_else(|_| {
            // If from_parts fails due to incorrect length (it expects 32 elements), 
            // let's build a proper 32-depth path.
            let elems: Vec<_> = (0..32).map(|i| Node::empty_root(i.into())).collect();
            sapling::MerklePath::from_parts(elems, Position::from(0)).unwrap()
        });
        
        // Let's create a valid empty tree anchor
        let anchor = sapling::Anchor::from(Node::empty_root(32.into()));

        // 3. Initialize the Builder
        let mut builder = Builder::new(
            Zip212Enforcement::On,
            BundleType::DEFAULT,
            anchor,
        );

        // 4. Add the sweep spend
        builder.add_spend(fvk.clone(), note, merkle_path).unwrap();

        // No Sapling outputs (we are sweeping to transparent).
        
        // 5. Build the unproven bundle
        let (unproven_bundle, _) = builder
            .build::<MockSpendProver, MockOutputProver, _, zcash_protocol::value::ZatBalance>(
                &[extsk.clone()], 
                &mut rng
            )
            .unwrap()
            .expect("Bundle should not be empty");

        // 6. Generate Mock Proofs (Instant! No 50MB params required!)
        let unauthed_bundle = unproven_bundle.create_proofs(
            &MockSpendProver,
            &MockOutputProver,
            &mut rng,
            ()
        );

        // 7. Apply Signatures
        let sighash = [0xAA; 32]; // Mock sighash from the transaction digest
        let authorized_bundle = unauthed_bundle.apply_signatures(
            &mut rng,
            sighash,
            &[ask]
        ).unwrap();

        // 8. Verify the bundle's value balance is exactly -10 ZEC 
        // (meaning 10 ZEC is exiting the Sapling pool to go to the Transparent pool)
        let balance: i64 = authorized_bundle.value_balance().try_into().unwrap();
        assert_eq!(balance, -10_00_000_000, "Sapling bundle should export 10 ZEC");
    }
}
