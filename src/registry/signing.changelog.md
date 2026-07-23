# Registry signing changelog

Tracks design-relevant changes to `src/registry/signing.rs`.

## 2026-07-23 — Pool-role signer separation

- The mixed V6 assembler no longer accepts one role-neutral Orchard spending
  key for both shielded pools.
- Orchard real spends can be authorized only by `TreasuryKeys`; Ironwood real
  spends can be authorized only by `RegistryKeys`. Both bundles still sign the
  same complete V6 shielded sighash.
- Output-only bundles pass no real signing key and rely only on the Orchard
  builder's retained dummy-spend authorizers.

## 2026-07-23 — Registry-only public signing boundary

- The public Ironwood signer wrapper accepts `RegistryKeys`; a Treasury key
  capability cannot be passed to the Registry transaction signer.

## 2026-07-22 — Mixed-pool V6 assembler

- Added `assemble_v6_transaction`, which can prove and sign a V6 transaction
  containing at least one Orchard or Ironwood bundle, plus optional
  transparent outputs.
- Restricted the mixed assembler to crate visibility; the public Registry
  wrapper remains Ironwood-only.
- Kept `assemble_and_sign_transaction` as a thin wrapper around the new mixed-pool
  assembler for the existing Registry-only Ironwood path.
- Both paths reuse the cached `PostNu6_3` `ProvingKey`/`VerifyingKey`, so
  mixed-pool Treasury transactions (Orchard spend + Ironwood refund output)
  do not pay the ~2-minute key-build cost on every transaction.
- The TX-005 unauthorized-vs-authorized digest equality check now covers both
  Orchard and Ironwood digests when both bundles are present.
- Added fail-closed checks for NU6.3 activation, correct Orchard V3/Ironwood V3
  field placement, checked expiry-height arithmetic, at least one shielded
  bundle, and cached proving/verifying-key circuit-version agreement.

## 2026-07-21 — TX-005 exact-transaction sighash boundary

- Removed the pre-authorized optional Sapling bundle from
  `assemble_and_sign_transaction`. V6 shielded sighashes commit to Sapling
  effecting data, so inserting a Sapling bundle after computing the sighash
  authorized a different transaction from the one serialized.
- Kept the Registry signer deliberately Ironwood-only. A future mixed-pool
  Treasury path must follow the pinned `zcash_primitives::transaction::Builder`
  ordering: every effecting bundle is present in one unauthorized transaction
  before the shared sighash, then Sapling and Ironwood are authorized over that
  exact commitment.
- Added a fail-closed pre-serialization postcondition that compares the
  upstream-generated V6 effecting-data digests (`TxDigests`) of the final
  authorized transaction against the digests used for the shielded sighash.
  This avoids relying on `signature_hash` on `TransactionData<Authorized>`,
  whose transparent authorization type does not implement
  `TransparentAuthorizingContext`. This implements the structural part of
  `TX-005`; mutation and independent-sighash tests remain unexecuted work.
