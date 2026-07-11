# Zcash Protocol Specification Mapping

The `librustzcash` codebase is explicitly structured to mirror the [Zcash Protocol Specification](https://github.com/zcash/zips/blob/main/rendered/protocol/protocol.pdf). To fully understand the implementation of consensus rules, cryptography, and transaction encoding, it is crucial to map the Rust modules directly back to the specification chapters.

Below is a detailed comparison of the `librustzcash` modules against the Protocol Spec sections they implement.

## § 3.11 Coinbase Transactions
- **Spec Concept:** Defines the rules for transactions that generate new Zcash (coinbase), including miner rewards and founders' rewards.
- **Codebase Mapping:** `zcash_transparent/src/coinbase.rs` and `zcash_transparent/src/bundle.rs`. The code enforces constraints such as the requirement that coinbase transactions must have no transparent inputs, and validates the height encoding in the coinbase script.

## § 7.1 Transaction Encoding and Consensus
- **Spec Concept:** Defines the exact byte-level serialization of V4, V5, and V6 transactions.
- **Codebase Mapping:** `zcash_primitives/src/transaction/mod.rs` and `zcash_protocol/src/constants.rs`. The code explicitly implements `#txnencoding` and `#txnconsensus` constraints. The `transaction::builder` module validates that components match these strict encoding guidelines before calculating signature hashes.

## § 7.1.1 Transaction Identifiers
- **Spec Concept:** Defines how a transaction ID is computed via Blake2b over the transaction components.
- **Codebase Mapping:** `zcash_client_backend/src/proto/compact_formats.rs` and `zcash_primitives/src/transaction/txid.rs`. 

## § 7.3 & § 7.4 Sapling Spend and Output Encodings
- **Spec Concept:** Defines how Sapling shielded spends and outputs are serialized, including proofs, commitments, and ciphertexts.
- **Codebase Mapping:** `pczt/src/sapling.rs` and `zcash_client_backend/src/proto/compact_formats.rs`. The `CompactOutput` and `CompactSpend` protobuf messages directly align with `#spendencodingandconsensus` and `#outputencodingandconsensus`.

## § 7.5 Orchard Action Encodings
- **Spec Concept:** Defines how Orchard actions (which combine spends and outputs into a single Halo2 proof system) are serialized.
- **Codebase Mapping:** `pczt/src/orchard.rs`. The encoding aligns with `#actionencodingandconsensus` and `#orchardpaymentaddrencoding`.

## § 7.6.1 Equihash
- **Spec Concept:** Defines the asymmetric memory-hard proof-of-work algorithm used to validate block nonces.
- **Codebase Mapping:** `components/equihash/src/lib.rs` and `components/equihash/src/verify.rs`. The Tromp-based FFI solver and the Rust verification logic check the collision tree and minimal bit-lengths exactly as specified in `#equihash`.

## § 5.6.1.1 Sprout Payment Address Encoding
- **Spec Concept:** Defines the Base58Check encoding of legacy Sprout addresses.
- **Codebase Mapping:** `zcash_protocol/src/consensus.rs`, `zcash_protocol/src/constants/mainnet.rs`, and `testnet.rs`. These modules store the byte prefixes required for `#sproutpaymentaddrencoding` across networks.

## § 4.17 JoinSplit Statement (Sprout)
- **Spec Concept:** The zero-knowledge proof statement for the legacy Sprout shielded pool.
- **Codebase Mapping:** `zcash_proofs/src/circuit/sprout/mod.rs` links directly to `#joinsplitstatement` for its Groth16 circuit definition.

## Summary

When extending `librustzcash`, you must ensure that any structural changes to transaction builders, block headers, or parsing logic are validated against the `protocol.pdf` specification linked in the doc comments. The library relies heavily on these annotations to verify that the Rust `struct` and `enum` bounds mathematically match the constraints defined in the PDF.
