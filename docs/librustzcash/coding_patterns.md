# Coding Patterns

The `librustzcash` codebase employs several specific Rust coding patterns and architectural abstractions. These patterns are designed to separate consensus logic from wallet logic, and abstract storage details from execution logic.

## 1. Trait-Based Data Abstractions

The `zcash_client_backend` crate heavily relies on abstractions rather than concrete types for storage and network data interactions.
- **Core Storage Traits:** `WalletRead`, `WalletWrite`, `InputSource`, and `WalletCommitmentTrees` are defined as traits. This enables crates like `zcash_client_sqlite` to implement them for SQLite, but allows for alternative backends without touching wallet logic.
- **Tree Abstraction:** The library relies on `shardtree` and traits like `ShardStore` rather than a full in-memory tree. This limits the data footprint by caching only relevant tree shards and frontiers.

## 2. Type-States for Lifecycle Enforcement

Transaction building and processing strictly utilize Rust type-states to prevent accidental misuse of unsigned or incomplete data.
- **Unauthorized vs. Authorized:** The transaction bundles (such as `Bundle<Unauthorized>` in `zcash_transparent`) utilize generics to statically track whether a bundle has received signatures. Only `Authorized` bundles can be fully extracted.
- **Proposals vs. Construction:** A `TransactionRequest` is transformed into a `Proposal` (input selection and fee resolution), which is completely decoupled from proving and building the actual transaction bytes.

## 3. PCZT (Partially Constructed Zcash Transactions)

Similar to Bitcoin's PSBT, PCZT generalizes the split between creating a transaction, generating zero-knowledge proofs (proving), and providing signatures. 
- Workflows involve disparate roles (`Creator`, `Updater`, `Signer`, `Extractor`).
- This explicit separation permits offline signing via hardware wallets where proving/updating occurs externally.

## 4. Strict Shielded Pool Separation

Zcash maintains Transparent, Sprout (legacy), Sapling, Orchard, and Ironwood as distinct pools. The codebase treats these as strictly independent modular components.
- Transactions consist of distinct "bundles" (e.g. `transparent::Bundle`, `sapling::Bundle`, `orchard::Bundle`).
- Even in database schemas (like in `zcash_client_sqlite`), data is strongly isolated into tables like `sapling_received_notes` and `orchard_received_notes`, stitched together through SQL views (e.g., `v_transactions`) or generic abstractions (e.g., `TableConstants`).

## 5. Idempotent Migrations and SQLite Patterns

The concrete `zcash_client_sqlite` implementation demonstrates robust database interaction patterns:
- **Migration DAGs:** Utilizes the `schemerz` crate to represent migrations as a Directed Acyclic Graph (DAG), ensuring atomic schema evolution.
- **Upserts and ON CONFLICT:** Write queries lean on `INSERT ... ON CONFLICT (...) DO UPDATE` for idempotent block and note insertions, protecting against duplicate events during sync rollbacks.
- **CTEs and Window Functions:** SQL queries (like selecting spendable notes) rely heavily on Common Table Expressions (CTEs) and window functions (`SUM(value) OVER (...)`) for performant aggregations within SQLite.

## 6. Separated Scanning and Trial Decryption

Wallet scanning abstracts the block orchestration from the cryptographic payloads.
- **Batched Decryption:** Trial decryption is heavily batched across domains (Sapling, Orchard) to significantly improve performance over individual note decryption.
- **Domains:** The `zcash_note_encryption::Domain` trait generalizes decryption for different shield pools so scanning logic remains oblivious to the underlying elliptic curve mechanics.
