# Architecture and Crates

The `librustzcash` monorepo is a workspace composed of multiple interacting crates. These crates are generally categorized into Protocol, Wallet Support/Abstractions, and standalone utilities. 

## Strict Dependency Graph (DAG) for `zns-mint`

When developing applications like `zns-mint` (Zcash Naming Service / Minting protocol), it is critical to understand the strict dependency flow of the `librustzcash` crates. High-level wallet crates sit at the top and flow downwards into the raw protocol primitives. Importing incorrectly (e.g., trying to parse addresses using `zcash_primitives`) will result in cyclic dependencies.

**1. The Database/Application Layer**
*   `zcash_client_sqlite` depends heavily on `zcash_client_backend`. It is the terminal node of the graph; nothing depends on it.

**2. The Wallet Engine Layer**
*   `zcash_client_backend` orchestrates the system. It depends downwards on `pczt`, `zcash_keys`, `zcash_proofs`, and `zip321`.

**3. The Proving & PCZT Layer**
*   `pczt` and `zcash_proofs` both depend downwards on `zcash_primitives` to access raw transaction data structures before they are signed/proved.

**4. The Key & Identity Layer**
*   `zcash_keys` bypasses the primitives and depends directly on `zcash_transparent`, `sapling-crypto`, and `orchard` for cryptographic key derivation.
*   `zip321` depends on `zcash_address` to parse URIs.

**5. The Primitives Layer**
*   `zcash_primitives` is the heavy lifter. It depends on `zcash_transparent`, `equihash`, `sapling-crypto`, and `orchard` to build transaction bundles.

**6. The Foundational Layers**
*   `zcash_transparent` depends on `zcash_address` and `zip32`.
*   `zcash_address` depends on `f4jumble` (for unified address encoding) and `zcash_protocol`.
*   `zcash_protocol` depends on `zcash_encoding` for low-level byte serialization.

## Categories

### 1. Zcash Protocol Core
These crates define the fundamental consensus rules, primitives, and structures of the Zcash network.

- **`zcash_protocol`**: Constants and common types. Defines consensus parameters, bounded value types (Zatoshis), and memo types. Separates shielded pools into Transparent, Sapling, Orchard, and Ironwood.
- **`zcash_transparent`**: Transparent transaction components (Bitcoin-derived). Handles transparent addresses, inputs (`TransparentInputInfo`), outputs, and UTXO management. Includes the `TransparentBuilder` which builds `Bundle<Unauthorized>` elements.
- **`zcash_history`**: Implements the chain history Merkle Mountain Range (MMR) used to authenticate blocks. The `Tree<V>` struct acts as a partial view of the MMR nodes to handle append/truncate operations for different network upgrades (Sapling, NU5, Ironwood).
- **`zcash_primitives`**: Core utilities and transaction models. 
  - Represents transaction structures across versions: V4 (concatenated components), V5 (ZIP-225 modular bundles with hierarchical Blake2b digests), and V6 (introducing Ironwood bundles). 
  - Contains transaction builders, block headers/structures, fee calculations (ZIP-317 marginal rules), and memo routing.
- **`zcash_proofs`**: Defines the Sprout/Sapling circuit and proving system (`LocalTxProver`), gluing together external cryptographic implementations.

### 2. Keys, Addresses, and Wallet Support
These crates provide the necessary infrastructure to build client wallets and interact with Zcash.

- **`zcash_address`**: Parsing and serialization of addresses (Unified, FVK, IVK containers). It explicitly avoids protocol-specific dependencies, converting string representations into typed structures.
- **`zcash_keys`**: Spending keys, viewing keys, and addresses. Implements ZIP 32 / ZIP 48 key derivation, supporting Unified Spending Keys (USK) and Unified Full Viewing Keys (UFVK).
- **`pczt`**: Data types and interfaces for Partially Constructed Zcash Transactions. Represents the build/prove/sign separation, defining roles such as `Creator`, `Updater`, `Signer`, and `Extractor`.
- **`zcash_client_backend`**: The primary wallet framework for Zcash. Abstract definitions for data storage (`WalletRead`, `WalletWrite`, `InputSource`), chain scanning decoupled from logic, light client sync, transaction proposals, and high-level transaction construction.
- **`zcash_client_sqlite`**: A concrete SQLite-based implementation of the `zcash_client_backend` storage APIs. 

### 3. Utilities and Components
Located in the `components/` directory, these provide isolated protocols and encoding schemes:
- **`zip321`**: Reference implementation for ZIP-321 payment request URIs (`from_uri` / `to_uri`).
- **`zcash_encoding`**: Common stable binary operations (CompactSize, Vectors, Arrays, Options, ReverseHex).
- **`f4jumble`**: The F4Jumble algorithm, an unkeyed 4-round Feistel construction that cascades small changes, used for Unified addresses.
- **`equihash`**: Proof-of-work protocol implementation, interacting with C-based Tromp solvers via FFI.
- **`eip681`**: Parser for Ethereum-style EIP-681 transaction request URIs.

## Security and Consensus Note

**Important:** The APIs exposed by these crates are used in zcashd, Zebra, and other ecosystem components. However, they **do not fully validate Zcash consensus**. Instead, they check a subset of validity constraints. The only way to guarantee full Zcash consensus validity is to use a full consensus node.
