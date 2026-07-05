# Handoff — Key Derivation & Wallet Refactor

## What changed

A multi-step refactor of the mint's key derivation, boot sequence, and wallet
initialization. The old code had a `Keys` struct — a god-object holding both
accounts' spending keys, passed to every consumer. Derivation was baked into
the struct's constructor. The scanner re-derived IVKs from `&Keys` on every
block. Four accessor methods were thin wrappers around upstream methods that
added no value.

### Key design decisions

1. **No `Keys` struct.** Replaced with `AccountKeys` — one struct per account,
   held independently by each module. No god-object passed through the runtime.

2. **No `Seed` struct.** The upstream (`zcash_client_sqlite`,
   `zcash_client_backend`) uses `secrecy::SecretVec<u8>` directly as the seed
   type. No custom wrapper. We do the same with `Secret<[u8; 32]>`.
   Fingerprint (`SeedFingerprint::from_seed`) and derivation
   (`UnifiedSpendingKey::from_seed`) are upstream standalone functions called
   at the call site (boot), not wrapped in methods.

3. **`key.rs` is generation helpers, not runtime state.** Called once at boot,
   never again. `derive_account(&Secret<[u8; 32]>, AccountId) -> AccountKeys` —
   one function, called twice. The scanner gets UFVKs from the wallet (via
   `Wallet::ufvk_for`), not from a `&Keys` parameter.

4. **`Secret<[u8; 32]>` from the `secrecy` crate** replaces `Zeroizing<[u8; 32]>`
   from the `zeroize` crate. Aligns with the upstream ecosystem
   (`zcash_client_backend` uses `SecretVec<u8>` everywhere). Zeroizes on drop,
   requires `expose_secret()` for access.

5. **Seed fingerprint verification at boot.** Hardcoded
   `EXPECTED_SEED_FINGERPRINT` constant (currently the zero-seed fingerprint as
   a dummy). Boot computes `SeedFingerprint::from_seed(seed.expose_secret())`
   and compares. Mismatch → refuse to boot. No durable state needed — the
   fingerprint is a compile-time constant, same pattern as the upstream's
   `Zip32Derivation` but hardcoded instead of database-stored.

6. **No stored FVK.** `AccountKeys` holds only `UnifiedSpendingKey`. The UFVK is
   derived on demand via `fvk()` (calls `to_unified_full_viewing_key`). The FVK
   is derivable from the spending key — storing both is redundant.

7. **Multi-pool enablement.** `zcash_keys` features expanded from `["orchard"]`
   to `["orchard", "sapling", "transparent-inputs"]`. Both accounts derive all
   three pools via `UnifiedSpendingKey::from_seed`. The Treasury uses all three
   (user-facing). The Registry uses only Orchard (name-notes-only); its
   Sapling/Transparent components are unused but present because the upstream
   API doesn't support per-account pool selection.

### Files changed

| File | What |
|------|------|
| `src/key.rs` | Full rewrite. `Keys` struct → `AccountKeys` + `derive_account`. `Seed` struct removed. Uses `Secret<[u8; 32]>`. 12 tests. |
| `src/boot.rs` | Uses `Secret<[u8; 32]>` directly. `verify_fingerprint` calls `SeedFingerprint::from_seed` on demand. `decrypt_sealed_blob` returns `Secret<[u8; 32]>`. Hardcoded fingerprint constant. |
| `src/wallet.rs` | Added `ufvk_for(AccountId)` accessor so the scanner can read UFVKs from the wallet. |
| `src/scanner/scan.rs` | Removed `keys: &Keys` parameter. Gets UFVKs from `wallet.ufvk_for(account)`. |
| `src/registry.rs` | `build_transaction` takes `&orchard::keys::SpendingKey` instead of `&Keys`. |
| `src/main.rs` | Updated boot destructuring for new return type. |
| `Cargo.toml` | Added `secrecy = "0.8"`. Expanded `zcash_keys` and `zcash_client_backend` features. Added `transparent` crate dep. |
| `AGENTS.md` | Added commit/PR-style rules. |
| `docs/protocol/00-overview.md` | Expanded implementation state. |
| `docs/protocol/14-wallet-design.md` | Added storage rationale cross-ref. |
| `docs/protocol/14a-wallet-storage-rationale.md` | New — why in-memory only, no database. |
| `docs/protocol/wallet.md` | New — full wallet design (ShardTree, scanning pipeline, spending path). |
| `docs/protocol/README.md` | Added 14a entry. |
| `src/auth.rs` | Trimmed module doc (removed aspirational content). |
| `src/zcash/chain.rs` | Minor doc trim. |

### What builds

`cargo build` — clean. `cargo test` — 15 passed, 1 ignored (zebra network
test), 0 failed.

### What doesn't work yet

- `boot::obtain_key_source()` and `boot::decrypt_sealed_blob()` are `todo!()`.
  The mint cannot boot in production until TEE-sealed-blob decryption is
  implemented.
- `EXPECTED_SEED_FINGERPRINT` is the zero-seed fingerprint. Must be replaced
  with the deployment seed's fingerprint before production.
- `scanner::scan::scan_to_tip` is a stub (`TODO` body).
- `registry::build_transaction` is a stub (`todo!()`).
- `zeroize` is still a direct dep in `Cargo.toml` but no longer used directly
  (only through `secrecy`). Could be removed as a direct dep.

### Uncommitted

All changes are uncommitted. The user has not said "commit."

### Architecture summary

```
Boot (parameterless, deterministic):
  1. check_liveness() → JSON-RPC
  2. verify_chain_integrity() → gRPC + cross-validate
  3. decrypt_sealed_blob() → Secret<[u8; 32]>
  4. verify_fingerprint() → SeedFingerprint::from_seed vs hardcoded constant
  5. key::derive_account(&seed, 0) → AccountKeys (treasury)
     key::derive_account(&seed, 1) → AccountKeys (registry)
     seed drops — Secret zeroizes
  6. initialize_wallet(treasury.fvk(), registry.fvk()) → Wallet (holds UFVKs)

Runtime:
  Scanner reads UFVKs from Wallet via wallet.ufvk_for(account)
  Treasury signing path calls treasury_keys.orchard/sapling/transparent_spending_key()
  Registry signing path calls registry_keys.orchard_spending_key()
  Nobody touches key.rs during the active code path
```

### Key upstream references (read during this session)

- `zcash_keys/src/keys.rs` — `UnifiedSpendingKey`, `UnifiedFullViewingKey`,
  `from_seed`, `to_unified_full_viewing_key`, `subsumes_ufvk`
- `orchard/src/keys.rs` — `SpendingKey`, `FullViewingKey`, `to_ivk`, `to_ovk`,
  constant-time validation, ỹ=0 negation, `Debug` redaction
- `orchard/src/zip32.rs` — `ExtendedSpendingKey`, `from_path`, `derive_child`
- `sapling-crypto/src/keys.rs` — `ExpandedSpendingKey`, `SpendAuthorizingKey`,
  `FullViewingKey`, zero-scalar rejection
- `sapling-crypto/src/zip32.rs` — `ExtendedSpendingKey`, additive child derivation,
  internal FVK derivation
- `zcash_transparent/src/keys.rs` — `AccountPrivKey::from_seed` (BIP-44),
  `AccountPubKey`, `ExternalIvk`, OVK derivation
- `zip32/src/fingerprint.rs` — `SeedFingerprint::from_seed`, bech32m encoding
- `secrecy/src/lib.rs` — `Secret<T>`, `ExposeSecret`, zeroize on drop,
  `DebugSecret` (redacted Debug)
- `zcash_client_sqlite/src/lib.rs` — `create_account`, `import_account_hd`,
  `validate_seed`, `seed_relevance_to_derived_accounts`
- `zcash_client_sqlite/src/wallet.rs` — `seed_matches_derived_account`
  (two-step: fingerprint + viewing key), `max_zip32_account_index`
- `zcash_client_backend/src/data_api.rs` — `Zip32Derivation`, `AccountSource`,
  `AccountBirthday`, `WalletWrite::create_account` trait + docs