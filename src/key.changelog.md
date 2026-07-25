# Key module changelog

Tracks design-relevant changes to `src/key.rs`.

## 2026-07-25 — Sound zeroization of UnifiedSpendingKey

- Added a compile-time assertion `!std::mem::needs_drop::<UnifiedSpendingKey>()`
  to guard the manual `ptr::write_bytes` zeroization in `AccountKeys::Drop`.
  Upstream `UnifiedSpendingKey` and its components have no `Drop` impl at the
  pinned revision, so the zeroization is sound today; the assertion forces a
  re-audit before the code can compile if upstream ever adds a destructor.
- Simplified the safety comment around the zeroization block.

## 2026-07-23 — Account-role spending capabilities

- Replaced the public role-neutral `AccountKeys` surface with distinct
  `TreasuryKeys` and `RegistryKeys` capability types.
- Each public derivation function fixes its ZIP-32 account internally
  (`Treasury=0`, `Registry=1`); callers cannot swap an `AccountId` at runtime.
- Raw Orchard spending-key access is crate-private and remains behind the role
  wrapper. Transaction builders and signers accept the role type they require,
  so Treasury authority cannot satisfy a Registry signer parameter or vice
  versa.
- Viewing-key access remains available for boot attestation and scanner setup.

