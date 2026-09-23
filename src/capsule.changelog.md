# Capsule module changelog

Tracks design-relevant changes to `src/capsule.rs`.

## 2026-09-23 — Capsule bytes are bounded before they are parsed

- `read_capsule_file` reads at most `CAPSULE_LEN + 1` bytes. Parse
  accepts only that exact length, and the nonce and ciphertext must
  be 24 and 48 bytes before decryption.

## 2026-09-15 — Split from boot; TEE-parameterised seal / unseal

- `capsule::{seal_seed, unseal_seed}` replace the inlined
  `decrypt_sealed_blob` in boot. Both take a `&dyn Tee` for the sealing
  key so integration tests can round-trip through `FakeTee` without
  forking the crypto or inventing a second capsule layout.
- On-disk format is unchanged: postcard-serialised
  `{ magic: b"ZNS_SEED", fingerprint: [u8; 32], nonce: [u8; 24],
  ciphertext: Vec<u8> }`, `XChaCha20Poly1305`, AAD = `magic ||
  fingerprint`, plaintext = 32-byte ZIP-32 seed. `seal_seed` derives
  the fingerprint from the seed itself so `unseal_seed` can cross-check
  after decrypt.
- `parse_capsule` / `serialize_capsule` are exposed for callers that
  need the postcard round-trip directly (integration tests, keygen).
- `CapsuleError` distinguishes `BadMagic`, `BadNonce`,
  `FingerprintMismatch`, `Decrypt`, `Seal`, `Parse`, `BadSeedSize`, and
  a `Tee(TeeError)` pass-through — boot logs the specific failure mode
  rather than a single opaque "capsule broken".
