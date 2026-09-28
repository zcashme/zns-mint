# Capsule module changelog

Tracks design-relevant changes to `src/capsule.rs`.

## 2026-09-28 — Capsule operations are methods (#229)

- `Capsule::seal` and `Capsule::parse` construct the envelope;
  `unseal` and `serialize` operate on it. The shared nonce/ciphertext check
  is the private `validate_lengths` method. `read_capsule_file` remains a
  free function for bounded filesystem intake.
- The postcard layout, public fields, validation order, AEAD/AAD,
  fingerprint check, and zeroization are unchanged. Existing upstream
  `Aead` operations (`aead` 0.5.2, `src/lib.rs:167`) and ZIP-32
  `SeedFingerprint::from_seed` (`zip32` 0.2.1, `src/fingerprint.rs:46`)
  remain the implementation; no crypto wrapper or new type is introduced.
- Boot, the fake-capsule writer, and existing tests use the method API.
  Regtest and FakeTee selection are unchanged.

## 2026-09-28 — One structural capsule error (#227)

- Magic, file-length, nonce-length, and ciphertext-length failures return
  the plain `BadCapsule` variant, displayed as `invalid capsule format`.
  Boot handles each failure identically; the separate variants and length
  fields are removed. Validation order and the bounded file read stay the same.
- Existing rejection tests expect `BadCapsule`; round-trip and authentication
  tests retain their existing assertions.

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
