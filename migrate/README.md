# zns-migrate

One-shot move of a sealed ZNS seed from the guest that holds it (`source`) to the next measured guest (`target`).

```bash
# M2, the guest that will hold the new capsule
zns-migrate target \
  --manifest /migration/upgrade.toml \
  --transport-dir /migration \
  --output-capsule /state/keys/zns_seed.capsule

# M1, the guest that holds the current capsule
zns-migrate source \
  --manifest /migration/upgrade.toml \
  --transport-dir /migration \
  --input-capsule /state/keys/zns_seed.capsule
```

Either side may start first. Target waits until source writes `source.ready`, then publishes an attested X25519 offer before source unseals the capsule. The transport directory is an untrusted channel, not state:

```text
source.ready
offer.bin
attestation.bin
encrypted_seed.bin
source_attestation.bin
receipt.bin
receipt_attestation.bin
```

Use a fresh directory for each attempt. The capsule stays outside that directory. Target will not replace an existing capsule unless `--replace-after-verified-migration` is set. It also will not decrypt a transfer until `source_attestation.bin` verifies against that offer and that ciphertext, and the report measurement equals the manifest's `from_measurement`. After the new capsule is linked into place, target unseals it again and only then writes the receipt. Source accepts that receipt only when `receipt_attestation.bin` binds this offer and this receipt, and the report measurement equals `to_measurement`.

`zns-canon` supplies sealing, capsule parsing, the manifest hash, migration `report_data`, and stored SNP report verification. This binary does not yet call `authorize_manifest`, so a zcashme GitHub artifact attestation of the manifest is not required. Source requires the target report measurement to equal `to_measurement`, and the offer's manifest hash to match.

The X25519 seed wrap lives in this binary for now. `zns-canon` still returns `NoImpl` for ephemeral key generation, encryption, and decryption, and those functions do not bind the offer nonce or manifest hash.

`zns-canon` is the git dependency on `main`. Sealing and attestation use the SNP guest device. There is no off-enclave build.
