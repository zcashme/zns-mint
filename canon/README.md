# zns-canon

Shared custody cryptography for ZNS. `zns-mint` and `zns-keygen` will depend on this crate; those repos are unchanged here.

- `capsule` — sealed ZIP-32 seed (`XChaCha20Poly1305`, postcard, magic `ZNS_SEED`)
- `sealing` — TEE seam: SEV-SNP derived sealing key and attestation report request (`FakeTee` behind `--features fake-tee`)
- `attestation` — SEV-SNP report verification (pinned AMD ARK, VCEK signature, capsule `report_data`)

The genesis ceremony is in `zns-keygen`. Next steps: `zns-migrate` binary.