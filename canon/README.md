# zns-canon

Shared custody cryptography for ZNS. `zns-mint` and `zns-keygen` depend on this crate.

- `capsule` — sealed ZIP-32 seed (`XChaCha20Poly1305`, postcard, magic `ZNS_SEED`)
- `sealing` — TEE seam: SEV-SNP derived sealing key and attestation report request (`FakeTee` behind `--features fake-tee`)
- `attestation` — SEV-SNP report verification (pinned AMD ARK, VCEK signature, capsule `report_data`)
- `genesis` — canonical record of a finished ceremony, and its `report_data`
- `upgrade` — measurement-change manifest and its hash. m-of-n signature verification is not done
- `migration` — offer binding for moving the seed to a new measurement. The X25519 handoff is not done

Ceremony and migration orchestration stay outside this crate.