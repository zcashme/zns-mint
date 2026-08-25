# zns-mint Bootstrap & Release Plan

This document is the discovery plan for taking the current `zns-mint` boot
sequence from a local-decrypt prototype to a publicly verifiable, GitHub-tagged,
AWS SEV-SNP deployment.

It is a **planning artifact**, not implementation. Code changes, workflow files,
and AWS resources listed here still need to be built.

---

## 1. Current state of the boot sequence

The only seed-handling code lives in `src/boot.rs`. It implements a
**single-instance, local-decrypt, runtime-attest** flow:

1. `check_liveness()` — JSON-RPC `getblockchaininfo` to Zebra.
2. `verify_chain_integrity()` — gRPC/JSON-RPC cross-validation, genesis check,
   NU5 baseline.
3. `obtain_key_source()` — reads `zns_seed.capsule` from disk (or zero seed in
   `dev-seed` mode).
4. `derive_sealing_key()` — calls `/dev/sev-guest` `SNP_DERIVE_KEY`, binding the
   key to guest policy, image_id, family_id, and measurement.
5. `decrypt_capsule()` — XChaCha20-Poly1305 AEAD with AAD =
   `magic || fingerprint`.
6. `verify_fingerprint()` — compares ZIP-32 seed fingerprint against
   `deployment/seed_fingerprint.txt` compiled into the binary.
7. `derive_treasury()` / `derive_registry()` — ZIP-32 accounts 0 and 1.
8. `origin_checkpoint()` — seeds wallet trees from Zebra `z_gettreestate` at
   `NU6.3 - 1`.
9. `generate_mint_attestation()` — writes `zns_mint_attestation.bin` via
   `/dev/sev-guest` `get_report`, with report_data =
   `BLAKE2b-512(treasury_default_address || "||" || registry_fvk)`.

What is **not** in this repo:

- Capsule creation (lives in a separate repo/tool).
- Tagged-release gating inside the TEE.
- Admission attestation / TEE-to-TEE HPKE handoff.
- Seed epochs or migration logic.
- Replica provisioning / cutover fencing.
- GitHub release or AWS deployment automation.
- Public attestation verifier.

---

## 2. Public verification goal

Anyone must be able to verify the chain:

```
GitHub immutable tag
  → commit SHA
  → release manifest (artifact hashes + TEE measurements)
  → AWS AMI / image digest
  → running SEV-SNP measurement
  → Treasury address + Registry FVK
  → SEV-SNP attestation report
```

Public artifacts:

1. Source code (GitHub).
2. Release manifest with measurements (GitHub Release asset).
3. Deployed image / AMI IDs (GitHub Release + AWS).
4. Runtime attestation + public identities (published by the live mint).

---

## 3. Required GitHub additions

### Repository structure

```
.github/
├── workflows/
│   ├── pr.yml                # build/test on PRs; no seed access
│   ├── release.yml           # tag → build binary + guest image + manifest
│   └── deploy.yml            # publish image → AWS AMI → launch instance
├── dependabot.yml            # already exists
└── BOOTSTRAP-PLAN.md       # this file
```

### Branch / tag protection

- Protect `main`: require PR review, required status checks, no direct push.
- Protect tags matching `v*.*.*`: only the release workflow may create/publish
  releases from them.
- Restrict AWS OIDC `sub` claim to the release workflow on protected tags.

### Workflows

#### `pr.yml`

- Checkout PR commit.
- `cargo build --features regtest`.
- `cargo test --features regtest`.
- Clippy / fmt checks.
- Verify changelogs updated for touched modules.
- **No AWS access, no seed handling, no releasable artifact.**

#### `release.yml`

Triggered on push of `v*.*.*`.

- Check out exact tag.
- Record commit SHA.
- Build `zns-mint --release`.
- Build minimal SEV-SNP guest image (kernel + initramfs + `zns-mint` as the
  only workload, no SSH/shell/console).
- Compute image SHA-256.
- Derive expected SEV-SNP measurement from the image build.
- Create release manifest:

```json
{
  "repository": "github.com/<owner>/zns-mint",
  "tag": "v1.0.0",
  "commit_sha": "...",
  "network": "mainnet",
  "protocol_version": 1,
  "policy_version": 1,
  "seed_epoch": 1,
  "release_kind": "runtime",
  "artifacts": [
    {
      "name": "zns-mint-guest-image",
      "sha256": "...",
      "tee_measurement": "...",
      "provider": "aws-snp"
    }
  ]
}
```

- Generate GitHub artifact provenance.
- Attach image, manifest, SBOM, measurements, attestations to a **draft**
  release.
- On success, publish as an **immutable GitHub Release**.

No seed is ever handled in this workflow.

#### `deploy.yml`

Triggered after a release is published.

- Use GitHub OIDC to assume AWS IAM role:

```yaml
permissions:
  id-token: write
  contents: read
```

- Download the released guest image.
- Upload to private S3 staging bucket.
- Register as AMI.
- Launch SEV-SNP EC2 instance from that AMI.
- Post AMI ID / instance ID back to the GitHub Release.
- Health check the instance and fail the deployment if the mint does not report
  readiness.

---

## 4. Required code changes in `zns-mint`

### Boot / capsule hardening (`src/boot.rs`)

1. **Extend `SeedCapsule` AAD** to include:
   - `format_version`
   - `network`
   - `seed_epoch`
   - `release_manifest_digest`

   The mint must verify these before trusting the decrypted seed.

2. **Add TEE measurement gate**: at boot, compare the live SEV-SNP
   measurement to the expected measurement published in the release manifest
   baked into the image. Refuse to decrypt if it does not match.

3. **Network / seed-epoch enforcement**: refuse a mainnet capsule on a
   regtest image, or an epoch-1 capsule under an epoch-2 image.

### Public attestation verifier (new crate, e.g. `tools/verifier/`)

A standalone, publicly runnable tool that verifies `zns_mint_attestation.bin`:

```
tools/verifier/
├── Cargo.toml
└── src/
    ├── main.rs          # CLI entry point
    ├── report.rs        # parse SEV-SNP attestation report
    ├── chain.rs         # verify AMD VCEK/ARK certificate chain
    ├── manifest.rs      # parse zns-mint release manifest
    └── identity.rs      # recompute Treasury address + Registry FVK
```

Inputs:

- `zns_mint_attestation.bin` from a running mint.
- Release manifest from GitHub.
- Expected Treasury address / Registry FVK (or fetch from chain).

Outputs:

- `measurement OK / FAIL`
- `report_data matches expected identities OK / FAIL`
- `AMD certificate chain OK / FAIL`
- `release manifest link OK / FAIL`

The verifier should be distributed as a release binary from the same GitHub
repo.

### Optional in-repo helper

Because the capsule creator lives in a separate repo, this repo can still ship:

- A capsule **parser/validator** for testing.
- Documentation of the exact capsule format and AAD.
- A `tools/capsule-dev/` crate to create testnet/dev capsules locally.

---

## 5. Required AWS resources

| Resource | Purpose |
|---|---|
| IAM OIDC identity provider for GitHub | Trust GitHub Actions |
| IAM role `zns-mint-release-deploy` | Assumed only by the release/deploy workflow |
| S3 staging bucket | Store built guest image before AMI registration |
| AMI registration permissions | From the release/deploy workflow |
| EC2 launch permissions | From the deploy workflow |
| SEV-SNP enabled instance type | AMD-based instance with SNP support |
| VPC / security group | Minimal: outbound only, no inbound SSH |
| CloudWatch (optional) | Metrics/logs, **no seed material ever** |

---

## 6. End-to-end deployment flow

```
1. Operator pushes protected tag v1.0.0
        ↓
2. release.yml runs on GitHub-hosted runner
   - builds zns-mint
   - builds immutable guest image
   - computes image SHA-256 + expected SEV-SNP measurement
   - creates release manifest
   - publishes immutable GitHub Release
        ↓
3. deploy.yml runs
   - OIDC → AWS role
   - uploads image to S3
   - registers AMI
   - launches SEV-SNP EC2 instance
   - posts AMI ID / instance ID to release
        ↓
4. Operator provisions seed (OUTSIDE CI)
   - TEE generates ephemeral key + admission attestation
   - Operator verifies attestation locally
   - Operator encrypts seed to TEE key, creates zns_seed.capsule
   - uploads ciphertext to the instance
        ↓
5. zns-mint boots inside TEE
   - derives K_seal from /dev/sev-guest
   - decrypts capsule
   - verifies fingerprint + release manifest
   - derives Treasury (acct 0) and Registry (acct 1) keys
   - writes zns_mint_attestation.bin
   - starts scanning the chain
        ↓
6. Public verifier
   - anyone downloads attestation + manifest
   - checks AMD cert chain
   - checks measurement matches manifest
   - checks report_data binds Treasury address + Registry FVK
   - confirms the live mint runs approved code with expected identities
```

---

## 7. Capsule creation boundary

Capsule creation is intentionally **outside this repo**. The contract between
the capsule creator and the mint is:

- Input: seed (32 bytes), target network, seed epoch, release manifest digest,
  target TEE measurement / VMRK-derived sealing key.
- Output: `zns_seed.capsule` containing:
  - `magic = b"ZNS_SEED"`
  - `fingerprint` (32 bytes, ZIP-32 seed fingerprint)
  - `nonce` (24 bytes)
  - `ciphertext` (XChaCha20-Poly1305)
  - AAD = `format_version || network || seed_epoch || fingerprint ||
    release_manifest_digest`

The capsule must be created either:

- Inside the target TEE, using its own derived `K_seal`, or
- By something that can derive the same VMRK-bound key as the target TEE.

In the V1 operator-knows-seed model, the operator uses a local provisioning
tool that verifies the TEE's admission attestation and encrypts the seed to
its attested ephemeral key. The TEE then decrypts internally and reseals under
its own VMRK-derived `K_seal`.

---

## 8. First concrete next steps

1. Replace `deployment/seed_fingerprint.txt` `PLACEHOLDER` with the real
   ZIP-32 seed fingerprint for the intended network.
2. Decide where the capsule creator repo/tool lives and confirm it can produce
   a valid capsule for the target TEE.
3. Add `.github/workflows/pr.yml` for safe CI that never touches AWS or seeds.
4. Add `.github/workflows/release.yml` that builds the binary and produces a
   release manifest (guest image building can be stubbed initially).
5. Add `.github/workflows/deploy.yml` skeleton with OIDC-to-AWS wiring.
6. Add the public `tools/verifier/` crate skeleton.
7. Extend `SeedCapsule` and `boot.rs` to parse/verify network, seed_epoch, and
   release-manifest digest once the format is finalized.

---

## 9. V1 trust model note

The current V1 plan deliberately weakens the foundational invariant from
"no human can ever see the Registry seed" to:

> "AWS and GitHub cannot see the seed; the operator can."

This is acceptable for testnet / early V1, but must be documented honestly and
kept separate from the eventual mainnet model where seed access is machine-only
and bound to immutable tagged releases plus attested TEE-to-TEE handoff.
