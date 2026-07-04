# 03 - Name Note

## Definition

A Name Note is an Orchard note controlled by the Registry account that encodes a
ZNS lifecycle action.

It has:

- value `0`;
- recipient equal to the Registry external Orchard address;
- a 512-byte memo carrying the canonical ZNS payload;
- a ZNS-specific commitment built from deterministic `(psi, rcm)` values.

## Commitment Inputs

For each lifecycle action, the mint computes:

```text
(psi, rcm) = zns_psi_rcm(action, name, ua, prev_rcm)
```

`psi` is a Pallas base-field element used by the ZNS Orchard commitment path.
`rcm` is the commitment trapdoor and also becomes the next link's `prev_rcm`.

The inputs are:

- `action`: canonical ASCII verb, one of `claim`, `update`, `release`;
- `name`: canonical lowercase DNS-label name;
- `ua`: Unified Address string, empty only for committed release notes;
- `prev_rcm`: 32-byte previous chain value.

## Hash Construction

The v1 domain tag is:

```text
ZcashName/v1
```

The derivation uses BLAKE2b-512 with length-prefixed fields and separate field
tags for `psi` and `rcm`. This construction is byte-stable. Changing field
order, field tags, length prefixes, or the domain tag is a protocol version
change and requires new cross-implementation vectors.

## Orchard Fork

The mint depends on the ZNS Orchard fork with `unsafe-zns`. That fork exposes
builder APIs for ZNS outputs and spends. The name is deliberate: the code is no
longer using spec-faithful Orchard note commitments. It repurposes Orchard note
machinery for ZNS state commitments while retaining Orchard spend authority,
nullifiers, and proofs.

## Verification

A verifier reads the Name Note memo, recomputes `(psi, rcm)`, and checks that
the note commitment matches the payload. This is why the memo grammar and
derivation are protocol-critical.
