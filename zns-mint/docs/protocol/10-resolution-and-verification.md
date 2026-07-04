# 10 - Resolution And Verification

## Resolver Goal

A resolver computes the current UA for a name from public chain data.

It should not trust the Registry's private database. It may use indexes for
speed, but the answer must be reproducible from confirmed Name Notes on the
best chain.

Anyone can run a resolver with the Registry UFVK. The UFVK is the public
scanning capability for Registry-received Name Notes; it is not the Registry
spending key and does not authorize name changes.

## Verification Inputs

For each candidate Name Note, a verifier needs:

- the Registry UFVK or equivalent scanned Name Note data;
- the Orchard note commitment;
- the memo fields `(action, name, ua, prev_rcm)`;
- enough transaction/block context to establish chain order and confirmation;
- the ZNS derivation algorithm.

## Verification Steps

For each Name Note:

1. parse the memo strictly;
2. validate the name and action;
3. recompute `(psi, rcm)`;
4. verify the note commitment matches the recomputed payload;
5. apply the lifecycle chain rule for that name;
6. select the latest valid non-released tip as the current binding.

## Independent Kernel

The mint and verifier intentionally keep separate implementations of the ZNS
kernel. Shared test vectors keep them byte-aligned. This prevents a derivation
bug copied into both producer and verifier from silently validating itself.

## Finality Policy

ZNS treats the immediate Zcash best chain as truth. The latest valid Name Note
on the current best chain is the current name state.

If the best chain changes, the name state changes with it. Reorg handling is an
implementation requirement for the mint and resolvers; it is not a separate
finality layer in the ZNS protocol.
