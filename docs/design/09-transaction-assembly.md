# 09 - Transaction Assembly

## Current State

The Registry library constructs an unproven Ironwood V3 bundle from an opaque
exact fee-note plan, adds Registry change, places the bundle in a V6
transaction, computes the real transaction sighash, proves, signs, verifies the
proof, and serializes the transaction. The planner accepts a caller-owned
exclusion set; canonical Wallet state owns no reservations. Witnesses bind to
the fully-applied cursor height; branch, fee, and expiry policy bind to the next
mineable height.

These assembly paths are intentionally unwired from the current passive replay
runtime. A future Live layer must own reservations and may invoke them only
after an exact Rebuild-to-Live transition.

Production minting still needs:

- runtime wiring from authorized requests through assembly and submission;
- Treasury transaction assembly for OTP relay and Registry replenishment;
- runtime integration and Zebra acceptance evidence for the drafted Treasury
  claim-refund assembler and auto-sweep policy;
- one atomic claim transaction replacing the temporary two-transaction path;
- retry, confirmation, expiry, and reorg reconciliation;
- end-to-end regtest coverage of claim, update, release, and failure paths.

## Name Note Transaction Types

### Claim

A claim transaction creates a value-0 Registry Name Note. It does not spend a
prior Name Note.

The claim transaction path must also account for the user's name payment. That
payment is received by the Treasury and is not the Name Note value; the Name
Note is always value `0`. The Registry's claim transaction does not consume the
payment; it only references its acceptance as a precondition.

The drafted refund transaction is separate from the Registry Name Note
transaction. It spends the matched Treasury Orchard payment, returns retained
value to a Treasury internal Orchard address, and creates an always-present
Ironwood refund output at the claimant UA's Orchard receiver. For this exact
shape, Orchard V3 contributes two logical actions and the padded Ironwood V3
output contributes two, so the standard ZIP-317 fee is 20,000 zatoshis. The
gross Treasury surcharge is ten times that network fee; the network fee is paid
from the surcharge before Treasury change is created.

The runtime must replace this separate-transaction draft with one V6 atomic
settlement containing the exact Treasury payment spend, refund/change, Registry
fee spends/change, and Name Note. Which account contributes the aggregate
ZIP-317 fee remains an explicit policy decision because consensus exposes one
transaction fee, not a separable per-bundle fee.

### Update

An update transaction spends the prior live Name Note and creates the next live
Name Note. The new `prev_rcm` is the old note's `rcm`.

### Release

A release transaction spends the prior live Name Note and creates a terminal
release Name Note with empty UA.

### OTP Relay

An OTP relay transaction sends the OTP memo from Treasury to the canonical
current controller. At NU6.3 a Treasury Orchard bundle cannot create a
cross-address controller output; the viable drafted shape is Treasury Orchard
spends/change plus an output-only Ironwood bundle. Relay memo grammar, output
value, OVK recovery policy, and non-Orchard controller handling require explicit
decisions before this path is implemented.

## Sighash

A real transaction path must compute the actual V6 transaction sighash and sign
against it. A stand-in `[0; 32]` sighash is acceptable only in early
development and must not ship.

The public Registry signer remains Ironwood-only. The crate-private mixed
assembler accepts typed Treasury authority only for Orchard real spends and
typed Registry authority only for Ironwood real spends, under one shared V6
sighash. Output-only bundles require neither real spend key. Sapling is
absent from both the unauthorized transaction used for sighash computation and
the final authorized transaction. An already-authorized Sapling bundle must
never be inserted after the sighash is computed: V6 commits to Sapling
effecting data even though it does not commit to Sapling authorization bytes.
Any future Sapling-capable Treasury path must follow the upstream builder
ordering: prove Sapling without signing, place every effecting bundle in one
unauthorized transaction, compute one shared shielded sighash, and only then
authorize every bundle.

Before serialization, the signer compares the upstream-generated V6 effecting-
data digests (`TxDigests`) of the final authorized transaction against the
digests used to compute the shielded sighash. If any header, transparent,
Sapling, Orchard, or Ironwood digest differs, signing fails closed. This
postcondition protects against later effecting-data drift; mutation and
independent-sighash tests are still required before `TX-005` is considered
fully verified.

## Fee Funding

Fees are paid by the account that authorizes the transaction:

- Registry Name Note transactions (claim, update, release) are funded by the
  Registry account itself. There is no Treasury fee-funding path for Name Notes.
  The transaction builder must combine Registry funding with Registry Name Note
  actions without exposing the Registry key outside its signing path.
- Treasury OTP relay transactions are funded by the Treasury account.

Name payments are separate from transaction fees. A claim must prove or carry
the required name payment received at the Treasury, while the Registry still
handles network fee funding for its own outgoing Name Note transaction.

## Submission State

After broadcast, the mint must track:

- transaction id;
- originating request or chain action;
- first submit height/time;
- retry count;
- confirmation height;
- failure reason, if final.

Submission state is operational. It must not become name-state authority.
