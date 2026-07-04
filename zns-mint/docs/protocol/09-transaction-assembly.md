# 09 - Transaction Assembly

## Current Gap

The mint can derive keys and scan the chain, but cannot yet build, prove, or
sign Orchard bundles, and a bundle is not a broadcastable Zcash transaction
even once it exists.

Production minting still needs:

- Orchard bundle build/prove/sign for Registry Name Note actions and Treasury
  OTP relay actions;
- transaction assembly around the Orchard bundle;
- real v5 sighash calculation;
- Registry self-funding of fees;
- ZIP-317 fee policy compliance;
- broadcast/submission;
- retry and confirmation tracking.

## Name Note Transaction Types

### Claim

A claim transaction creates a value-0 Registry Name Note. It does not spend a
prior Name Note.

The claim transaction path must also account for the user's name payment. That
payment is received by the Treasury and is not the Name Note value; the Name
Note is always value `0`. The Registry's claim transaction does not consume the
payment; it only references its acceptance as a precondition.

### Update

An update transaction spends the prior live Name Note and creates the next live
Name Note. The new `prev_rcm` is the old note's `rcm`.

### Release

A release transaction spends the prior live Name Note and creates a terminal
release Name Note with empty UA.

### OTP Relay

An OTP relay transaction sends the OTP memo from the Treasury to the current
UA. It is a Treasury transaction, not a Registry Name Note transaction, but it
still needs funding and broadcast.

## Sighash

A real transaction path must compute the actual v5 transaction sighash and sign
against it. A stand-in `[0; 32]` sighash is acceptable only in early
development and must not ship.

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