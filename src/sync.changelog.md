# `sync.rs` design record

## 2026-07-24 — Scanner metadata is the sole accepted-height source

- Removed the duplicate `BlockOutput` height field and accessor.
- Wallet application, Registry transitions, and validated Name Note locators
  now derive the accepted height from `BlockOutput::metadata().block_height()`.
- The scan input height remains only where the pinned upstream scanner and
  transaction decryption APIs require it.

## Validated Ironwood Name Note scanning

- The pinned upstream full scanner remains authoritative for block continuity,
  all pool commitment streams, ordinary wallet notes, and recognized ordinary
  spends. Its standard `IronwoodDomain` cannot decrypt ZcashName Name Notes
  whose commitments use memo-derived openings.
- A supplemental pre-consumption pass walks raw block transactions and
  Ironwood actions in consensus order and calls the Orchard fork's private-
  domain `try_zns_note_decryption` facade with the Registry external IVK.
- The callback performs one canonical Name Note memo parse, derives `(rcm,
  psi)` from that same typed payload, and returns the payload with the opening
  parts. Downstream code consumes the retained payload; it does not reparse the
  memo.
- Supplemental acceptance requires value zero, the exact Registry external
  recipient, and an ownership-gated nullifier from the Registry FVK. These are
  structural checks, not proof that the transaction represents a legal or
  Registry-authored lifecycle transition.
- Output identity is `(block transaction index, txid, Ironwood action index)`.
  The tree position is the block's accepted starting Ironwood tree size plus
  the action's global Ironwood ordinal, with checked arithmetic and a `cmx`
  cross-check against the upstream commitment stream.
- The cross-check converts the extracted commitment through
  `MerkleHashOrchard::from_cmx`; the upstream extracted-commitment and tree-leaf
  types are intentionally distinct.
- The supplemental pass never appends a second commitment. Upstream already
  records every Ironwood action commitment, including outputs it cannot
  decrypt with the standard domain.
- Transactions containing only a Name Note must still appear in `BlockOutput`.
  Standard and supplemental results merge in block-index order; one action
  appearing in both categories is an invariant failure, never two received
  notes.
- Every public Ironwood action nullifier is retained per transaction so the
  Registry layer can detect spends of supplemental Name Notes. The upstream
  `Nullifiers` extension API is private and cannot index these outputs.
- Registry authorship and transition legality are enforced only when applying
  the ordered block: claims require a same-transaction recognized Registry fee
  spend; updates/releases require the exact current tip nullifier and matching
  predecessor, in addition to Registry fee funding.
- Raw public Orchard action and Sapling spend nullifiers are retained as well.
  Wallet spend detection resolves all three pools against its own rewindable
  nullifier indexes; the upstream scanner's non-rebuildable in-memory
  `Nullifiers` cache is no longer a source of ownership truth.
- `BlockOutput::transactions` now intentionally includes every transaction
  carrying an Ironwood bundle, even when it has no decrypted standard output,
  because the public nullifier stream is part of Name Note authorization.
- Viewing-key ownership contradictions use a distinct typed scanner error and
  cannot be confused with missing boot key material.
- `BlockOutput` and `TxOutput` evidence fields are private. External callers
  receive immutable accessors only, so a validated candidate cannot be moved
  between transactions or paired with fabricated fee/tip nullifier evidence
  before Registry validation.

## Rejected designs

- Treating any parseable Registry memo as a Name Note is rejected because an
  ordinary Ironwood note can carry the same bytes.
- Treating commitment validity as Registry authorship is rejected because
  anyone can create a zero-value output to the public Registry address.
- Reusing `Note::nullifier` is rejected because it derives the decoy standard
  opening rather than the validated ZcashName opening.
- Joining only the upstream wallet-relevant transaction list is rejected
  because a ZNS-only transaction is absent from that list.
- Injecting supplemental commitments is rejected because it double-counts the
  Ironwood tree and invalidates every later witness.
