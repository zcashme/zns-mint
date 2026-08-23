# `sync.rs` design record

## 2026-09-01 — Wrapper types killed; upstream `ScannedBlock` passes through

- Deleted every bespoke translation type between the upstream scanner and
  its consumers: `BlockOutput`, `TxOutput`, `ReceivedSapling`,
  `ReceivedIronwood`, `BlockMemos`, and `decrypt_block_memos`. They existed
  to reshape the scan result for the old bespoke wallet; the upstream-shaped
  wallet (`WalletWrite::put_blocks`, `store_decrypted_tx`) consumes upstream
  values directly, so the translation layer had no consumer.
- `scan_block` now returns `(ScannedBlock<AccountId>, Vec<ReceivedNameNote>)`
  — the upstream value unmodified plus the supplemental ZNS lane. Nullifier
  streams (per-pool `nullifier_map()`), commitment streams, wallet-relevant
  transactions, and block metadata all ride on `ScannedBlock`; the run loop
  hands it to `put_blocks`.
- `ReceivedNameNote` now carries its own `(block_index, txid, action_index)`
  attribution so the Registry groups Name Notes without a transaction
  wrapper.
- The Name Note retention-mark surgery on the Ironwood commitment stream is
  deleted with the wrappers (it mutated `into_commitments()`'s owned
  vectors, impossible once `ScannedBlock` passes through whole). Name Note
  witness retention now depends on the never-pruned `MemoryShardStore`;
  if a pruning floor is ever introduced, name-note retention must be
  redesigned as a first-class feature.
- `ScanError::TransactionIdentityMismatch` deleted with the identity checks
  that produced it; upstream `scan_block`'s own continuity validation is
  the authority. (The dead `RegistryOwnershipMismatch` variant was already
  deleted earlier this cycle.)
- Downstream callers (`registry.rs::apply_block`, the `main.rs` loop) are
  broken pending their migration to the upstream shape; that is the next
  slice.

## 2026-09-01 — Manual nullifier collection deleted

- The first loop no longer iterates raw Sapling/Ironwood bundles to collect
  nullifiers into `raw_shielded_transactions`. Since `Nullifiers::empty()` is
  passed to upstream `scan_block`, every nullifier is "unlinked" and appears
  in `ScannedBundles::nullifier_map()`. The scan now reads nullifiers from
  `scanned.ironwood().nullifier_map()` and `scanned.sapling().nullifier_map()`
  instead.
- `raw_shielded_transactions` BTreeMap deleted.
- `ScanError::RegistryOwnershipMismatch` deleted (dead code, never
  constructed).
- The first loop now does only the ZNS supplemental Name Note scan and
  `global_action_ordinal` tracking.

## 2026-08-15 — Orchard surfaces deleted from scan output

- `BlockOutput`/`TxOutput` no longer carry Orchard commitments, Orchard
  nullifiers, or received Orchard notes; `BlockMemos` drops the Orchard map.
  The wallet (two-pool: Sapling + Ironwood) consumes nothing Orchard. A
  transaction whose only shielded activity is an Orchard bundle no longer
  produces a `TxOutput` at all.
- The upstream scanner's Orchard trial-decryption keys remain (they cannot be
  excluded without naming `zcash_client_backend`'s `pub(crate)` Ironwood
  domain types), but NU6.3 disables Orchard cross-address transfers, so no
  Orchard note can ever be addressed to this wallet and nothing Orchard is
  surfaced. The block's Orchard commitment stream is discarded rather than
  appended to a tree.
- Registry Name-Note scanning is unchanged: it uses the Registry's
  Orchard-family FVK under `ZnsIronwoodDomain` — Ironwood keys, not the
  Orchard pool.

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
