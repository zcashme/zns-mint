# Treasury vault deposit changelog

## 2026-09-02 — Vault is the named destination; one-call deposit on the wallet trait surface

- `sweep.rs` renamed `vault.rs`: the module's responsibility is "send
  Treasury excess to the project's vault," and the destination is a specific
  custody entity, not generic cold storage. Function and policy names keep
  the sweep vocabulary where it names the action
  (`sweep_to_vault`, `SWEEP_THRESHOLD`, `SWEEP_RESERVE`).
- `SWEEP_ADDRESS` renamed `VAULT_ADDRESS`, doc'd as the project vault's
  P2PKH address — transparent by design so vault holdings are publicly
  auditable without viewing keys, and the attested mint never holds
  long-term value. The current `[0x42; 20]` bytes are a placeholder pending
  the vault's final approved address (flagged, unchanged).
- `sweep_policy` and `assemble_sweep` are replaced by one entry point:
  `sweep_to_vault(network, wallet, treasury_keys) -> Option<TxId>`. It
  decides (spendable balance vs threshold), derives heights from the wallet
  (`get_target_and_anchor_heights`, mirroring upstream `propose_transfer`),
  selects every unspent Treasury Ironwood note via upstream
  `InputSource::select_unspent_notes`, builds, proves, signs, and returns
  only the `TxId`.
- Caller-owned exclusions are gone, deliberately: the vault flow records
  the built transaction in the wallet via `store_transactions_to_be_sent`,
  which records every consumed note as spent — the wallet's own spend record
  is the reservation view, and a stored-but-unmined spend blocks re-selection
  until it confirms or its expiry height passes. This is upstream's own
  model (`create_proposed_transactions` stores the tx it builds).
- Known incompleteness, by scope discipline: (1) `signing::assemble_v6_transaction`
  currently returns `(TxId, String)` hex; this module is written against its
  planned return of the built `Transaction` so the deposit can be recorded —
  that change lands with the signing slice. (2) Wallet failures map to
  placeholder `AssemblyError` variants (`NoAnchor`/`NoWitness`/`NoteNotFound`)
  until a `Wallet` variant is added in the mint slice. No consumer wiring
  yet; the run loop's `AutoSweep` pending-work item will call `sweep_to_vault`.

## 2026-08-15 — Ironwood spend lane

- The sweep selects and spends Treasury Ironwood notes (the Orchard spend
  lane is deleted; Treasury balances accrue as Ironwood notes). The
  transparent cold-storage output and the fixed reserve/fee policy are
  unchanged.

## 2026-07-30 — Boot-proven fee network

- Sweep fee calculation and V6 assembly receive the boot-proven consensus
  parameters rather than a global default.

## 2026-07-28 — Two-ZEC sweep trigger

- Raised `SWEEP_THRESHOLD` from 0.1 ZEC to 2 ZEC. The independent 0.01 ZEC
  post-sweep reserve and the compiled approved P2PKH destination are unchanged.

## 2026-07-24 — Treasury auto-sweep

- Added `src/treasury/sweep.rs` with `sweep_policy()` and `assemble_sweep()` —
  detects when Treasury balance exceeds `SWEEP_THRESHOLD` and builds a V6
  transaction to sweep excess to a cold storage transparent address.
- Orchard bundle (Treasury authority): spends Treasury notes, creates change.
- Transparent output: sends `treasury_balance - SWEEP_RESERVE` to
  `SWEEP_ADDRESS`.
- Constants are hardcoded (no env vars, no config): `SWEEP_THRESHOLD` =
  10,000,000 zatoshis (0.1 ZEC), `SWEEP_RESERVE` = 1,000,000 zatoshis
  (0.01 ZEC), `SWEEP_ADDRESS` = approved P2PKH (`[0x42; 20]`).
- Wired into `live::reconcile` as a `PendingWork::AutoSweep` item.

## 2026-07-28 — Exact fee and reserve retained by assembly

- Sweep policy now determines only eligibility. Assembly selects the exact
  unreserved Treasury notes, computes its actual Orchard V3 action count and
  ZIP-317 fee, then sends `selected - reserve - fee` to cold storage.
- The fixed one-million-zatoshi Treasury reserve remains an Orchard change
  output. A sweep can no longer request the full pre-fee excess and fail for
  lack of fee funds.
