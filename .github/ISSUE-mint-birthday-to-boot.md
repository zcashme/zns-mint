# Move `MINT_BIRTHDAY` into boot's network selection; retire it from `mint.rs`

## Scope

Since #108 deleted the reorg-walk floor panic and the tip assert, `MINT_BIRTHDAY`
is boot-only (`src/main.changelog.md`, 2026-09-21). The sole consumers are the
origin checkpoint fetch (`src/boot.rs:503`) and the day-zero MTP backfill
(`src/boot.rs:192`). This moves the constant next to that consumer and its
network-selection peers, and makes the boot-only policy scope instead of prose.

## Current behavior

- `pub const MINT_BIRTHDAY` lives at `src/mint.rs:38-50` under a three-way cfg
  selection (mainnet `3_400_000` / testnet `4_338_933` / regtest `100`),
  exported from the crate root with zero importers outside boot. Nothing stops
  a future run-loop import; the policy lives in a changelog sentence.
- The cfg dance duplicates, in a separate file, the exact selection boot.rs
  already runs three times: `NETWORK_LABEL` (`src/boot.rs:35-42`),
  `type Network` (`src/boot.rs:44-53`), `boot_network()` (`src/boot.rs:55-69`).
  The value↔network pairing is not glanceable anywhere.
- The regtest value is only meaningful against `regtest_network()`'s schedule
  (NU6.3 activates at 4; the fixture's coinbase maturity runs through 104), and
  the test pinning that coupling (`src/boot.rs:690-693`) already lives in
  boot.rs. Today value, schedule, and test sit in two files.

## Proposed change

- Move the three cfg'd consts and their doc comment into boot.rs's network
  section, verbatim, and drop `pub` — privacy becomes the tripwire.
- Drop `MINT_BIRTHDAY` from the import at `src/boot.rs:28`.
- Reword the comment at `src/wallet.rs:180`, which names the constant, to cite
  the birthday concept rather than a soon-private item.
- Update `src/mint.changelog.md` and `src/boot.changelog.md` in the same change.
- The name stays `MINT_BIRTHDAY`: `zns-integration-tests/src/zebra.rs:15` cites
  the name in a comment; the harness does not import it.

## Risk (from the review of the move)

- No runtime change: same values, same gates, identical constant folding.
- One nameable residual failure mode: a gate/value transposition that is
  syntactically valid (e.g. the testnet variant carrying the mainnet value).
  CI clippy-compiles default, `testnet`, `regtest`, and `regtest,fake-tee`, so
  a wrong *gate* fails as duplicate/missing definition; a transposed *value*
  compiles and would ship a wrong birthday on one network. Mitigation: values
  move verbatim, never retyped, and the diff shows the removed and added blocks
  side by side; the regtest variant stays pinned by the assert at
  `src/boot.rs:693`.
- The readability gain is real but small. The load-bearing reason is regtest
  cohesion — value + schedule + pinning test in one file — not the move itself.

## Out of scope

- `MIN_TREASURY_BALANCE` (`src/mint.rs`) is also boot-only today, but it is
  economic policy rather than a deployment coordinate; it stays where it is.

## Acceptance criteria

- `cargo clippy --all-targets -- -D warnings` passes for default, `testnet`,
  `regtest`, and `regtest,fake-tee`; binary behavior is unchanged.
- No reference to `MINT_BIRTHDAY` outside `src/boot.rs`; the regtest pin test
  still asserts height 100.
- Both changelogs updated in the same change.
