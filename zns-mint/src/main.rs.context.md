# Context for src/main.rs (zns-mint)

**This file exists so that any agent (or future human) can read the full design context, constraints, and intent without having to reconstruct it from code comments or chat history.**

## Current State (as of this writing)
- Everything lives inside **ONE SINGLE MAIN FUNCTION**.
- The file is intentionally minimal.
- Design is expressed primarily through comments inside `main()`.
- Only non-std dependency so far: `tracing` + `tracing-subscriber` (for INFO level logging).

## Overall Purpose
This binary is the Zcash Name Service (ZNS) mint/registry daemon.

It is a **long-running binary** that acts as **two logical Zcash wallets** derived from a **single seed** using ZIP-32 multi-account derivation.

Core model:
- Single seed (never visible to humans).
- Two accounts:
  - **Treasury account (0)**: pays fees, can sweep excess.
  - **Registry account (1)**: creates/spends the special Name Notes that represent ZNS name ownership.

The binary runs **inside a Trusted Execution Environment (TEE)**. Attestation of the exact binary + launch parameters establishes trust. The seed phrase is stored in an **encrypted blob** that is injected by the TEE launcher. No human ever sees the phrase.

## Current Code Structure
```rust
fn main() {
    // tracing subscriber at INFO
    tracing::info!("zns-mint starting");

    // large design comment block describing:
    // - long-running binary + two wallets
    // - encrypted seed blob
    // - current account assignment
    // - Boot idea
    // - Run idea
}
```

We deliberately keep almost everything inside `main()` for now.

## Critical Constraints (DO NOT VIOLATE)

### No Environment Variables — Ever
- This binary must never read `std::env::var(...)` (or any equivalent) for configuration or secrets.
- Reason: TEE + attestation model. Env vars are too easy to leak and would weaken the trust story.

### Seed / Blob Handling
- The seed phrase is stored in an **encrypted blob**.
- Injected securely by the TEE launcher.
- Binary must decrypt the blob *inside the TEE*.
- Derive the two accounts.
- Zeroize plaintext seed material as soon as possible after derivation.
- **Never** log, print, or leak the seed or blob contents.
- The blob encryption should be bound to the TEE measurement/attestation.

### Minimalism Rules (user guidance)
- ONE SINGLE MAIN FUNCTION for as long as possible.
- Do **not** introduce:
  - Config/CLI argument parsing (clap or manual)
  - Structs for configuration
  - Separate modules
  - Unnecessary crates
- Only expand when the user explicitly says so ("now let's do X").
- Context documents (`*.context.md`) next to source files are encouraged.

## Account Assignment (current)
- Treasury account (0): pays fees, can sweep excess.
- Registry account (1): creates/spends the special Name Notes.

Note: There was discussion about whether to swap these. Current code uses the above assignment. Swapping would put core ZNS logic on 0 and treasury on 1. The difference is mostly convention/tooling rather than cryptography.

## Boot Idea (from code comments)
(Not coded yet)

- get the encrypted seed blob
- decrypt inside TEE
- derive the two accounts
- open wallet DBs
- connect to lightwalletd
- sync both accounts
- enter the run loop (scan memos, process ZNS ops, treasury stuff)

## Run Idea (from code comments)
(Not coded yet)

- main long-running loop (tick timer or tokio select on shutdown + chain events)
- keep both accounts synced to the current tip
- detect new ZNS memos on the registry account
- validate incoming requests (claim / update / release)
- handle auth flow for update/release (generate + store challenges)
- when ready to act: build + sign Name Note tx using the registry account
- draw fees from the treasury account as needed
- broadcast the transaction
- on successful inclusion: update local registry state and clean challenges
- occasionally sweep excess treasury funds to a cold address
- handle reorgs (rewind sync + local name state)
- log key events at INFO level
- support clean shutdown (persist critical state, etc.)

## Logging
- Uses `tracing_subscriber::fmt()` with `LevelFilter::INFO`.
- Initialized at the very top of `main()`.
- `tracing::info!("zns-mint starting");` is the first log line.
- Goal is readable logs (especially useful inside a TEE where stdout/stderr is the observation channel).

## Design Principles / Background
- Single seed for simplicity (one thing to back up / inject).
- Two accounts for separation of concerns (core name authority vs funding/sweeping).
- TEE is the primary security boundary.
- The binary is the only thing that will ever see this seed in normal operation.
- Focus on "boot then hand off to run loop".

## For Future Agents / Maintainers / You
- Re-read this file before making changes to `main.rs`.
- The user is iterating on high-level design via comments in the single main function.
- When the user says things like "let's also add a section on the Run idea", update both the inline comments **and** this document.
- "save all context to main.rs.context.md" means this file should be the single source of truth for design intent.
- Do not add real implementation (config parsing, modules, actual key derivation, DB code, etc.) until the user asks.
- Keep the spirit of extreme minimalism.

## Related / Historical Notes
- This project was restarted from a much larger multi-crate structure.
- Earlier work had separate crates (core, state, signer, mint, etc.) and a full CLI with clap — all deliberately removed.
- Old protocol docs exist in `docs/` but the code is being built fresh.
- Account numbering was discussed; current assignment is reflected above.

## Next Steps (only when user says so)
- Actual implementation of Boot steps
- Key derivation logic (with zeroize, proper ZIP-32, secrecy, etc.)
- Wallet DB setup for the two accounts
- lightwalletd connection + sync
- ZNS memo parsing
- Run loop
- etc.

This context document should be kept up to date whenever the design comments in main.rs change.


