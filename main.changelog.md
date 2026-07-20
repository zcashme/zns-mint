# zns-mint changelog

## Unreleased
- Refactored `treasury` to include a `memo` submodule (as a file `src/treasury/memo.rs` rather than moving `treasury.rs` to a directory module), designed for request memo classification.
- Created `src/treasury/memo.rs.context.md` to outline the boundaries of memo parsing (strictly parsing/typing, no payment matching or state changes).
- Implemented `match_fee` in `src/treasury/fee.rs` to detect claim payments by directly parsing the note's encrypted memo, confirming that the request note itself serves as the payment.
- Updated `docs/design/15-treasury-module.md` to resolve the Open Question around payment memo grammar.
