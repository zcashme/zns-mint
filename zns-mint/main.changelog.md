# zns-mint changelog

## Unreleased
- Refactored `treasury` to include a `memo` submodule (as a file `src/treasury/memo.rs` rather than moving `treasury.rs` to a directory module), designed for request memo classification.
- Created `src/treasury/memo.rs.context.md` to outline the boundaries of memo parsing (strictly parsing/typing, no payment matching or state changes).
