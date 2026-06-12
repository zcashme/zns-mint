//! ZNS domain types (action kinds, memo format) — parse memos without
//! pulling the proving stack.
//!
//! Persistence lives in `zns-state`; crypto in `zns-mint`.

pub mod action;
pub mod error;
pub mod memo;

pub use action::{Action, ZERO_PREV_RCM};
pub use error::MemoError;
pub use memo::{parse_memo, ParsedMemo};
