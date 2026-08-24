//! Treasury wallet view and Treasury policy for the mint.
//!
//! The Treasury is the user-facing account's agent (ZIP-32 account 0): it is
//! everything that account must do, and nothing more. Five responsibilities:
//!
//! 1. **Interpret intake** — claim payments and OTP relay requests arrive as
//!    Ironwood notes owned by the wallet; Treasury decodes their stored memos
//!    (`memo`) and classifies them. Treasury is keyless: it holds no keys and
//!    no notes of its own — not even viewing keys. Every fact it learns flows
//!    through a wallet projection, and every signing capability arrives as a
//!    borrowed argument.
//! 2. **Guarantee payment freshness** — a payment confirmed at or before the
//!    name's current tip is rejected; a payment cannot be reused after a
//!    release/reclaim boundary.
//! 3. **Participate in settlements** — the atomic claim (spend the payment
//!    note, retain the fixed price) and the OTP relay (spend the request
//!    note, deliver the memo plus the controller's compensation). Treasury
//!    never decides a name's lifecycle — that is the Registry's.
//! 4. **Deposit to the vault** (`vault`) — when the spendable balance exceeds
//!    the threshold, send the excess to the project vault's transparent
//!    address, retaining a fixed reserve.
//! 5. **Fund the Registry** (`replenish`) — refill the Registry's fee-note
//!    pool from Treasury value when it drops below its floor.

pub mod memo;
pub mod replenish;
pub mod relay;
pub mod vault;
