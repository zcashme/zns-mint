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
//! 5. **Fund the Registry** (`replenish`) — mint fresh fee notes from
//!    Treasury value when the Registry's fee liquidity runs low.

use crate::mint::TREASURY_ACCOUNT;

pub mod claim;
pub mod memo;
pub mod replenish;
pub mod relay;
pub mod vault;
use crate::wallet::transaction::ReceivedIronwoodNote;
use crate::wallet::Wallet;
/// Treasury wallet view.
///
/// The Treasury does not own notes; `Wallet` owns all notes and commitment
/// trees. These methods project the Treasury account's slice of the wallet.
#[derive(Default)]
pub struct Treasury;

impl Treasury {
    /// The Treasury's unspent notes. Treasury notes are Ironwood notes:
    /// NU6.3 disables Orchard cross-address transfers, so users cannot send
    /// the Treasury Orchard notes.
    pub fn unspent_notes<'w>(
        &self,
        wallet: &'w Wallet,
    ) -> impl Iterator<Item = &'w ReceivedIronwoodNote> {
        wallet.ironwood_notes_for(TREASURY_ACCOUNT)
    }

    pub fn balance(&self, wallet: &Wallet) -> u64 {
        wallet.balance(TREASURY_ACCOUNT).into_u64()
    }
}
