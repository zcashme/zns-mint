//! Protocol-level fee floors and dust values for ZNS operations.
//!
//! These are not "configuration" — they are part of the economic rules of the
//! name service so that mutations cannot be used to drain the treasury and
//! so the minimums are covered by the same attestation as the rest of the logic.

/// Minimum fee in zatoshis required for a CLAIM operation.
pub const MIN_CLAIM_FEE_ZAT: u64 = 10_000; // 0.0001 ZEC

/// ZIP-317 fee for a funded mint / relay (1 spend + ≤2 outputs ⇒ 2 logical
/// actions ⇒ 5000 × 2). Also the conventional dust value carried to a recipient.
pub const MINT_FEE_ZAT: u64 = 10_000;

/// Minimum value a treasury funding note must hold: the costliest single
/// spend is the OTP challenge relay (fee + dust to the owner = 2 × fee). A
/// floor of one fee would let the selector pick a user's own dust note and
/// then fail the relay with `InsufficientFee`.
pub const FUNDING_MIN_ZAT: u64 = 2 * MINT_FEE_ZAT;

/// Minimum fee for an UPDATE / RELEASE request — covers the funded OTP relay
/// it triggers (fee + dust), so mutations can't drain the treasury.
pub const MIN_MUTATION_FEE_ZAT: u64 = 2 * MINT_FEE_ZAT;
