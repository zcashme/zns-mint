# Treasury OTP relay changelog

## 2026-07-24 — OTP relay transaction assembly

- Added `src/treasury/relay.rs` with `assemble_otp_relay` — builds a standard
  Orchard transaction from the Treasury to the current controller's Orchard
  address, carrying the OTP relay memo.
- The controller's UA is parsed via `zcash_address::ZcashAddress::convert_if_network`
  to extract the Orchard receiver. If the UA has no Orchard receiver, the
  relay fails (open design question: non-Orchard controller handling).
- The OTP output carries value 0 (just the memo).
- Treasury fee funding uses a greedy iterative selection that converges on
  the ZIP-317 fee.
- Open design questions from `docs/design/09-transaction-assembly.md`:
  - Non-Orchard controller handling (current: fail if no Orchard receiver).
  - Output value (current: 0 zatoshis).
  - OVK recovery policy (current: Treasury external OVK).