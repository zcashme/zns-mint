# Treasury OTP relay changelog

## 2026-07-30 — Boot-proven address and fee network

- Relay fee calculation and Unified Address decoding receive the same
  boot-proven consensus parameters used by the loop and signer.

## 2026-07-28 — Owner-visible relay and fixed relay value

- Relay memos begin with the fixed-width OTP:
  `ZNS:otp:<otp>:<name>:<verb>:<requested_ua>`. The output is encrypted to the
  current controller while the plaintext shows the requested update target.
- A relay request note must equal exactly twice the final ZIP-317 fee. One fee
  pays the network; the other is delivered to the original owner. Treasury
  retains no relay value.

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
